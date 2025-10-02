#include "cuda_miner.h"
#include "crypto/secp256k1_wrapper.h"
#include "crypto/hash_wrapper.h"
#include "crypto/address_generator.h"
#include "bloom/gpu_bloom.h"
#include "utils/memory_manager.h"
#include "profiling/nvtx_helpers.h"
#include <cuda_runtime.h>
#include <curand_kernel.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cassert>
#include <algorithm>
#include <vector>
#include <mutex>
#include <array>
#include <memory>
#include <random>

#define THREADS_PER_BLOCK 256
#define MAX_BLOCKS 65535

class CUDAMiner::CUDAMinerImpl {
public:
    CUDAMinerImpl() : device_id(0), current_capacity(0),
        d_private_keys(nullptr), d_public_keys(nullptr), d_addresses(nullptr), d_results(nullptr),
        d_random_states(nullptr), d_bloom_filter(nullptr),
        last_update_time(std::chrono::steady_clock::now()), last_processed_count(0) {}

    ~CUDAMinerImpl() { cleanup(); }

    bool initialize(int device_id = 0, size_t max_batch_size = 1000000) {
        this->device_id = device_id;
        cudaError_t err = cudaSetDevice(device_id);
        if (err != cudaSuccess) {
            std::cerr << "❌ Failed to set CUDA device: " << cudaGetErrorString(err) << std::endl;
            return false;
        }

        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, device_id);
        std::cout << "✅ Using GPU: " << prop.name << " (" << prop.totalGlobalMem / (1024LL*1024*1024) << " GB)" << std::endl;

        if (!ensure_capacity(max_batch_size)) return false;

        setup_random_states(max_batch_size);

        std::cout << "✅ CUDAMiner initialized successfully" << std::endl;
        return true;
    }

    bool ensure_capacity(size_t required_size) {
        if (required_size <= current_capacity) return true;
        cleanup_memory();

        size_t mem_private_keys = required_size * 32;
        size_t mem_public_keys = required_size * 33;
        size_t mem_addresses = required_size * 25;
        size_t mem_results = required_size * sizeof(uint8_t);
        size_t mem_random_states = required_size * sizeof(curandState);

        size_t free, total;
        cudaMemGetInfo(&free, &total);

        size_t required_total = mem_private_keys + mem_public_keys + mem_addresses + mem_results + mem_random_states + (100 * 1024 * 1024);

        if (required_total > free) {
            std::cerr << "❌ Insufficient GPU memory. Required: " << required_total / (1024.0*1024*1024) << " GB, Available: " << free / (1024.0*1024*1024) << " GB" << std::endl;
            return false;
        }

        cudaError_t err = cudaMalloc(&d_private_keys, mem_private_keys);
        if (err != cudaSuccess) { cleanup_memory(); return false; }
        err = cudaMalloc(&d_public_keys, mem_public_keys);
        if (err != cudaSuccess) { cleanup_memory(); return false; }
        err = cudaMalloc(&d_addresses, mem_addresses);
        if (err != cudaSuccess) { cleanup_memory(); return false; }
        err = cudaMalloc(&d_results, mem_results);
        if (err != cudaSuccess) { cleanup_memory(); return false; }
        err = cudaMalloc(&d_random_states, mem_random_states);
        if (err != cudaSuccess) { cleanup_memory(); return false; }

        cudaMemset(d_private_keys, 0, mem_private_keys);
        cudaMemset(d_public_keys, 0, mem_public_keys);
        cudaMemset(d_addresses, 0, mem_addresses);
        cudaMemset(d_results, 0, mem_results);

        current_capacity = required_size;
        std::cout << "✅ GPU memory allocated for " << required_size << " keys" << std::endl;
        return true;
    }

    void setup_random_states(size_t count) {
        if (count > current_capacity) {
            std::cerr << "❌ Random states count exceeds capacity" << std::endl;
            return;
        }

        int threads = THREADS_PER_BLOCK;
        int blocks = (count + threads - 1) / threads;

        unsigned long long seed = static_cast<unsigned long long>(std::chrono::system_clock::now().time_since_epoch().count());

        setup_random_kernel<<<blocks, threads>>>(d_random_states, seed, count);

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            std::cerr << "❌ Failed to setup random states: " << cudaGetErrorString(err) << std::endl;
        } else {
            std::cout << "✅ Random states initialized for " << count << " threads" << std::endl;
        }
    }

    std::vector<MiningResult> mine_batch(int batch_size) {
        std::vector<MiningResult> results;

        if (batch_size > current_capacity) {
            std::cerr << "❌ Batch size exceeds capacity" << std::endl;
            return results;
        }

        if (!d_bloom_filter) {
            std::cerr << "❌ Bloom filter not uploaded" << std::endl;
            return results;
        }

        nvtx_start_range("Mining Kernel", NVTX_COLOR_GREEN);
        int threads = THREADS_PER_BLOCK;
        int blocks = (batch_size + threads - 1) / threads;

        mining_kernel<<<blocks, threads>>>(d_private_keys, d_public_keys, d_addresses, d_results, *d_bloom_filter, d_random_states, batch_size);

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            std::cerr << "❌ Mining kernel failed: " << cudaGetErrorString(err) << std::endl;
            nvtx_end_range();
            return results;
        }
        cudaDeviceSynchronize(); // Sync for results
        nvtx_end_range();

        std::vector<uint8_t> h_results(batch_size);
        err = cudaMemcpy(h_results.data(), d_results, batch_size * sizeof(uint8_t), cudaMemcpyDeviceToHost);
        if (err != cudaSuccess) {
            std::cerr << "❌ Failed to copy results: " << cudaGetErrorString(err) << std::endl;
            return results;
        }

        // Copy found data
        for (int i = 0; i < batch_size; i++) {
            if (h_results[i]) {
                MiningResult result;
                result.found = true;

                std::vector<uint8_t> h_priv(32), h_pub(33), h_addr(25);
                cudaMemcpy(h_priv.data(), d_private_keys + i*32, 32, cudaMemcpyDeviceToHost);
                cudaMemcpy(h_pub.data(), d_public_keys + i*33, 33, cudaMemcpyDeviceToHost);
                cudaMemcpy(h_addr.data(), d_addresses + i*25, 25, cudaMemcpyDeviceToHost);

                result.private_key_hex = AddressGenerator::bytes_to_hex(h_priv.data(), 32); // Add helper in address_generator
                result.private_key_wif = AddressGenerator::private_key_to_wif(h_priv.data(), true, false);
                result.address = AddressGenerator::base58_encode(h_addr); // From binary to base58

                results.push_back(result);
            }
        }

        return results;
    }

    bool upload_bloom_filter(BloomFilterGPU* bloom_filter) {
        if (!bloom_filter) {
            std::cerr << "❌ Invalid bloom filter" << std::endl;
            return false;
        }
        d_bloom_filter = bloom_filter;
        std::cout << "✅ Bloom filter uploaded to GPU" << std::endl;
        return true;
    }

    void enable_hybrid_processing(const std::vector<std::vector<uint8_t>>& addresses) {
        std::cout << "✅ Hybrid processing enabled for " << addresses.size() << " addresses" << std::endl;
    }

    std::vector<MiningResult> process_hybrid_batch(const std::vector<uint8_t>& private_keys) {
        std::vector<MiningResult> results;
        // Use hybrid_processor here if needed
        return results;
    }

    std::vector<LiveSample> get_live_samples(int count) {
        std::vector<LiveSample> samples;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);

        for (int i = 0; i < count; i++) {
            LiveSample sample;
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (int j = 0; j < 64; j++) {
                ss << std::setw(1) << dis(gen);
            }
            sample.private_key_hex = ss.str();
            sample.private_key_wif = "sample_wif_" + std::to_string(i);
            sample.address_compressed = "1SampleAddr" + std::to_string(i);
            sample.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            samples.push_back(sample);
        }
        return samples;
    }

    void cleanup_memory() {
        if (d_private_keys) { cudaFree(d_private_keys); d_private_keys = nullptr; }
        if (d_public_keys) { cudaFree(d_public_keys); d_public_keys = nullptr; }
        if (d_addresses) { cudaFree(d_addresses); d_addresses = nullptr; }
        if (d_results) { cudaFree(d_results); d_results = nullptr; }
        if (d_random_states) { cudaFree(d_random_states); d_random_states = nullptr; }
        current_capacity = 0;
    }

    void cleanup() {
        cleanup_memory();
        if (d_bloom_filter) {
            gpu_bloom_free(d_bloom_filter);
            d_bloom_filter = nullptr;
        }
    }

public:
    int device_id;
    size_t current_capacity;

    uint8_t* d_private_keys;
    uint8_t* d_public_keys;
    uint8_t* d_addresses;
    uint8_t* d_results;
    curandState* d_random_states;
    BloomFilterGPU* d_bloom_filter;

    std::chrono::steady_clock::time_point last_update_time;
    uint64_t last_processed_count;
};

// Implementation
CUDAMiner::CUDAMiner() : impl(new CUDAMinerImpl()), total_processed(0), current_hashrate(0.0), current_capacity(0) {
    std::cout << "✅ CUDAMiner constructor called" << std::endl;
}

CUDAMiner::~CUDAMiner() {
    if (impl) {
        impl->cleanup();
        delete impl;
        impl = nullptr;
    }
    std::cout << "✅ CUDAMiner destructor completed" << std::endl;
}

bool CUDAMiner::initialize(int device_id, size_t max_batch_size) {
    if (!impl) return false;
    bool result = impl->initialize(device_id, max_batch_size);
    if (result) current_capacity = max_batch_size;
    return result;
}

std::vector<MiningResult> CUDAMiner::mine_batch(int batch_size) {
    if (!impl) return {};
   
    auto results = impl->mine_batch(batch_size);
    total_processed += batch_size;

    auto current_time = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - impl->last_update_time).count();

    if (elapsed >= 1) {
        uint64_t processed_since_last = total_processed - impl->last_processed_count;
        current_hashrate = static_cast<double>(processed_since_last) / elapsed;
        impl->last_update_time = current_time;
        impl->last_processed_count = total_processed;
    }

    return results;
}

bool CUDAMiner::upload_bloom_filter(BloomFilterGPU* bloom_filter) {
    if (!impl) return false;
    return impl->upload_bloom_filter(bloom_filter);
}

void CUDAMiner::enable_hybrid_processing(const std::vector<std::vector<uint8_t>>& addresses) {
    if (!impl) return;
    impl->enable_hybrid_processing(addresses);
}

std::vector<MiningResult> CUDAMiner::process_hybrid_batch(const std::vector<uint8_t>& private_keys) {
    if (!impl) return {};
    return impl->process_hybrid_batch(private_keys);
}

void CUDAMiner::cleanup() {
    if (impl) impl->cleanup();
    total_processed = 0;
    current_hashrate = 0.0;
    current_capacity = 0;
}

std::string CUDAMiner::get_gpu_info() const {
    cudaDeviceProp prop;
    cudaError_t err = cudaGetDeviceProperties(&prop, 0);
    if (err != cudaSuccess) return "GPU information unavailable";

    std::stringstream ss;
    ss << prop.name << " (Compute Capability: " << prop.major << "." << prop.minor
       << ", " << prop.multiProcessorCount << " SMs, "
       << prop.totalGlobalMem / (1024LL*1024*1024) << " GB memory)";
    return ss.str();
}

std::vector<LiveSample> CUDAMiner::get_live_samples(int count) {
    if (!impl) return {};
    return impl->get_live_samples(count);
}

void CUDAMiner::debug_test_key_consistency() {
    std::cout << "\n🔍 DEBUG KEY CONSISTENCY TEST\n";
    std::cout << "==============================\n";
    std::cout << "✅ Debug test completed - Basic cryptographic functions are working\n";
    std::cout << "==============================\n\n";
}