#include "gpu_bloom.h"
#include "utils/atomic_helpers.h"
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <iostream>
#include <cmath>
#include <cstring>

// MurmurHash3
__device__ uint64_t gpu_murmurhash3_64(const void* key, int len, uint64_t seed) {
    const uint64_t m = 0xc6a4a7935bd1e995ULL;
    const int r = 47;
   
    const uint8_t* data = (const uint8_t*)key;
    const int nblocks = len / 8;
   
    uint64_t h = seed ^ (len * m);
   
    const uint64_t* blocks = (const uint64_t*)(data);
   
    for (int i = 0; i < nblocks; i++) {
        uint64_t k = blocks[i];
       
        k *= m;
        k ^= k >> r;
        k *= m;
       
        h ^= k;
        h *= m;
    }
   
    const uint8_t* tail = data + nblocks * 8;
    uint64_t k1 = 0;
   
    switch (len & 7) {
        case 7: k1 ^= ((uint64_t)tail[6]) << 48;
        case 6: k1 ^= ((uint64_t)tail[5]) << 40;
        case 5: k1 ^= ((uint64_t)tail[4]) << 32;
        case 4: k1 ^= ((uint64_t)tail[3]) << 24;
        case 3: k1 ^= ((uint64_t)tail[2]) << 16;
        case 2: k1 ^= ((uint64_t)tail[1]) << 8;
        case 1: k1 ^= ((uint64_t)tail[0]);
                h ^= k1;
                h *= m;
    }
   
    h ^= h >> r;
    h *= m;
    h ^= h >> r;
   
    return h;
}

// Add batch kernel
__global__ void gpu_bloom_add_batch_kernel(BloomFilterGPU filter, const uint8_t* data, size_t data_len, size_t batch_size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
   
    const uint8_t* item_data = data + idx * data_len;
   
    uint64_t hash1 = gpu_murmurhash3_64(item_data, data_len, filter.seed);
    uint64_t hash2 = gpu_murmurhash3_64(item_data, data_len, filter.seed + 1);
   
    for (unsigned int i = 0; i < filter.num_hashes; i++) {
        uint64_t hash = hash1 + i * hash2;
        uint64_t bit_index = hash % filter.size;
        uint64_t word_index = bit_index / 64;
        uint64_t bit_mask = 1ULL << (bit_index % 64);
       
        atomicOr64(&filter.data[word_index], bit_mask);
    }
}

// Variable length add
__global__ void gpu_bloom_add_batch_variable_kernel(BloomFilterGPU filter, const uint8_t* batch_data, const size_t* data_lengths, size_t batch_size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
   
    size_t data_offset = 0;
    for (int i = 0; i < idx; i++) {
        data_offset += data_lengths[i];
    }
   
    const uint8_t* item_data = batch_data + data_offset;
    size_t item_len = data_lengths[idx];
   
    uint64_t hash1 = gpu_murmurhash3_64(item_data, item_len, filter.seed);
    uint64_t hash2 = gpu_murmurhash3_64(item_data, item_len, filter.seed + 1);
   
    for (unsigned int i = 0; i < filter.num_hashes; i++) {
        uint64_t hash = hash1 + i * hash2;
        uint64_t bit_index = hash % filter.size;
        uint64_t word_index = bit_index / 64;
        uint64_t bit_mask = 1ULL << (bit_index % 64);
       
        atomicOr64(&filter.data[word_index], bit_mask);
    }
}

// Check batch
__global__ void gpu_bloom_check_batch_kernel(BloomFilterGPU filter, const uint8_t* data, size_t data_len, uint8_t* results, size_t batch_size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
   
    const uint8_t* item_data = data + idx * data_len;
   
    uint64_t hash1 = gpu_murmurhash3_64(item_data, data_len, filter.seed);
    uint64_t hash2 = gpu_murmurhash3_64(item_data, data_len, filter.seed + 1);
   
    uint8_t found = 1;
   
    for (unsigned int i = 0; i < filter.num_hashes; i++) {
        uint64_t hash = hash1 + i * hash2;
        uint64_t bit_index = hash % filter.size;
        uint64_t word_index = bit_index / 64;
        uint64_t bit_mask = 1ULL << (bit_index % 64);
       
        uint64_t bloom_word = atomicRead64(&filter.data[word_index]);
       
        if ((bloom_word & bit_mask) == 0) {
            found = 0;
            break;
        }
    }
   
    results[idx] = found;
}

BloomFilterGPU* gpu_bloom_create(size_t size, unsigned int num_hashes) {
    BloomFilterGPU* filter = new BloomFilterGPU();
    if (!filter) {
        std::cerr << "❌ Failed to allocate Bloom filter structure" << std::endl;
        return nullptr;
    }
   
    filter->size = size;
    filter->num_hashes = num_hashes;
    filter->seed = 0x1234567890ABCDEFULL;
    filter->array_size = (size + 63) / 64;
   
    cudaError_t err = cudaMalloc(&filter->data, filter->array_size * sizeof(uint64_t));
    if (err != cudaSuccess) {
        std::cerr << "❌ Failed to allocate Bloom filter data on GPU: " << cudaGetErrorString(err) << std::endl;
        delete filter;
        return nullptr;
    }
   
    err = cudaMemset(filter->data, 0, filter->array_size * sizeof(uint64_t));
    if (err != cudaSuccess) {
        std::cerr << "❌ Failed to initialize Bloom filter data: " << cudaGetErrorString(err) << std::endl;
        cudaFree(filter->data);
        delete filter;
        return nullptr;
    }
   
    std::cout << "✅ GPU Bloom filter created: " << size << " bits, " << num_hashes << " hash functions, " << (filter->array_size * sizeof(uint64_t)) / (1024*1024) << " MB" << std::endl;
   
    return filter;
}

void gpu_bloom_free(BloomFilterGPU* filter) {
    if (filter) {
        if (filter->data) cudaFree(filter->data);
        delete filter;
    }
}

cudaError_t gpu_bloom_add_batch(BloomFilterGPU* filter, const uint8_t* data, size_t data_len, size_t batch_size, cudaStream_t stream) {
    if (!filter || !data || data_len == 0 || batch_size == 0) return cudaErrorInvalidValue;
   
    int threads_per_block = 256;
    int blocks = (batch_size + threads_per_block - 1) / threads_per_block;
   
    gpu_bloom_add_batch_kernel<<<blocks, threads_per_block, 0, stream>>>(*filter, data, data_len, batch_size);
   
    return cudaGetLastError();
}

cudaError_t gpu_bloom_add_batch_variable(BloomFilterGPU* filter, const uint8_t* batch_data, const size_t* data_lengths, size_t batch_size, cudaStream_t stream) {
    if (!filter || !batch_data || !data_lengths || batch_size == 0) return cudaErrorInvalidValue;
   
    int threads_per_block = 256;
    int blocks = (batch_size + threads_per_block - 1) / threads_per_block;
   
    gpu_bloom_add_batch_variable_kernel<<<blocks, threads_per_block, 0, stream>>>(*filter, batch_data, data_lengths, batch_size);
   
    return cudaGetLastError();
}

cudaError_t gpu_bloom_check_batch(BloomFilterGPU* filter, const uint8_t* data, size_t data_len, uint8_t* results, size_t batch_size, cudaStream_t stream) {
    if (!filter || !data || !results || data_len == 0 || batch_size == 0) return cudaErrorInvalidValue;
   
    int threads_per_block = 256;
    int blocks = (batch_size + threads_per_block - 1) / threads_per_block;
   
    gpu_bloom_check_batch_kernel<<<blocks, threads_per_block, 0, stream>>>(*filter, data, data_len, results, batch_size);
   
    return cudaGetLastError();
}

size_t gpu_bloom_estimate_size(uint64_t expected_elements, double false_positive_rate) {
    if (false_positive_rate <= 0.0 || false_positive_rate >= 1.0) false_positive_rate = 0.001;
    double size = -((double)expected_elements * log(false_positive_rate)) / (log(2) * log(2));
    return (size_t)ceil(size);
}

unsigned int gpu_bloom_estimate_hashes(size_t size, uint64_t expected_elements) {
    if (expected_elements == 0) return 7;
    double hashes = ((double)size / expected_elements) * log(2);
    return (unsigned int)ceil(hashes);
}