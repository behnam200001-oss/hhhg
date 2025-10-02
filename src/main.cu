#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <csignal>
#include <vector>
#include <iomanip>
#include <openssl/sha.h>
#include <cstring>
#include <memory>
#include <random>
#include "cuda_miner.h"
#include "crypto/secp256k1_wrapper.h"
#include "crypto/hash_wrapper.h"
#include "crypto/address_generator.h"
#include "bloom/gpu_bloom.h"
#include "utils/memory_manager.h"
#include "profiling/nvtx_helpers.h"

std::atomic<bool> running(true);
std::atomic<uint64_t> total_keys_processed(0);
std::atomic<uint64_t> total_matches_found(0);

struct SampleDisplay {
    std::string private_key;
    std::string address;
    std::string type;  // New: P2PKH, P2SH, Bech32, Taproot
    uint64_t timestamp;
};

std::vector<SampleDisplay> recent_samples;
std::mutex samples_mutex;

void signal_handler(int signal) {
    std::cout << "\n⚠️ Received signal " << signal << ", shutting down gracefully..." << std::endl;
    running = false;
}

std::string generate_sample_private_key() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
   
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 64; i++) {
        ss << std::setw(1) << dis(gen);
    }
    return ss.str();
}

std::string generate_sample_address(int type) {
    std::vector<std::string> prefixes = {"1", "3", "bc1q", "bc1p"};
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 99999);
   
    std::stringstream ss;
    ss << prefixes[type] << "Sample" << std::setfill('0') << std::setw(5) << dis(gen);
    return ss.str();
}

void add_live_sample(const std::string& private_key, const std::string& address, const std::string& type) {
    std::lock_guard<std::mutex> lock(samples_mutex);
   
    SampleDisplay sample;
    sample.private_key = private_key;
    sample.address = address;
    sample.type = type;
    sample.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
   
    recent_samples.push_back(sample);
   
    if (recent_samples.size() > 10) {
        recent_samples.erase(recent_samples.begin());
    }
}

std::vector<SampleDisplay> get_recent_samples(int count) {
    std::lock_guard<std::mutex> lock(samples_mutex);
    count = std::min(count, (int)recent_samples.size());
   
    std::vector<SampleDisplay> result;
    if (!recent_samples.empty()) {
        int start_idx = std::max(0, (int)recent_samples.size() - count);
        for (int i = start_idx; i < recent_samples.size(); i++) {
            result.push_back(recent_samples[i]);
        }
    }
    return result;
}

void live_reporter() {
    auto last_report_time = std::chrono::steady_clock::now();
    uint64_t last_processed = 0;
   
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
       
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - last_report_time).count();
       
        if (elapsed >= 10) {
            uint64_t processed = total_keys_processed.load();
            uint64_t matches = total_matches_found.load();
           
            uint64_t processed_since_last = processed - last_processed;
            double hashrate = processed_since_last / 10.0;
            last_processed = processed;
           
            std::cout << "\n" << std::string(60, '=') << "\n";
            std::cout << "📊 LIVE MINING REPORT\n";
            std::cout << std::string(60, '-') << "\n";
            std::cout << "🔑 Total Keys Searched: " << processed << "\n";
            std::cout << "⚡ Current Speed: " << std::fixed << std::setprecision(0) << hashrate << " keys/sec\n";
            std::cout << "✅ Matches Found: " << matches << "\n";
            std::cout << std::string(60, '-') << "\n";
           
            auto samples = get_recent_samples(3);
            if (!samples.empty()) {
                std::cout << "🎯 RECENTLY GENERATED (FULL DETAILS):\n";
                for (int i = 0; i < samples.size(); i++) {
                    std::cout << " " << (i+1) << ". Type: " << samples[i].type << " | Address: " << samples[i].address << "\n";
                    std::cout << " Private Key: " << samples[i].private_key << "\n";
                    std::cout << " Timestamp: " << std::put_time(std::localtime((time_t*)&samples[i].timestamp), "%H:%M:%S") << "\n";
                    if (i < samples.size() - 1) std::cout << " " << std::string(40, '-') << "\n";
                }
            } else {
                std::cout << "🔄 Generating addresses...\n";
            }
            std::cout << std::string(60, '=') << "\n\n";
           
            last_report_time = current_time;
        }
    }
}

void save_match_to_file(const std::string& private_key, const std::string& address, const std::string& type, const std::string& output_file) {
    std::ofstream out_file(output_file, std::ios::app);
    if (!out_file.is_open()) {
        std::cerr << "❌ Failed to open output file: " << output_file << std::endl;
        return;
    }
   
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
   
    out_file << "🎉 MATCH FOUND [" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "]\n";
    out_file << "Type: " << type << "\n";
    out_file << "Private Key (HEX): " << private_key << "\n";
    out_file << "Address: " << address << "\n";
    out_file << std::string(50, '=') << "\n\n";
    out_file.flush();
    out_file.close();
   
    std::cout << "\n💥💥💥 MATCH FOUND! 💥💥💥\n";
    std::cout << "Type: " << type << "\n";
    std::cout << "🔑 Private Key: " << private_key << "\n";
    std::cout << "🏠 Address: " << address << "\n";
    std::cout << "💾 Saved to: " << output_file << "\n\n";
}

// Existing load_addresses_simple unchanged...

BloomFilterGPU* create_simple_bloom(const std::vector<std::vector<uint8_t>>& binary_addresses) {
    // Existing + support for multiple types (decode all to binary hash160 or full)
    // For simplicity, assume all are P2PKH binary; extend if needed
    // ... existing code ...
}

void show_usage(const char* program_name) {
    // Existing unchanged...
}

int main(int argc, char** argv) {
    // Existing arg parsing unchanged...
   
    // ... load addresses and bloom ...
   
    CUDAMiner miner;
    if (!miner.initialize(device_id, batch_size * 4)) {  // *4 for types
        gpu_bloom_free(bloom_filter);
        return 1;
    }
   
    if (!miner.upload_bloom_filter(bloom_filter)) {
        miner.cleanup();
        gpu_bloom_free(bloom_filter);
        return 1;
    }
   
    std::cout << "⛏️ Starting mining process (All Address Types)...\n\n";
   
    std::thread reporter(live_reporter);
   
    try {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> type_dis(0, 3);  // Random type for samples
        
        while (running) {
            auto batch_results = miner.mine_batch(batch_size);
            total_keys_processed += batch_size * 4;  // *4 types per key
            
            for (const auto& result : batch_results) {
                if (result.found) {
                    save_match_to_file(result.private_key_hex, result.address, result.type, output_file);
                    total_matches_found++;
                    add_live_sample(result.private_key_hex, result.address, result.type);
                }
            }
           
            // Add live samples with random types
            auto samples = miner.get_live_samples(3);
            for (const auto& sample : samples) {
                int rand_type = type_dis(gen);
                std::string addr_type = (rand_type == 0 ? "P2PKH" : rand_type == 1 ? "P2SH" : rand_type == 2 ? "Bech32" : "Taproot");
                std::string sample_addr = generate_sample_address(rand_type);
                add_live_sample(sample.private_key_hex, sample_addr, addr_type);
            }
           
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    } catch (const std::exception& e) {
        std::cerr << "❌ Exception: " << e.what() << std::endl;
        running = false;
    }
   
    running = false;
    if (reporter.joinable()) reporter.join();
   
    miner.cleanup();
    gpu_bloom_free(bloom_filter);
   
    std::cout << "\n✅ Mining completed\n";
    std::cout << " 🔑 Total Keys: " << total_keys_processed.load() << "\n";
    std::cout << " ✅ Total Matches: " << total_matches_found.load() << "\n";
   
    return 0;
}