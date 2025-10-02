#pragma once

#ifndef CUDA_MINER_H
#define CUDA_MINER_H

#include <vector>
#include <string>
#include <cstdint>
#include <atomic>

struct BloomFilterGPU;

struct MiningResult {
    bool found;
    std::string private_key_hex;
    std::string private_key_wif;
    std::string p2pkh_compressed;
    std::string p2pkh_uncompressed;
    std::string p2sh;
    std::string address;
};

// ساختار برای نمونه‌های زنده
struct LiveSample {
    std::string private_key_hex;
    std::string private_key_wif;
    std::string address_compressed;
    std::string address_uncompressed;
    std::string address_p2sh;
    uint64_t timestamp;
};

class CUDAMiner {
public:
    CUDAMiner();
    ~CUDAMiner();

    bool initialize(int device_id = 0, size_t max_batch_size = 1000000);
    std::vector<MiningResult> mine_batch(int batch_size);
    bool upload_bloom_filter(BloomFilterGPU* bloom_filter);
    void cleanup();
    
    // Performance monitoring
    uint64_t get_total_processed() const { return total_processed; }
    double get_hashrate() const { return current_hashrate; }
    size_t get_batch_capacity() const { return current_capacity; }
    std::string get_gpu_info() const;
    
    // تابع جدید برای گرفتن نمونه‌های زنده
    std::vector<LiveSample> get_live_samples(int count = 3);

    // توابع جدید برای دیباگ
    static void debug_test_key_consistency();

    // توابع جدید اضافه شده برای پردازش هیبریدی
    void enable_hybrid_processing(const std::vector<std::vector<uint8_t>>& addresses);
    std::vector<MiningResult> process_hybrid_batch(const std::vector<uint8_t>& private_keys);

private:
    class CUDAMinerImpl;
    CUDAMinerImpl* impl;
    
    std::atomic<uint64_t> total_processed;
    std::atomic<double> current_hashrate;
    size_t current_capacity;
};

#endif // CUDA_MINER_H
