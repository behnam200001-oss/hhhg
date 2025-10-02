#pragma once

#ifndef GPU_BLOOM_H
#define GPU_BLOOM_H

#include <cstdint>
#include <cuda_runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BloomFilterGPU {
    uint64_t* data;
    size_t size;
    unsigned int num_hashes;
    uint64_t seed;
    size_t array_size;
} BloomFilterGPU;

// تابع هش برای استفاده در کرنل‌های دیگر
__device__ uint64_t gpu_murmurhash3_64(const void* key, int len, uint64_t seed);

BloomFilterGPU* gpu_bloom_create(size_t size, unsigned int num_hashes);
void gpu_bloom_free(BloomFilterGPU* filter);

cudaError_t gpu_bloom_add_batch(
    BloomFilterGPU* filter, 
    const uint8_t* data, 
    size_t data_len, 
    size_t batch_size,
    cudaStream_t stream
);

// تابع جدید برای داده‌های با طول متغیر
cudaError_t gpu_bloom_add_batch_variable(
    BloomFilterGPU* filter, 
    const uint8_t* batch_data,
    const size_t* data_lengths,
    size_t batch_size,
    cudaStream_t stream
);

cudaError_t gpu_bloom_check_batch(
    BloomFilterGPU* filter, 
    const uint8_t* data, 
    size_t data_len, 
    uint8_t* results, // تغییر از bool به uint8_t
    size_t batch_size,
    cudaStream_t stream
);

size_t gpu_bloom_estimate_size(uint64_t expected_elements, double false_positive_rate);
unsigned int gpu_bloom_estimate_hashes(size_t size, uint64_t expected_elements);

#ifdef __cplusplus
}
#endif

#endif // GPU_BLOOM_H