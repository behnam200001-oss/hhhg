#pragma once

#ifndef HASH_WRAPPER_H
#define HASH_WRAPPER_H

#include <cstdint>
#include <cuda_runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

// توابع هش بهینه برای GPU
__device__ void gpu_sha256(const uint8_t* data, size_t len, uint8_t hash[32]);
__device__ void gpu_ripemd160(const uint8_t* data, size_t len, uint8_t hash[20]);

// تابع ترکیبی SHA256 + RIPEMD160
__device__ void gpu_hash160(const uint8_t* data, size_t len, uint8_t hash[20]);

// توابع batch برای بهینه‌سازی
cudaError_t gpu_sha256_batch(
    const uint8_t* data, 
    uint8_t* hashes, 
    size_t data_len, 
    size_t batch_size,
    cudaStream_t stream
);

cudaError_t gpu_hash160_batch(
    const uint8_t* data, 
    uint8_t* hashes, 
    size_t data_len, 
    size_t batch_size,
    cudaStream_t stream
);

#ifdef __cplusplus
}
#endif

#endif // HASH_WRAPPER_H