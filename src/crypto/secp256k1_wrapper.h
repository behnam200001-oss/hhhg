#pragma once

#ifndef SECP256K1_WRAPPER_H
#define SECP256K1_WRAPPER_H

#include <cstdint>
#include <cuda_runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

// ساختار بهینه‌شده برای GPU
typedef struct {
    int device_id;
    void* d_context;  // اشاره‌گر به context روی GPU
} Secp256k1Context;

// توابع مدیریت
Secp256k1Context* secp256k1_init(int device_id);
void secp256k1_free(Secp256k1Context* context);

// توابع محاسباتی روی GPU - اصلاح signature
__device__ bool gpu_secp256k1_pubkey_create(
    const void* context,  // تغییر از Secp256k1Context* به void*
    const uint8_t* private_key, 
    uint8_t* public_key, 
    bool compressed
);

// تابع بررسی صحت کلید خصوصی
__device__ bool is_valid_private_key(const uint8_t* private_key);

// توابع batch برای بهینه‌سازی
cudaError_t gpu_secp256k1_batch_pubkey_create(
    const Secp256k1Context* context,
    const uint8_t* private_keys,
    uint8_t* public_keys,
    bool compressed,
    size_t batch_size,
    cudaStream_t stream
);

#ifdef __cplusplus
}
#endif

#endif // SECP256K1_WRAPPER_H