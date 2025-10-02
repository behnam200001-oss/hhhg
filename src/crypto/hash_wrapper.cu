#include "hash_wrapper.h"
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <cstring>
#include <iostream>

// جدول ثابت کامل K برای SHA256
__constant__ uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// ثابت‌های RIPEMD-160
__constant__ uint32_t RIPEMD160_K[5] = {
    0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E
};

__constant__ uint32_t RIPEMD160_KR[5] = {
    0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000
};

__constant__ int RIPEMD160_r[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

__constant__ int RIPEMD160_s[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

__constant__ int RIPEMD160_ss[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

// توابع کمکی
__device__ inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

__device__ inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

__device__ inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

__device__ inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

__device__ inline uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

__device__ inline uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// توابع RIPEMD-160
__device__ inline uint32_t f(uint32_t x, uint32_t y, uint32_t z, int round) {
    switch (round) {
        case 0: return x ^ y ^ z;
        case 1: return (x & y) | (~x & z);
        case 2: return (x | ~y) ^ z;
        case 3: return (x & z) | (y & ~z);
        case 4: return x ^ (y | ~z);
        default: return 0;
    }
}

__device__ inline uint32_t g(uint32_t x, uint32_t y, uint32_t z, int round) {
    switch (round) {
        case 0: return x ^ y ^ z;
        case 1: return (x & y) | (~x & z);
        case 2: return (x | ~y) ^ z;
        case 3: return (x & z) | (y & ~z);
        case 4: return x ^ (y | ~z);
        default: return 0;
    }
}

// پیاده‌سازی کامل SHA256
__device__ void gpu_sha256(const uint8_t* data, size_t len, uint8_t hash[32]) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    size_t total_blocks = (len + 8) / 64 + 1;
    size_t original_bit_len = len * 8;
    
    for (size_t block = 0; block < total_blocks; block++) {
        uint32_t w[64] = {0};
        uint8_t block_data[64] = {0};
        
        size_t copy_len = 0;
        if (block * 64 < len) {
            copy_len = min((size_t)64, len - block * 64);
            for (size_t i = 0; i < copy_len; i++) {
                block_data[i] = data[block * 64 + i];
            }
        }
        
        // Padding
        if (block == total_blocks - 1) {
            if (copy_len < 56) {
                block_data[copy_len] = 0x80;
                for (int i = 0; i < 8; i++) {
                    block_data[63 - i] = (original_bit_len >> (i * 8)) & 0xFF;
                }
            } else {
                block_data[copy_len] = 0x80;
            }
        }
        
        // Prepare message schedule
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)block_data[i*4] << 24) | 
                   ((uint32_t)block_data[i*4+1] << 16) | 
                   ((uint32_t)block_data[i*4+2] << 8) | 
                   block_data[i*4+3];
        }
        
        for (int i = 16; i < 64; i++) {
            w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
        }
        
        // Compression
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f_val = h[5], g_val = h[6], h_val = h[7];
        
        for (int i = 0; i < 64; i++) {
            uint32_t temp1 = h_val + sigma1(e) + ch(e, f_val, g_val) + k[i] + w[i];
            uint32_t temp2 = sigma0(a) + maj(a, b, c);
            
            h_val = g_val;
            g_val = f_val;
            f_val = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        
        // Update hash values
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f_val; h[6] += g_val; h[7] += h_val;
    }
    
    // Convert to big-endian
    for (int i = 0; i < 8; i++) {
        hash[i*4] = (h[i] >> 24) & 0xFF;
        hash[i*4+1] = (h[i] >> 16) & 0xFF;
        hash[i*4+2] = (h[i] >> 8) & 0xFF;
        hash[i*4+3] = h[i] & 0xFF;
    }
}

// پیاده‌سازی کامل RIPEMD-160
__device__ void gpu_ripemd160(const uint8_t* data, size_t len, uint8_t hash[20]) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476, h4 = 0xC3D2E1F0;
    
    // Pre-processing
    size_t original_bit_len = len * 8;
    size_t new_len = len + 1 + 8; // data + 0x80 + length
    size_t total_blocks = (new_len + 63) / 64;
    size_t total_bytes = total_blocks * 64;
    
    // Process each block
    for (size_t block = 0; block < total_blocks; block++) {
        uint32_t X[16] = {0};
        uint8_t block_data[64] = {0};
        
        size_t offset = block * 64;
        size_t bytes_to_copy = 0;
        
        if (offset < len) {
            bytes_to_copy = min((size_t)64, len - offset);
            for (size_t i = 0; i < bytes_to_copy; i++) {
                block_data[i] = data[offset + i];
            }
        }
        
        // Padding for last block
        if (block == total_blocks - 1) {
            if (bytes_to_copy < 64) {
                block_data[bytes_to_copy] = 0x80;
            }
            
            // Add length in bits (little-endian)
            for (int i = 0; i < 8; i++) {
                block_data[56 + i] = (original_bit_len >> (i * 8)) & 0xFF;
            }
        }
        
        // Convert to 32-bit words (little-endian)
        for (int i = 0; i < 16; i++) {
            X[i] = (uint32_t)block_data[i*4] | 
                   ((uint32_t)block_data[i*4+1] << 8) | 
                   ((uint32_t)block_data[i*4+2] << 16) | 
                   ((uint32_t)block_data[i*4+3] << 24);
        }
        
        // RIPEMD-160 compression function
        uint32_t a1 = h0, b1 = h1, c1 = h2, d1 = h3, e1 = h4;
        uint32_t a2 = h0, b2 = h1, c2 = h2, d2 = h3, e2 = h4;
        
        for (int i = 0; i < 80; i++) {
            int round = i / 16;
            uint32_t t;
            
            // Left line
            t = a1 + f(b1, c1, d1, round) + X[RIPEMD160_r[i]] + RIPEMD160_K[round];
            t = rotr(t, RIPEMD160_s[i]) + e1;
            a1 = e1; e1 = d1; d1 = rotr(c1, 10); c1 = b1; b1 = t;
            
            // Right line  
            t = a2 + g(b2, c2, d2, round) + X[RIPEMD160_r[79-i]] + RIPEMD160_KR[round];
            t = rotr(t, RIPEMD160_ss[i]) + e2;
            a2 = e2; e2 = d2; d2 = rotr(c2, 10); c2 = b2; b2 = t;
        }
        
        // Combine results
        uint32_t t = h1 + c1 + d2;
        h1 = h2 + d1 + e2;
        h2 = h3 + e1 + a2;
        h3 = h4 + a1 + b2;
        h4 = h0 + b1 + c2;
        h0 = t;
    }
    
    // Output (little-endian)
    hash[0] = h0 & 0xFF; hash[1] = (h0 >> 8) & 0xFF; hash[2] = (h0 >> 16) & 0xFF; hash[3] = (h0 >> 24) & 0xFF;
    hash[4] = h1 & 0xFF; hash[5] = (h1 >> 8) & 0xFF; hash[6] = (h1 >> 16) & 0xFF; hash[7] = (h1 >> 24) & 0xFF;
    hash[8] = h2 & 0xFF; hash[9] = (h2 >> 8) & 0xFF; hash[10] = (h2 >> 16) & 0xFF; hash[11] = (h2 >> 24) & 0xFF;
    hash[12] = h3 & 0xFF; hash[13] = (h3 >> 8) & 0xFF; hash[14] = (h3 >> 16) & 0xFF; hash[15] = (h3 >> 24) & 0xFF;
    hash[16] = h4 & 0xFF; hash[17] = (h4 >> 8) & 0xFF; hash[18] = (h4 >> 16) & 0xFF; hash[19] = (h4 >> 24) & 0xFF;
}

// تابع ترکیبی hash160
__device__ void gpu_hash160(const uint8_t* data, size_t len, uint8_t hash[20]) {
    uint8_t sha256_hash[32];
    gpu_sha256(data, len, sha256_hash);
    gpu_ripemd160(sha256_hash, 32, hash);
}

// هسته‌های Batch
__global__ void gpu_sha256_batch_kernel(const uint8_t* data, uint8_t* hashes, size_t data_len, size_t batch_size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
    
    const uint8_t* item_data = data + idx * data_len;
    uint8_t* item_hash = hashes + idx * 32;
    gpu_sha256(item_data, data_len, item_hash);
}

__global__ void gpu_hash160_batch_kernel(const uint8_t* data, uint8_t* hashes, size_t data_len, size_t batch_size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
    
    const uint8_t* item_data = data + idx * data_len;
    uint8_t* item_hash = hashes + idx * 20;
    gpu_hash160(item_data, data_len, item_hash);
}

// توابع host
cudaError_t gpu_sha256_batch(const uint8_t* data, uint8_t* hashes, size_t data_len, size_t batch_size, cudaStream_t stream) {
    if (!data || !hashes || data_len == 0 || batch_size == 0) {
        return cudaErrorInvalidValue;
    }
    
    int threads = 256;
    int blocks = (batch_size + threads - 1) / threads;
    gpu_sha256_batch_kernel<<<blocks, threads, 0, stream>>>(data, hashes, data_len, batch_size);
    return cudaGetLastError();
}

cudaError_t gpu_hash160_batch(const uint8_t* data, uint8_t* hashes, size_t data_len, size_t batch_size, cudaStream_t stream) {
    if (!data || !hashes || data_len == 0 || batch_size == 0) {
        return cudaErrorInvalidValue;
    }
    
    int threads = 256;
    int blocks = (batch_size + threads - 1) / threads;
    gpu_hash160_batch_kernel<<<blocks, threads, 0, stream>>>(data, hashes, data_len, batch_size);
    return cudaGetLastError();
}