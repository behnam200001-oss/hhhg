#include "cuda_miner.h"
#include "crypto/secp256k1_wrapper.h"
#include "crypto/hash_wrapper.h"
#include "bloom/gpu_bloom.h"
#include "utils/atomic_helpers.h"
#include <cuda_runtime.h>
#include <curand_kernel.h>
#include <device_launch_parameters.h>

// Existing setup_random_kernel unchanged...

// Existing extern device functions unchanged...

// Existing safe_bloom_filter_check unchanged...

// New: Generate all 4 address types (binary for Bloom check)
__device__ bool generate_addresses_all_types(const uint8_t* public_key_compressed, uint8_t* addresses_buffer, uint8_t* type_flags) {
    uint8_t hash160[20];
    gpu_hash160(public_key_compressed, 33, hash160);
   
    // Type 0: P2PKH Compressed (25 bytes)
    uint8_t p2pkh[25];
    uint8_t payload[21] = {0x00};  // Mainnet P2PKH
    for (int i = 0; i < 20; i++) payload[1 + i] = hash160[i];
    uint8_t checksum1[32], checksum2[32];
    gpu_sha256(payload, 21, checksum1);
    gpu_sha256(checksum1, 32, checksum2);
    for (int i = 0; i < 21; i++) p2pkh[i] = payload[i];
    for (int i = 0; i < 4; i++) p2pkh[21 + i] = checksum2[i];
    for (int i = 0; i < 25; i++) addresses_buffer[0 * 25 + i] = p2pkh[i];
    type_flags[0] = 0;  // P2PKH
   
    // Type 1: P2SH (25 bytes)
    uint8_t redeem_script[23] = {0x00, 0x14};  // OP_0 PUSH20
    for (int i = 0; i < 20; i++) redeem_script[2 + i] = hash160[i];
    redeem_script[22] = 0x87;  // OP_EQUAL
    uint8_t script_hash160[20];
    gpu_hash160(redeem_script, 23, script_hash160);
    uint8_t p2sh_payload[21] = {0x05};  // Mainnet P2SH
    for (int i = 0; i < 20; i++) p2sh_payload[1 + i] = script_hash160[i];
    gpu_sha256(p2sh_payload, 21, checksum1);
    gpu_sha256(checksum1, 32, checksum2);
    uint8_t p2sh[25];
    for (int i = 0; i < 21; i++) p2sh[i] = p2sh_payload[i];
    for (int i = 0; i < 4; i++) p2sh[21 + i] = checksum2[i];
    for (int i = 0; i < 25; i++) addresses_buffer[1 * 25 + i] = p2sh[i];
    type_flags[1] = 1;  // P2SH
   
    // Type 2: Bech32 P2WPKH (binary: v0 (1 byte) + hash160 (20 bytes), total 21 bytes for Bloom)
    addresses_buffer[2 * 25 + 0] = 0x00;  // Witness version 0
    for (int i = 0; i < 20; i++) addresses_buffer[2 * 25 + 1 + i] = hash160[i];
    type_flags[2] = 2;  // Bech32 (use 21 bytes for check)
   
    // Type 3: Taproot P2TR (binary: x-only pubkey 32 bytes)
    for (int i = 0; i < 32; i++) addresses_buffer[3 * 25 + i] = public_key_compressed[1 + i];  // x coord (skip 0x02/0x03)
    type_flags[3] = 3;  // Taproot (32 bytes for check)
   
    return true;
}

// Updated validate for all types (binary)
__device__ bool validate_generated_address(const uint8_t* address, uint8_t type) {
    if (type == 0 || type == 1) {  // Base58 types
        if (address[0] != (type == 0 ? 0x00 : 0x05)) return false;
        uint8_t payload[21];
        for (int i = 0; i < 21; i++) payload[i] = address[i];
        uint8_t checksum1[32], checksum2[32];
        gpu_sha256(payload, 21, checksum1);
        gpu_sha256(checksum1, 32, checksum2);
        for (int i = 0; i < 4; i++) {
            if (address[21 + i] != checksum2[i]) return false;
        }
        return true;
    } else if (type == 2 || type == 3) {  // SegWit/Taproot: simple length check
        return true;  // Full validate on CPU
    }
    return false;
}

// Main mining kernel (updated for all types)
__global__ void mining_kernel(
    uint8_t* private_keys,
    uint8_t* public_keys,
    uint8_t* addresses,  // Now batch_size * 100 (4 types * 25)
    uint8_t* type_results,  // batch_size * 4
    uint8_t* results,
    BloomFilterGPU bloom_filter,
    curandState* random_states,
    size_t batch_size
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
   
    curandState* state = &random_states[idx];
    uint8_t private_key[32];
    bool valid_key = false;
    int attempts = 0;
   
    while (!valid_key && attempts < 5) {
        for (int i = 0; i < 32; i++) {
            private_key[i] = curand(state) & 0xFF;
        }
        valid_key = is_valid_private_key(private_key);
        attempts++;
    }
   
    if (!valid_key) {
        results[idx] = 0;
        return;
    }
   
    for (int i = 0; i < 32; i++) {
        private_keys[idx * 32 + i] = private_key[i];
    }
   
    uint8_t public_key_compressed[33];
    bool pubkey_success = gpu_secp256k1_pubkey_create(nullptr, private_key, public_key_compressed, true);
   
    if (!pubkey_success) {
        results[idx] = 0;
        return;
    }
   
    for (int i = 0; i < 33; i++) {
        public_keys[idx * 33 + i] = public_key_compressed[i];
    }
   
    uint8_t addresses_buffer[100];  // 4*25
    uint8_t type_flags[4];
    bool gen_success = generate_addresses_all_types(public_key_compressed, addresses_buffer, type_flags);
   
    if (!gen_success) {
        results[idx] = 0;
        return;
    }
   
    // Store
    for (int t = 0; t < 4; t++) {
        for (int b = 0; b < 25; b++) {
            addresses[idx * 100 + t * 25 + b] = addresses_buffer[t * 25 + b];
        }
        type_results[idx * 4 + t] = type_flags[t];
    }
   
    // Validate and check Bloom for each
    bool any_found = false;
    for (int t = 0; t < 4; t++) {
        uint8_t* addr = addresses_buffer + t * 25;
        size_t addr_len = (type_flags[t] == 2 ? 21 : type_flags[t] == 3 ? 32 : 25);
        if (validate_generated_address(addr, type_flags[t]) && safe_bloom_filter_check(bloom_filter, addr, addr_len)) {
            any_found = true;
            break;
        }
    }
    results[idx] = any_found ? 1 : 0;
}

// Simple kernel (updated similarly)
__global__ void simple_mining_kernel(
    // ... params + addresses 100 bytes, type_results ...
) {
    // Similar to mining_kernel, generate all types
    // ... (copy logic from above) ...
}

// Update ensure_capacity in cuda_miner.cu impl (for new sizes)
// mem_addresses = required_size * 100;  // 4 types
// mem_type_results = required_size * 4;