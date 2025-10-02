#pragma once

#ifndef HYBRID_PROCESSOR_H
#define HYBRID_PROCESSOR_H

#include <vector>
#include <string>
#include <cstdint>
#include "cuda_miner.h"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>  // اضافه شده برای تعریف secp256k1_context

class HybridProcessor {
public:
    HybridProcessor();
    ~HybridProcessor();
    
    // پردازش دسته‌ای کلیدها با استفاده از libsecp256k1
    std::vector<MiningResult> process_candidates(
        const std::vector<uint8_t>& private_keys,
        const std::vector<std::vector<uint8_t>>& target_addresses);
    
private:
    secp256k1_context* ctx;
    
    // تولید آدرس استاندارد
    std::string generate_standard_address(const uint8_t* public_key_compressed);
    
    // بررسی تطابق آدرس
    bool check_address_match(const std::string& address, 
                           const std::vector<std::vector<uint8_t>>& target_addresses);
    
    // تبدیل بایت به هگز
    std::string bytes_to_hex(const uint8_t* data, size_t len);
    
    // تولید WIF
    std::string private_key_to_wif(const uint8_t* private_key, bool compressed = true);
    
    // کدگذاری Base58
    std::string base58_encode(const std::vector<uint8_t>& data);
    
    // دیکد Base58
    bool base58_decode(const std::string& address, std::vector<uint8_t>& decoded);
};

#endif // HYBRID_PROCESSOR_H