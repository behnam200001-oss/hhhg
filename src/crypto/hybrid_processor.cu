#include "hybrid_processor.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>

HybridProcessor::HybridProcessor() : ctx(nullptr) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) throw std::runtime_error("Failed to create secp256k1 context");
   
    std::vector<uint8_t> seed(32, 0x01); // Dummy seed for now
    secp256k1_context_randomize(ctx, seed.data());
}

HybridProcessor::~HybridProcessor() {
    if (ctx) secp256k1_context_destroy(ctx);
}

std::vector<MiningResult> HybridProcessor::process_candidates(const std::vector<uint8_t>& private_keys, const std::vector<std::vector<uint8_t>>& target_addresses) {
    std::vector<MiningResult> results;
   
    if (private_keys.size() % 32 != 0) throw std::invalid_argument("Private keys must be multiples of 32 bytes");
   
    size_t key_count = private_keys.size() / 32;
   
    for (size_t i = 0; i < key_count; i++) {
        const uint8_t* priv_key = private_keys.data() + i * 32;
       
        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key)) {
           
            uint8_t pubkey_serialized[33];
            size_t outputlen = 33;
            secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);
           
            std::string address = generate_standard_address(pubkey_serialized);
           
            if (check_address_match(address, target_addresses)) {
                MiningResult result;
                result.found = true;
                result.private_key_hex = bytes_to_hex(priv_key, 32);
                result.private_key_wif = private_key_to_wif(priv_key, true);
                result.address = address;
                result.p2pkh_compressed = address;
               
                results.push_back(result);
               
                std::cout << "🎉 MATCH FOUND via Hybrid Processor!" << std::endl;
                std::cout << " Address: " << address << std::endl;
                std::cout << " Private Key: " << result.private_key_hex << std::endl;
            }
        }
    }
   
    return results;
}

std::string HybridProcessor::generate_standard_address(const uint8_t* public_key_compressed) {
    uint8_t sha256_hash[32];
    uint8_t ripemd160_hash[20];
   
    SHA256(public_key_compressed, 33, sha256_hash);
    RIPEMD160(sha256_hash, 32, ripemd160_hash);
   
    std::vector<uint8_t> payload;
    payload.push_back(0x00);
    payload.insert(payload.end(), ripemd160_hash, ripemd160_hash + 20);
   
    uint8_t checksum1[32], checksum2[32];
    SHA256(payload.data(), payload.size(), checksum1);
    SHA256(checksum1, 32, checksum2);
   
    std::vector<uint8_t> address_bytes = payload;
    address_bytes.insert(address_bytes.end(), checksum2, checksum2 + 4);
   
    return base58_encode(address_bytes);
}

bool HybridProcessor::check_address_match(const std::string& address, const std::vector<std::vector<uint8_t>>& target_addresses) {
    std::vector<uint8_t> decoded_address;
    if (!base58_decode(address, decoded_address)) return false;
   
    for (const auto& target_addr : target_addresses) {
        if (decoded_address == target_addr) return true;
    }
    return false;
}

std::string HybridProcessor::bytes_to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return ss.str();
}

std::string HybridProcessor::private_key_to_wif(const uint8_t* private_key, bool compressed) {
    std::vector<uint8_t> wif_data;
    wif_data.push_back(0x80);
    wif_data.insert(wif_data.end(), private_key, private_key + 32);
   
    if (compressed) wif_data.push_back(0x01);
   
    uint8_t checksum1[32], checksum2[32];
    SHA256(wif_data.data(), wif_data.size(), checksum1);
    SHA256(checksum1, 32, checksum2);
   
    wif_data.insert(wif_data.end(), checksum2, checksum2 + 4);
   
    return base58_encode(wif_data);
}

// Fixed base58_encode in hybrid (same as address_generator)
std::string HybridProcessor::base58_encode(const std::vector<uint8_t>& data) {
    // Copy the fixed implementation from address_generator
    if (data.empty()) return "";
   
    size_t leading_zeros = 0;
    while (leading_zeros < data.size() && data[leading_zeros] == 0) leading_zeros++;
   
    std::vector<uint8_t> digits;
    size_t size = data.size() * 138 / 100 + 1;
    digits.resize(size, 0);
   
    for (size_t i = leading_zeros; i < data.size(); i++) {
        uint32_t carry = data[i];
        for (size_t j = 0; j < size; j++) {
            carry += (uint32_t)(digits[j]) << 8;
            digits[j] = carry % 58;
            carry /= 58;
        }
    }
   
    size_t start = 0;
    while (start < size && digits[start] == 0) start++;
   
    std::string result;
    result.reserve(leading_zeros + (size - start));
   
    for (size_t i = 0; i < leading_zeros; i++) result += '1';
   
    for (int i = static_cast<int>(size) - 1; i >= static_cast<int>(start); i--) {
        result += BASE58_CHARS[digits[i]];
    }
   
    if (result.empty()) result = "1";
    return result;
}

bool HybridProcessor::base58_decode(const std::string& address, std::vector<uint8_t>& decoded) {
    const char* BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
   
    if (address.empty()) return false;
   
    size_t leading_ones = 0;
    while (leading_ones < address.size() && address[leading_ones] == '1') leading_ones++;
   
    std::vector<uint8_t> result(25, 0);
   
    for (size_t i = leading_ones; i < address.size(); i++) {
        char c = address[i];
        const char* pos = strchr(BASE58_CHARS, c);
        if (!pos) return false;
       
        int digit = pos - BASE58_CHARS;
        int carry = digit;
       
        for (int j = 24; j >= 0; j--) {
            carry += 58 * result[j];
            result[j] = carry % 256;
            carry /= 256;
        }
       
        if (carry != 0) return false;
    }
   
    decoded = result;
    return true;
}