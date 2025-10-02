#pragma once
#ifndef ADDRESS_GENERATOR_H
#define ADDRESS_GENERATOR_H

#include <cstdint>
#include <vector>
#include <string>
#include <cuda_runtime.h>

class AddressGenerator {
public:
    // Existing
    static std::string private_key_to_wif(const uint8_t* private_key, bool compressed = true, bool testnet = false);
    static std::string public_key_to_p2pkh(const uint8_t* public_key, size_t pubkey_len, bool testnet = false);
    static std::string public_key_to_p2sh(const uint8_t* public_key, bool testnet = false);
   
    static bool validate_bitcoin_address(const std::string& address);
   
    static bool base58_decode(const std::string& address, std::vector<uint8_t>& decoded_data);
   
    static bool validate_binary_address(const uint8_t* binary_address);
   
    static void run_comprehensive_test();
    static std::string base58_encode(const std::vector<uint8_t>& data);
   
    static std::string bytes_to_hex(const uint8_t* data, size_t len);

    // New: Bech32 (P2WPKH) and Taproot (P2TR)
    static std::string public_key_to_bech32(const uint8_t* public_key, size_t pubkey_len, bool testnet = false);
    static std::string public_key_to_taproot(const uint8_t* public_key, size_t pubkey_len, bool testnet = false);

    // Helper for Bech32
    static std::string bech32_encode(const std::vector<uint8_t>& data, const std::string& prefix, int witness_version = 0);
    static bool bech32_decode(const std::string& address, std::vector<uint8_t>& decoded_data, std::string& prefix, int& witness_version);
};

#endif // ADDRESS_GENERATOR_H