#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <openssl/evp.h>
#include "encryption.h"

/**
 * Class implementing AES-GCM encryption
 * Provides authenticated encryption with associated data (AEAD)
 */
class AesGcm
{
public:
    /**
     * Initialize AES-GCM with default parameters
     */
    AesGcm();

    /**
     * Initialize AES-GCM with specific key and tag size
     * @param keySize Key size in bits (128, 192, or 256)
     * @param tagSize Authentication tag size in bytes (default 16)
     */
    AesGcm(int keySize, int tagSize = 16);

    /**
     * Destructor - cleans up any OpenSSL resources
     */
    ~AesGcm();

    /**
     * Encrypt data using AES-GCM
     * @param plaintext Data to encrypt
     * @param key Encryption key
     * @param nonce Initialization vector/nonce (must be unique per encryption with same key)
     * @param associatedData Additional authenticated data (optional)
     * @return Encrypted data structure with ciphertext and authentication tag
     * @throws std::runtime_error if encryption fails
     */
    Encryption::EncryptedData encrypt(
        const std::vector<uint8_t> &plaintext,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &associatedData = std::vector<uint8_t>());

    /**
     * Decrypt data using AES-GCM
     * @param encryptedData Data to decrypt, including tag
     * @param key Decryption key
     * @param nonce Initialization vector/nonce used for encryption
     * @param associatedData Additional authenticated data (must match what was used for encryption)
     * @return Decrypted data
     * @throws std::runtime_error if decryption or authentication fails
     */
    std::vector<uint8_t> decrypt(
        const Encryption::EncryptedData &encryptedData,
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &associatedData = std::vector<uint8_t>());

    /**
     * Generate a secure random nonce for AES-GCM
     * @param size Size of nonce in bytes (12 bytes recommended)
     * @return Random nonce
     */
    static std::vector<uint8_t> generateNonce(size_t size = 12);

    /**
     * Set the key size
     * @param bits Key size in bits (128, 192, or 256)
     * @throws std::invalid_argument if key size is invalid
     */
    void setKeySize(int bits);

    /**
     * Set the authentication tag size
     * @param bytes Tag size in bytes (recommended at least 12, default 16)
     * @throws std::invalid_argument if tag size is invalid
     */
    void setTagSize(int bytes);

    /**
     * Get the current key size
     * @return Key size in bits
     */
    int getKeySize() const;

    /**
     * Get the current tag size
     * @return Tag size in bytes
     */
    int getTagSize() const;

private:
    // Key and tag sizes
    int keySize_; // In bits (128, 192, or 256)
    int tagSize_; // In bytes

    // OpenSSL cipher context
    EVP_CIPHER_CTX *ctx_;

    // Helper methods
    const EVP_CIPHER *getCipher() const;
    void initializeContext();
    void cleanupContext();

    // Validate parameters
    bool isValidKeySize(int bits) const;
    bool isValidTagSize(int bytes) const;
    bool validateKey(const std::vector<uint8_t> &key) const;
    bool validateNonce(const std::vector<uint8_t> &nonce) const;
};