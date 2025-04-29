#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>
#include <string>
#include <memory>
#include "../include/aes_gcm.h"

// Helper function to get OpenSSL error message
std::string getOpenSSLErrorMessage()
{
    char errorBuffer[256];
    unsigned long error = ERR_get_error();
    if (error == 0)
    {
        return "Unknown error";
    }
    ERR_error_string_n(error, errorBuffer, sizeof(errorBuffer));
    return std::string(errorBuffer);
}

// Custom deleter for EVP_CIPHER_CTX
struct CipherContextDeleter
{
    void operator()(EVP_CIPHER_CTX *ctx) const
    {
        if (ctx)
        {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

AesGcm::AesGcm()
    : keySize_(256), tagSize_(16), ctx_(nullptr)
{
    initializeContext();
}

AesGcm::AesGcm(int keySize, int tagSize)
    : keySize_(keySize), tagSize_(tagSize), ctx_(nullptr)
{

    if (!isValidKeySize(keySize))
    {
        throw std::invalid_argument("Invalid key size: must be 128, 192, or 256 bits");
    }

    if (!isValidTagSize(tagSize))
    {
        throw std::invalid_argument("Invalid tag size: must be between 4 and 16 bytes");
    }

    initializeContext();
}

AesGcm::~AesGcm()
{
    cleanupContext();
}

void AesGcm::initializeContext()
{
    ctx_ = EVP_CIPHER_CTX_new();
    if (!ctx_)
    {
        throw std::runtime_error("Failed to create OpenSSL cipher context");
    }
}

void AesGcm::cleanupContext()
{
    if (ctx_)
    {
        EVP_CIPHER_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

Encryption::EncryptedData AesGcm::encrypt(
    const std::vector<uint8_t> &plaintext,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &associatedData)
{

    // Validate parameters
    if (!validateKey(key))
    {
        throw std::invalid_argument("Invalid key size for AES-GCM");
    }

    if (!validateNonce(nonce))
    {
        throw std::invalid_argument("Invalid nonce size for AES-GCM (recommended 12 bytes)");
    }

    // Prepare encrypted data structure
    Encryption::EncryptedData result;
    result.algorithm = "AES-GCM";
    result.version = "1.0";
    result.nonce = nonce;
    result.tag.resize(tagSize_);
    result.ciphertext.resize(plaintext.size());

    // Initialize encryption
    if (!EVP_EncryptInit_ex(ctx_, getCipher(), nullptr, nullptr, nullptr))
    {
        throw std::runtime_error("Failed to initialize AES-GCM encryption");
    }

    // Set IV length (nonce)
    if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr))
    {
        throw std::runtime_error("Failed to set nonce length");
    }

    // Initialize key and nonce
    if (!EVP_EncryptInit_ex(ctx_, nullptr, nullptr, key.data(), nonce.data()))
    {
        throw std::runtime_error("Failed to set key and nonce");
    }

    // Process associated data if any
    if (!associatedData.empty())
    {
        int outlen;
        if (!EVP_EncryptUpdate(ctx_, nullptr, &outlen, associatedData.data(), associatedData.size()))
        {
            throw std::runtime_error("Failed to process associated data");
        }
    }

    // Encrypt plaintext
    int outlen;
    if (!EVP_EncryptUpdate(ctx_, result.ciphertext.data(), &outlen, plaintext.data(), plaintext.size()))
    {
        throw std::runtime_error("Failed to encrypt data");
    }

    // Check if output size matches input size for AES-GCM
    if (outlen != static_cast<int>(plaintext.size()))
    {
        throw std::runtime_error("Encryption output size mismatch");
    }

    // Finalize encryption
    if (!EVP_EncryptFinal_ex(ctx_, result.ciphertext.data() + outlen, &outlen))
    {
        throw std::runtime_error("Failed to finalize encryption");
    }

    // Get authentication tag
    if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, tagSize_, result.tag.data()))
    {
        throw std::runtime_error("Failed to get authentication tag");
    }

    return result;
}

std::vector<uint8_t> AesGcm::decrypt(
    const Encryption::EncryptedData &encryptedData,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &associatedData)
{

    // Validate parameters
    if (!validateKey(key))
    {
        throw std::invalid_argument("Invalid key size for AES-GCM");
    }

    if (!validateNonce(nonce))
    {
        throw std::invalid_argument("Invalid nonce size for AES-GCM (recommended 12 bytes)");
    }

    if (encryptedData.tag.size() != static_cast<size_t>(tagSize_))
    {
        throw std::invalid_argument("Authentication tag size mismatch");
    }

    // Prepare output buffer
    std::vector<uint8_t> plaintext(encryptedData.ciphertext.size());

    // Initialize decryption
    if (!EVP_DecryptInit_ex(ctx_, getCipher(), nullptr, nullptr, nullptr))
    {
        throw std::runtime_error("Failed to initialize AES-GCM decryption");
    }

    // Set IV length (nonce)
    if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr))
    {
        throw std::runtime_error("Failed to set nonce length");
    }

    // Initialize key and nonce
    if (!EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key.data(), nonce.data()))
    {
        throw std::runtime_error("Failed to set key and nonce");
    }

    // Process associated data if any
    if (!associatedData.empty())
    {
        int outlen;
        if (!EVP_DecryptUpdate(ctx_, nullptr, &outlen, associatedData.data(), associatedData.size()))
        {
            throw std::runtime_error("Failed to process associated data");
        }
    }

    // Decrypt ciphertext
    int outlen;
    if (!EVP_DecryptUpdate(
            ctx_,
            plaintext.data(),
            &outlen,
            encryptedData.ciphertext.data(),
            encryptedData.ciphertext.size()))
    {
        throw std::runtime_error("Failed to decrypt data");
    }

    // Set expected tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, encryptedData.tag.size(),
                             const_cast<void *>(static_cast<const void *>(encryptedData.tag.data()))))
    {
        throw std::runtime_error("Failed to set authentication tag");
    }

    // Finalize decryption and verify tag
    int ret = EVP_DecryptFinal_ex(ctx_, plaintext.data() + outlen, &outlen);
    if (ret <= 0)
    {
        // Authentication failed
        throw std::runtime_error("Authentication failed: tag verification failed");
    }

    return plaintext;
}

std::vector<uint8_t> AesGcm::generateNonce(size_t size)
{
    std::vector<uint8_t> nonce(size);
    if (RAND_bytes(nonce.data(), size) != 1)
    {
        throw std::runtime_error("Failed to generate secure random nonce");
    }
    return nonce;
}

void AesGcm::setKeySize(int bits)
{
    if (!isValidKeySize(bits))
    {
        throw std::invalid_argument("Invalid key size: must be 128, 192, or 256 bits");
    }
    keySize_ = bits;
}

void AesGcm::setTagSize(int bytes)
{
    if (!isValidTagSize(bytes))
    {
        throw std::invalid_argument("Invalid tag size: must be between 4 and 16 bytes");
    }
    tagSize_ = bytes;
}

int AesGcm::getKeySize() const
{
    return keySize_;
}

int AesGcm::getTagSize() const
{
    return tagSize_;
}

const EVP_CIPHER *AesGcm::getCipher() const
{
    switch (keySize_)
    {
    case 128:
        return EVP_aes_128_gcm();
    case 192:
        return EVP_aes_192_gcm();
    case 256:
        return EVP_aes_256_gcm();
    default:
        return EVP_aes_256_gcm(); // Default to 256-bit
    }
}

bool AesGcm::isValidKeySize(int bits) const
{
    return bits == 128 || bits == 192 || bits == 256;
}

bool AesGcm::isValidTagSize(int bytes) const
{
    // Tag sizes between 4 and 16 bytes are supported
    return bytes >= 4 && bytes <= 16;
}

bool AesGcm::validateKey(const std::vector<uint8_t> &key) const
{
    return key.size() == (keySize_ / 8);
}

bool AesGcm::validateNonce(const std::vector<uint8_t> &nonce) const
{
    // GCM supports nonces of any size, but 12 bytes is recommended
    return !nonce.empty() && nonce.size() <= 16;
}

// AES-GCM encryption implementation
Encryption::EncryptedData Encryption::encryptAesGcm(
    const std::string &plaintext,
    const std::vector<uint8_t> &key)
{
    if (!validateKey(key, config_.keySize))
    {
        throw std::runtime_error("Invalid key size for AES-GCM encryption");
    }

    // Create result structure
    EncryptedData result;
    result.algorithm = "AES-256-GCM";
    result.version = "1.0";
    result.compressed = config_.compressionEnabled;

    // Generate random nonce/IV
    result.nonce.resize(config_.nonceSize);
    if (RAND_bytes(result.nonce.data(), result.nonce.size()) != 1)
    {
        throw std::runtime_error("Failed to generate random nonce: " + getOpenSSLErrorMessage());
    }

    // Compress data if enabled
    std::vector<uint8_t> dataToEncrypt;
    if (config_.compressionEnabled)
    {
        dataToEncrypt = compressData(std::vector<uint8_t>(plaintext.begin(), plaintext.end()));
    }
    else
    {
        dataToEncrypt.assign(plaintext.begin(), plaintext.end());
    }

    // Create and initialize the cipher context
    std::unique_ptr<EVP_CIPHER_CTX, CipherContextDeleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLErrorMessage());
    }

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        throw std::runtime_error("Failed to initialize encryption: " + getOpenSSLErrorMessage());
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, result.nonce.size(), nullptr) != 1)
    {
        throw std::runtime_error("Failed to set IV length: " + getOpenSSLErrorMessage());
    }

    // Initialize key and IV
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), result.nonce.data()) != 1)
    {
        throw std::runtime_error("Failed to set key and IV: " + getOpenSSLErrorMessage());
    }

    // Provide additional authenticated data (AAD) if any
    // For now, we're not using AAD, but this would be the place to add it

    // Determine output buffer size
    int blockSize = EVP_CIPHER_CTX_block_size(ctx.get());
    result.ciphertext.resize(dataToEncrypt.size() + blockSize);

    // Perform encryption
    int outLen = 0;
    if (EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &outLen,
                          dataToEncrypt.data(), dataToEncrypt.size()) != 1)
    {
        throw std::runtime_error("Encryption failed: " + getOpenSSLErrorMessage());
    }

    int ciphertextLen = outLen;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx.get(), result.ciphertext.data() + outLen, &outLen) != 1)
    {
        throw std::runtime_error("Finalization failed: " + getOpenSSLErrorMessage());
    }

    ciphertextLen += outLen;
    result.ciphertext.resize(ciphertextLen);

    // Get the authentication tag
    result.tag.resize(config_.tagSize);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, result.tag.size(), result.tag.data()) != 1)
    {
        throw std::runtime_error("Failed to get authentication tag: " + getOpenSSLErrorMessage());
    }

    // Log the operation
    logCryptoOperation("AES-GCM encryption", true);

    return result;
}

// AES-GCM decryption implementation
std::string Encryption::decryptAesGcm(
    const EncryptedData &data,
    const std::vector<uint8_t> &key)
{
    if (!validateKey(key, config_.keySize))
    {
        throw std::runtime_error("Invalid key size for AES-GCM decryption");
    }

    if (!validateEncryptedData(data))
    {
        throw std::runtime_error("Invalid encrypted data format");
    }

    // Create and initialize the cipher context
    std::unique_ptr<EVP_CIPHER_CTX, CipherContextDeleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLErrorMessage());
    }

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        throw std::runtime_error("Failed to initialize decryption: " + getOpenSSLErrorMessage());
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, data.nonce.size(), nullptr) != 1)
    {
        throw std::runtime_error("Failed to set IV length: " + getOpenSSLErrorMessage());
    }

    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), data.nonce.data()) != 1)
    {
        throw std::runtime_error("Failed to set key and IV: " + getOpenSSLErrorMessage());
    }

    // Provide additional authenticated data (AAD) if any
    // For now, we're not using AAD, but this would be the place to add it

    // Allocate memory for the plaintext
    std::vector<uint8_t> plaintext(data.ciphertext.size());

    // Perform decryption
    int outLen = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outLen,
                          data.ciphertext.data(), data.ciphertext.size()) != 1)
    {
        throw std::runtime_error("Decryption failed: " + getOpenSSLErrorMessage());
    }

    int plaintextLen = outLen;

    // Set expected tag value
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, data.tag.size(),
                            const_cast<uint8_t *>(data.tag.data())) != 1)
    {
        throw std::runtime_error("Failed to set authentication tag: " + getOpenSSLErrorMessage());
    }

    // Finalize decryption and verify the tag
    int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outLen, &outLen);

    // Check if authentication was successful
    if (ret <= 0)
    {
        throw std::runtime_error("Authentication failed - data has been tampered with");
    }

    plaintextLen += outLen;
    plaintext.resize(plaintextLen);

    // Decompress if needed
    if (data.compressed)
    {
        try
        {
            std::vector<uint8_t> decompressed = decompressData(plaintext);
            plaintext = decompressed;
        }
        catch (const std::exception &e)
        {
            throw std::runtime_error(std::string("Decompression failed: ") + e.what());
        }
    }

    // Log the operation
    logCryptoOperation("AES-GCM decryption", true);

    // Convert to string and return
    return std::string(plaintext.begin(), plaintext.end());
}

// Validate encrypted data structure
bool Encryption::validateEncryptedData(const EncryptedData &data)
{
    // Check algorithm
    if (data.algorithm != "AES-256-GCM")
    {
        return false;
    }

    // Check nonce size
    if (data.nonce.size() != config_.nonceSize)
    {
        return false;
    }

    // Check tag size
    if (data.tag.size() != config_.tagSize)
    {
        return false;
    }

    // Check ciphertext
    if (data.ciphertext.empty())
    {
        return false;
    }

    return true;
}

// Validate key
bool Encryption::validateKey(const std::vector<uint8_t> &key, int expectedSize)
{
    return key.size() == static_cast<size_t>(expectedSize);
}