#include "encryption.h"
#include "config.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdexcept>
#include <vector>
#include <cstring>
#include <algorithm>
#include <random>
#include <chrono>

// Constructor
Encryption::Encryption()
    : rng_(std::random_device{}())
{

    // Set default configuration
    config_ = EncryptionConfig{};

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Initialize implementations
    initImplementation();

    // Register supported algorithms
    registerAlgorithms();

    // Register supported KDFs
    registerKDFs();
}

// Constructor with configuration
Encryption::Encryption(const EncryptionConfig &config)
    : config_(config), rng_(std::random_device{}())
{

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Initialize implementations
    initImplementation();

    // Register supported algorithms
    registerAlgorithms();

    // Register supported KDFs
    registerKDFs();
}

// Destructor
Encryption::~Encryption()
{
    // Clean up key store securely
    for (auto &pair : keyStore_)
    {
        std::vector<uint8_t> &key = pair.second;
        secureWipeMemory(key.data(), key.size());
        key.clear();
    }
    keyStore_.clear();

    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();
}

// Initialize with configuration
bool Encryption::initialize(const EncryptionConfig &config)
{
    config_ = config;
    return true;
}

// Initialize with a key
bool Encryption::initialize(const std::string &key)
{
    if (key.size() != static_cast<size_t>(config_.keySize))
    {
        return false;
    }

    // Store master key
    std::vector<uint8_t> masterKey(key.begin(), key.end());
    keyStore_["master"] = masterKey;

    // Create key info
    KeyInfo info;
    info.type = KeyType::MASTER_KEY;
    info.id = "master";
    info.creationTime = std::chrono::system_clock::now();
    info.isActive = true;
    keyInfo_["master"] = info;

    return true;
}

// Initialize implementation
void Encryption::initImplementation()
{
    // No implementation details to initialize
}

// Register supported algorithms
void Encryption::registerAlgorithms()
{
    // Register AES-GCM
    encryptors_["AES-256-GCM"] = [this](const std::string &plaintext, const std::vector<uint8_t> &key)
    {
        return encryptAesGcm(plaintext, key);
    };

    decryptors_["AES-256-GCM"] = [this](const EncryptedData &data, const std::vector<uint8_t> &key)
    {
        return decryptAesGcm(data, key);
    };

    // Register other algorithms here
}

// Register supported KDFs
void Encryption::registerKDFs()
{
    // Register PBKDF2
    kdfs_["PBKDF2-HMAC-SHA256"] = [this](const std::string &password, const KDFParams &params)
    {
        return deriveKeyPbkdf2(password, params);
    };

    // Register Argon2
    kdfs_["Argon2id"] = [this](const std::string &password, const KDFParams &params)
    {
        return deriveKeyArgon2(password, params);
    };

    // Other KDFs would be registered here
}

// Generate random bytes
std::vector<uint8_t> Encryption::generateRandomBytes(int length)
{
    std::vector<uint8_t> buffer(length);

    // Try OpenSSL's RAND_bytes first
    if (RAND_bytes(buffer.data(), length) == 1)
    {
        return buffer;
    }

    // Fallback to C++ random
    std::uniform_int_distribution<> dist(0, 255);
    for (int i = 0; i < length; i++)
    {
        buffer[i] = static_cast<uint8_t>(dist(rng_));
    }

    return buffer;
}

// Generate a random key
std::string Encryption::generateRandomKey(size_t length)
{
    std::vector<uint8_t> buffer = generateRandomBytes(length);
    return std::string(reinterpret_cast<char *>(buffer.data()), buffer.size());
}

// Generate a random salt for key derivation
std::string Encryption::generateSalt(int length)
{
    return generateRandomKey(length);
}

// Generate a random IV
std::string Encryption::generateIV(size_t length)
{
    return generateRandomKey(length);
}

// Base64 encode a string
std::string Encryption::base64Encode(const std::string &data)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());

    // Don't use newlines
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bmem);

    BIO_write(b64, data.c_str(), data.length());
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string result(bptr->data, bptr->length);

    BIO_free_all(b64);

    return result;
}

// Base64 decode a string
std::string Encryption::base64Decode(const std::string &data)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(data.c_str(), data.length());

    // Don't use newlines
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_push(b64, bmem);

    std::vector<unsigned char> buffer(data.length());
    int decodedLength = BIO_read(bmem, buffer.data(), data.length());

    BIO_free_all(bmem);

    if (decodedLength <= 0)
    {
        throw std::runtime_error("Base64 decoding failed");
    }

    return std::string(reinterpret_cast<char *>(buffer.data()), decodedLength);
}

// Encrypt data using selected algorithm
Encryption::EncryptedData Encryption::encrypt(
    const std::string &plaintext,
    const std::vector<uint8_t> &key)
{
    // Get appropriate encryptor function
    auto it = encryptors_.find(config_.algorithm);
    if (it == encryptors_.end())
    {
        throw std::runtime_error("Unsupported encryption algorithm: " + config_.algorithm);
    }

    // Call the encryptor
    return it->second(plaintext, key);
}

// Decrypt data using algorithm specified in the data
std::string Encryption::decrypt(
    const EncryptedData &data,
    const std::vector<uint8_t> &key)
{
    // Get appropriate decryptor function
    auto it = decryptors_.find(data.algorithm);
    if (it == decryptors_.end())
    {
        throw std::runtime_error("Unsupported encryption algorithm: " + data.algorithm);
    }

    // Call the decryptor
    return it->second(data, key);
}

// Encrypt with password - simplified interface
Encryption::EncryptedData Encryption::encryptWithPassword(
    const std::string &plaintext,
    const std::string &password)
{
    // Generate salt
    std::string salt = generateSalt(16);

    // Set up KDF parameters
    KDFParams kdfParams;
    kdfParams.salt = salt;
    kdfParams.iterations = config_.iterations;
    kdfParams.memorySize = config_.memorySize;
    kdfParams.parallelism = config_.parallelism;
    kdfParams.algorithm = config_.keyDerivationFunction;

    // Derive key
    std::vector<uint8_t> key = deriveKey(password, kdfParams);

    // Encrypt the data
    EncryptedData encryptedData = encrypt(plaintext, key);

    // Add KDF parameters
    encryptedData.kdfParams = kdfParams;

    // Securely wipe the key
    secureWipeMemory(key.data(), key.size());

    return encryptedData;
}

// Decrypt with password - simplified interface
std::string Encryption::decryptWithPassword(
    const EncryptedData &data,
    const std::string &password)
{
    // Derive key using the KDF parameters from the data
    std::vector<uint8_t> key = deriveKey(password, data.kdfParams);

    // Decrypt the data
    std::string plaintext = decrypt(data, key);

    // Securely wipe the key
    secureWipeMemory(key.data(), key.size());

    return plaintext;
}

// Get current configuration
EncryptionConfig Encryption::getConfig() const
{
    return config_;
}

// Update configuration
bool Encryption::updateConfig(const EncryptionConfig &config)
{
    config_ = config;
    return true;
}

// Get supported algorithms
std::vector<std::string> Encryption::getSupportedAlgorithms()
{
    std::vector<std::string> algorithms;
    for (const auto &pair : encryptors_)
    {
        algorithms.push_back(pair.first);
    }
    return algorithms;
}

// Get supported KDFs
std::vector<std::string> Encryption::getSupportedKDFs()
{
    std::vector<std::string> kdfs;
    for (const auto &pair : kdfs_)
    {
        kdfs.push_back(pair.first);
    }
    return kdfs;
}

// Check if hardware acceleration is available
bool Encryption::isHardwareAccelerationAvailable()
{
    // Check for AES-NI support
#if defined(__AES__)
    return true;
#else
    return false;
#endif
}

// Serialize encrypted data to a format that can be stored
std::string Encryption::serializeEncryptedData(const EncryptedData &data)
{
    // Implement serialization here
    // This is a placeholder for a proper implementation

    // For now, we'll just convert the binary data to Base64
    std::string result;

    // Add algorithm and version
    result += data.algorithm + "|";
    result += data.version + "|";

    // Add compression flag
    result += (data.compressed ? "1" : "0") + std::string("|");

    // Add KDF info
    result += data.kdfParams.algorithm + "|";
    result += std::to_string(data.kdfParams.iterations) + "|";
    result += std::to_string(data.kdfParams.memorySize) + "|";
    result += std::to_string(data.kdfParams.parallelism) + "|";

    // Add salt
    result += base64Encode(data.kdfParams.salt) + "|";

    // Add nonce
    std::string nonceStr(reinterpret_cast<const char *>(data.nonce.data()), data.nonce.size());
    result += base64Encode(nonceStr) + "|";

    // Add tag
    std::string tagStr(reinterpret_cast<const char *>(data.tag.data()), data.tag.size());
    result += base64Encode(tagStr) + "|";

    // Add ciphertext
    std::string ciphertextStr(reinterpret_cast<const char *>(data.ciphertext.data()), data.ciphertext.size());
    result += base64Encode(ciphertextStr);

    return result;
}

// Deserialize encrypted data from a stored format
Encryption::EncryptedData Encryption::deserializeEncryptedData(const std::string &serialized)
{
    // Implement deserialization here
    // This is a placeholder for a proper implementation

    EncryptedData result;

    // Split by separator
    std::vector<std::string> parts;
    size_t start = 0;
    size_t end = serialized.find("|");
    while (end != std::string::npos)
    {
        parts.push_back(serialized.substr(start, end - start));
        start = end + 1;
        end = serialized.find("|", start);
    }
    parts.push_back(serialized.substr(start));

    if (parts.size() != 9)
    {
        throw std::runtime_error("Invalid serialized data format");
    }

    // Extract components
    result.algorithm = parts[0];
    result.version = parts[1];
    result.compressed = (parts[2] == "1");

    // KDF parameters
    result.kdfParams.algorithm = parts[3];
    result.kdfParams.iterations = std::stoi(parts[4]);
    result.kdfParams.memorySize = std::stoi(parts[5]);
    result.kdfParams.parallelism = std::stoi(parts[6]);

    // Salt
    result.kdfParams.salt = base64Decode(parts[7]);

    // Nonce
    std::string nonceStr = base64Decode(parts[8]);
    result.nonce.assign(nonceStr.begin(), nonceStr.end());

    // Tag
    std::string tagStr = base64Decode(parts[9]);
    result.tag.assign(tagStr.begin(), tagStr.end());

    // Ciphertext
    std::string ciphertextStr = base64Decode(parts[10]);
    result.ciphertext.assign(ciphertextStr.begin(), ciphertextStr.end());

    return result;
}

// Generate a secure password
std::string Encryption::generatePassword(
    int length,
    bool includeUppercase,
    bool includeLowercase,
    bool includeNumbers,
    bool includeSpecial,
    bool excludeSimilar)
{
    if (length <= 0)
    {
        return "";
    }

    // Define character sets
    std::string uppercaseChars = "ABCDEFGHJKLMNPQRSTUVWXY";
    std::string lowercaseChars = "abcdefghijkmnpqrstuvwxyz";
    std::string numberChars = "23456789";
    std::string specialChars = "!@#$%^&*()-_=+[]{};:,.<>?";

    // If not excluding similar characters, add them back
    if (!excludeSimilar)
    {
        uppercaseChars += "IOZ";
        lowercaseChars += "lo";
        numberChars += "01";
    }

    // Create combined character set
    std::string charset;
    if (includeUppercase)
        charset += uppercaseChars;
    if (includeLowercase)
        charset += lowercaseChars;
    if (includeNumbers)
        charset += numberChars;
    if (includeSpecial)
        charset += specialChars;

    // If no character set was selected, use lowercase as default
    if (charset.empty())
    {
        charset = lowercaseChars;
    }

    // Generate password
    std::string password;
    std::vector<uint8_t> randomBytes = generateRandomBytes(length);

    for (int i = 0; i < length; i++)
    {
        password += charset[randomBytes[i] % charset.size()];
    }

    // Ensure at least one character from each selected character set
    if (length >= 4)
    {
        if (includeUppercase && password.find_first_of(uppercaseChars) == std::string::npos)
        {
            password[0] = uppercaseChars[randomBytes[0] % uppercaseChars.size()];
        }

        if (includeLowercase && password.find_first_of(lowercaseChars) == std::string::npos)
        {
            password[1] = lowercaseChars[randomBytes[1] % lowercaseChars.size()];
        }

        if (includeNumbers && password.find_first_of(numberChars) == std::string::npos)
        {
            password[2] = numberChars[randomBytes[2] % numberChars.size()];
        }

        if (includeSpecial && password.find_first_of(specialChars) == std::string::npos)
        {
            password[3] = specialChars[randomBytes[3] % specialChars.size()];
        }
    }

    return password;
}

// Log crypto operation for diagnostics
void Encryption::logCryptoOperation(const std::string &operation, bool success)
{
    // This is a placeholder for actual logging implementation
    // In a real application, this would log to a file or send to a logging service

    // For now, we'll just do nothing
    (void)operation;
    (void)success;
}

// Reset the internal state
void Encryption::resetState()
{
    // Clean up key store securely
    for (auto &pair : keyStore_)
    {
        std::vector<uint8_t> &key = pair.second;
        secureWipeMemory(key.data(), key.size());
        key.clear();
    }
    keyStore_.clear();

    // Reset key info
    keyInfo_.clear();

    // Any other state that needs resetting
    // (Depending on implementation details, add more reset operations as needed)
}

// Template specialization for string secure wipe
void Encryption::secureWipe(std::string &data)
{
    if (data.empty())
    {
        return;
    }

    // Overwrite the string data
    secureWipeMemory(&data[0], data.size());

    // Resize the string to zero and swap with an empty string to ensure deallocation
    data.resize(0);
    std::string().swap(data);
}