#include "encryption.h"
#include "config.h"

#if Argon2_FOUND
#include <argon2.h>
#endif

#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <openssl/rand.h>
#include <sstream>
#include <chrono>
#include <thread>

namespace
{
    // Fallback PBKDF2 implementation using OpenSSL when Argon2 is not available
    std::vector<uint8_t> fallbackPBKDF2(
        const std::string &password,
        const std::string &salt,
        int iterations,
        int keyLength)
    {
        std::vector<uint8_t> key(keyLength);

        // Implementation using OpenSSL's PKCS5_PBKDF2_HMAC
        if (PKCS5_PBKDF2_HMAC(
                password.c_str(),
                password.length(),
                reinterpret_cast<const unsigned char *>(salt.c_str()),
                salt.length(),
                iterations,
                EVP_sha256(),
                keyLength,
                key.data()) != 1)
        {
            throw std::runtime_error("PBKDF2 key derivation failed");
        }

        return key;
    }
}

std::vector<uint8_t> Encryption::deriveKeyArgon2(const std::string &password, const KDFParams &params)
{
#if Argon2_FOUND
    // Create output key buffer
    std::vector<uint8_t> key(config_.keySize);

    // Convert salt to bytes
    const uint8_t *salt = reinterpret_cast<const uint8_t *>(params.salt.c_str());
    size_t saltlen = params.salt.length();

    // Determine Argon2 variant based on algorithm
    argon2_type type = argon2_type::Argon2_id;
    if (params.algorithm == "Argon2i")
    {
        type = argon2_type::Argon2_i;
    }
    else if (params.algorithm == "Argon2d")
    {
        type = argon2_type::Argon2_d;
    }

    // Run Argon2
    int result = argon2_hash(
        params.iterations,        // t_cost (time cost)
        params.memorySize / 1024, // m_cost (memory cost in kibibytes)
        params.parallelism,       // parallelism
        password.c_str(),         // password
        password.length(),        // password length
        salt,                     // salt
        saltlen,                  // salt length
        key.data(),               // output key
        key.size(),               // output key length
        nullptr,                  // encoded hash
        0,                        // encoded hash length
        type,                     // argon2 variant
        ARGON2_VERSION_13         // version
    );

    if (result != ARGON2_OK)
    {
        throw std::runtime_error(std::string("Argon2 key derivation failed: ") +
                                 argon2_error_message(result));
    }

    return key;
#else
    // Fallback to PBKDF2 if Argon2 is not available
    return fallbackPBKDF2(password, params.salt, params.iterations, config_.keySize);
#endif
}

// Implement the main deriveKey function that dispatches to appropriate implementation
std::vector<uint8_t> Encryption::deriveKey(const std::string &password, const KDFParams &params)
{
    if (params.algorithm == "Argon2id" ||
        params.algorithm == "Argon2i" ||
        params.algorithm == "Argon2d")
    {
        return deriveKeyArgon2(password, params);
    }
    else if (params.algorithm == "PBKDF2-HMAC-SHA256")
    {
        return deriveKeyPbkdf2(password, params);
    }
    else
    {
        throw std::runtime_error("Unsupported key derivation algorithm: " + params.algorithm);
    }
}

// Implementation of PBKDF2 key derivation
std::vector<uint8_t> Encryption::deriveKeyPbkdf2(const std::string &password, const KDFParams &params)
{
    return fallbackPBKDF2(password, params.salt, params.iterations, config_.keySize);
}

KdfArgon2::KdfArgon2()
    : variant_(Argon2Variant::ARGON2ID),
      iterations_(3),
      memory_(65536),
      parallelism_(4)
{
}

KdfArgon2::KdfArgon2(Argon2Variant variant, unsigned int iterations, unsigned int memory, unsigned int parallelism)
    : variant_(variant),
      iterations_(iterations),
      memory_(memory),
      parallelism_(parallelism)
{
    if (!validateParameters())
    {
        throw std::invalid_argument("Invalid Argon2 parameters");
    }
}

KdfArgon2::~KdfArgon2()
{
    // Nothing to clean up
}

std::vector<uint8_t> KdfArgon2::deriveKey(
    const std::string &password,
    const std::vector<uint8_t> &salt,
    size_t keyLength)
{

    if (password.empty())
    {
        throw std::invalid_argument("Password cannot be empty");
    }

    if (salt.empty() || salt.size() < 8)
    {
        throw std::invalid_argument("Salt must be at least 8 bytes long");
    }

    if (keyLength == 0 || keyLength > 1024)
    {
        throw std::invalid_argument("Key length must be between 1 and 1024 bytes");
    }

    return deriveKeyInternal(password, salt, keyLength);
}

std::vector<uint8_t> KdfArgon2::deriveKeyInternal(
    const std::string &password,
    const std::vector<uint8_t> &salt,
    size_t keyLength)
{

#ifdef Argon2_FOUND
    // Prepare output buffer
    std::vector<uint8_t> derivedKey(keyLength);

    // Determine Argon2 variant to use
    argon2_type type;
    switch (variant_)
    {
    case Argon2Variant::ARGON2D:
        type = Argon2_d;
        break;
    case Argon2Variant::ARGON2I:
        type = Argon2_i;
        break;
    case Argon2Variant::ARGON2ID:
        type = Argon2_id;
        break;
    default:
        throw std::runtime_error("Unknown Argon2 variant");
    }

    // Perform key derivation
    int result = argon2_hash(
        iterations_,       // iterations
        memory_,           // memory in KiB
        parallelism_,      // parallelism
        password.c_str(),  // password
        password.length(), // password length
        salt.data(),       // salt
        salt.size(),       // salt length
        derivedKey.data(), // output key
        keyLength,         // key length
        nullptr,           // encoded output (not used)
        0,                 // encoded output length
        type,              // algorithm type
        ARGON2_VERSION_13  // version
    );

    if (result != ARGON2_OK)
    {
        throw std::runtime_error("Argon2 key derivation failed: " + std::string(argon2_error_message(result)));
    }

    return derivedKey;
#else
    // Fallback to PBKDF2 using OpenSSL if Argon2 is not available
    // This is a simplified version - in a real application, you'd implement proper PBKDF2
    throw std::runtime_error("Argon2 is not available, please build with Argon2 support");
#endif
}

std::vector<uint8_t> KdfArgon2::generateSalt(size_t length)
{
    if (length < 8)
    {
        throw std::invalid_argument("Salt length must be at least 8 bytes");
    }

    std::vector<uint8_t> salt(length);
    if (RAND_bytes(salt.data(), length) != 1)
    {
        throw std::runtime_error("Failed to generate random salt");
    }

    return salt;
}

Encryption::KDFParams KdfArgon2::calculateParams(int targetTime)
{
    // Default parameters
    Encryption::KDFParams params;
    params.algorithm = "Argon2id";
    params.iterations = 3;
    params.memorySize = 65536; // 64 MB
    params.parallelism = 4;

    // If we have Argon2 available, try to calibrate parameters
#ifdef Argon2_FOUND
    // Start with minimal values
    unsigned int t_cost = 1;
    unsigned int m_cost = 16384; // 16 MB
    unsigned int parallelism = 4;

    // Generate test data
    std::string testPassword = "test_password";
    std::vector<uint8_t> testSalt = generateSalt(16);

    // Calibrate memory cost
    auto adjustParams = [&](unsigned int &param, const std::string &name, int step, int max)
    {
        while (true)
        {
            KdfArgon2 kdf(Argon2Variant::ARGON2ID, t_cost, m_cost, parallelism);

            auto start = std::chrono::high_resolution_clock::now();
            kdf.deriveKey(testPassword, testSalt, 32);
            auto end = std::chrono::high_resolution_clock::now();

            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            if (duration > targetTime || param >= max)
            {
                break;
            }

            param += step;
        }
    };

    // Adjust m_cost first (memory has biggest impact on security)
    adjustParams(m_cost, "memory", 8192, 1048576); // Increase by 8MB steps, max 1GB

    // Then adjust t_cost (iterations)
    adjustParams(t_cost, "iterations", 1, 10);

    // Update the parameters
    params.iterations = t_cost;
    params.memorySize = m_cost;
    params.parallelism = parallelism;
#endif

    return params;
}

void KdfArgon2::setVariant(Argon2Variant variant)
{
    variant_ = variant;
}

void KdfArgon2::setIterations(unsigned int iterations)
{
    iterations_ = iterations;
    if (!validateParameters())
    {
        throw std::invalid_argument("Invalid iterations value");
    }
}

void KdfArgon2::setMemory(unsigned int memory)
{
    memory_ = memory;
    if (!validateParameters())
    {
        throw std::invalid_argument("Invalid memory value");
    }
}

void KdfArgon2::setParallelism(unsigned int parallelism)
{
    parallelism_ = parallelism;
    if (!validateParameters())
    {
        throw std::invalid_argument("Invalid parallelism value");
    }
}

Argon2Variant KdfArgon2::getVariant() const
{
    return variant_;
}

unsigned int KdfArgon2::getIterations() const
{
    return iterations_;
}

unsigned int KdfArgon2::getMemory() const
{
    return memory_;
}

unsigned int KdfArgon2::getParallelism() const
{
    return parallelism_;
}

Encryption::KDFParams KdfArgon2::getKDFParams(const std::vector<uint8_t> &salt) const
{
    Encryption::KDFParams params;

    // Convert salt to hex string
    std::stringstream ss;
    for (auto byte : salt)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    params.salt = ss.str();
    params.iterations = iterations_;
    params.memorySize = memory_;
    params.parallelism = parallelism_;
    params.algorithm = variantToString(variant_);

    return params;
}

bool KdfArgon2::setFromKDFParams(const Encryption::KDFParams &params)
{
    // Parse algorithm
    if (params.algorithm == "Argon2d")
    {
        variant_ = Argon2Variant::ARGON2D;
    }
    else if (params.algorithm == "Argon2i")
    {
        variant_ = Argon2Variant::ARGON2I;
    }
    else if (params.algorithm == "Argon2id")
    {
        variant_ = Argon2Variant::ARGON2ID;
    }
    else
    {
        return false;
    }

    // Set parameters
    iterations_ = params.iterations;
    memory_ = params.memorySize;
    parallelism_ = params.parallelism;

    return validateParameters();
}

bool KdfArgon2::validateParameters() const
{
    // Check iterations (time cost)
    if (iterations_ < 1 || iterations_ > 1000)
    {
        return false;
    }

    // Check memory cost
    if (memory_ < 8 || memory_ > 4194304)
    { // 8 KB to 4 GB
        return false;
    }

    // Check parallelism
    if (parallelism_ < 1 || parallelism_ > 64)
    {
        return false;
    }

    return true;
}

int KdfArgon2::variantToInt() const
{
    switch (variant_)
    {
    case Argon2Variant::ARGON2D:
        return 0;
    case Argon2Variant::ARGON2I:
        return 1;
    case Argon2Variant::ARGON2ID:
        return 2;
    default:
        return 2; // Default to Argon2id
    }
}

Argon2Variant KdfArgon2::intToVariant(int variantInt)
{
    switch (variantInt)
    {
    case 0:
        return Argon2Variant::ARGON2D;
    case 1:
        return Argon2Variant::ARGON2I;
    case 2:
        return Argon2Variant::ARGON2ID;
    default:
        return Argon2Variant::ARGON2ID; // Default to Argon2id
    }
}

std::string KdfArgon2::variantToString(Argon2Variant variant)
{
    switch (variant)
    {
    case Argon2Variant::ARGON2D:
        return "Argon2d";
    case Argon2Variant::ARGON2I:
        return "Argon2i";
    case Argon2Variant::ARGON2ID:
        return "Argon2id";
    default:
        return "Argon2id"; // Default to Argon2id
    }
}