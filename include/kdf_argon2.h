#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include "encryption.h"

/**
 * Argon2 variant options
 */
enum class Argon2Variant
{
    ARGON2D, // Optimized to resist GPU attacks, but vulnerable to side-channels
    ARGON2I, // Optimized to resist side-channel attacks
    ARGON2ID // Hybrid approach (recommended)
};

/**
 * Class implementing Argon2 key derivation function
 * Argon2 is a modern password hashing and key derivation function
 * designed to be resistant to both GPU and side-channel attacks
 */
class KdfArgon2
{
public:
    /**
     * Initialize with default parameters
     */
    KdfArgon2();

    /**
     * Initialize with specific parameters
     * @param variant Argon2 variant to use
     * @param iterations Number of iterations
     * @param memory Memory cost in KiB
     * @param parallelism Degree of parallelism
     */
    KdfArgon2(Argon2Variant variant,
              unsigned int iterations = 3,
              unsigned int memory = 65536,
              unsigned int parallelism = 4);

    /**
     * Destructor
     */
    ~KdfArgon2();

    /**
     * Derive a key from a password using Argon2
     * @param password Password to derive key from
     * @param salt Salt for key derivation
     * @param keyLength Desired key length in bytes
     * @return Derived key
     * @throws std::runtime_error if key derivation fails
     */
    std::vector<uint8_t> deriveKey(
        const std::string &password,
        const std::vector<uint8_t> &salt,
        size_t keyLength = 32);

    /**
     * Generate a random salt suitable for Argon2
     * @param length Length of salt in bytes (recommended at least 16)
     * @return Random salt
     */
    static std::vector<uint8_t> generateSalt(size_t length = 16);

    /**
     * Calculate appropriate parameters based on system capabilities
     * @param targetTime Target execution time in milliseconds
     * @return KDF parameters (iterations, memory, parallelism)
     */
    static Encryption::KDFParams calculateParams(int targetTime = 500);

    /**
     * Set Argon2 variant
     * @param variant Variant to use
     */
    void setVariant(Argon2Variant variant);

    /**
     * Set number of iterations
     * @param iterations Number of iterations
     */
    void setIterations(unsigned int iterations);

    /**
     * Set memory cost
     * @param memory Memory cost in KiB
     */
    void setMemory(unsigned int memory);

    /**
     * Set parallelism degree
     * @param parallelism Degree of parallelism
     */
    void setParallelism(unsigned int parallelism);

    /**
     * Get current Argon2 variant
     * @return Current variant
     */
    Argon2Variant getVariant() const;

    /**
     * Get current iterations
     * @return Number of iterations
     */
    unsigned int getIterations() const;

    /**
     * Get current memory cost
     * @return Memory cost in KiB
     */
    unsigned int getMemory() const;

    /**
     * Get current parallelism degree
     * @return Degree of parallelism
     */
    unsigned int getParallelism() const;

    /**
     * Convert Argon2 parameters to KDF parameters structure
     * @param salt Salt to use
     * @return KDF parameters
     */
    Encryption::KDFParams getKDFParams(const std::vector<uint8_t> &salt) const;

    /**
     * Parse KDF parameters to set Argon2 options
     * @param params KDF parameters
     * @return True if parameters were valid and set successfully
     */
    bool setFromKDFParams(const Encryption::KDFParams &params);

private:
    // Argon2 parameters
    Argon2Variant variant_;
    unsigned int iterations_;
    unsigned int memory_;
    unsigned int parallelism_;

    // Internal implementation helpers
    std::vector<uint8_t> deriveKeyInternal(
        const std::string &password,
        const std::vector<uint8_t> &salt,
        size_t keyLength);

    // Validation helpers
    bool validateParameters() const;

    // Variant conversion helpers
    int variantToInt() const;
    static Argon2Variant intToVariant(int variantInt);
    static std::string variantToString(Argon2Variant variant);
};