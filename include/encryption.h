#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <random>
#include <functional>
#include <chrono>
#include <stdexcept>

/**
 * Encryption configuration settings
 */
struct EncryptionConfig
{
    std::string algorithm = "AES-256-GCM";          // Default encryption algorithm
    std::string keyDerivationFunction = "Argon2id"; // KDF algorithm
    int keySize = 32;                               // Key size in bytes
    int tagSize = 16;                               // Authentication tag size in bytes
    int nonceSize = 12;                             // Nonce size in bytes
    int iterations = 10000;                         // Iterations for KDF
    int memorySize = 65536;                         // Memory size for Argon2 (in KB)
    int parallelism = 4;                            // Parallelism factor for Argon2
    bool compressionEnabled = false;                // Whether to compress before encryption
    std::string compressionAlgorithm = "zlib";      // Compression algorithm
    bool useHardwareAcceleration = true;            // Use hardware acceleration if available
    bool zerizeMemoryAfterUse = true;               // Zero memory after cryptographic operations
    int autoKeyRotationDays = 90;                   // Days before automatic key rotation
};

/**
 * Class that provides encryption and decryption functionality
 * Supports multiple encryption algorithms and key derivation functions
 */
class Encryption
{
public:
    /**
     * Key derivation parameters
     */
    struct KDFParams
    {
        std::string salt;                   // Salt for key derivation
        int iterations = 10000;             // Number of iterations
        int memorySize = 65536;             // Memory size (Argon2)
        int parallelism = 4;                // Parallelism factor (Argon2)
        std::string algorithm = "Argon2id"; // KDF algorithm
    };

    /**
     * Encrypted data structure
     */
    struct EncryptedData
    {
        std::vector<uint8_t> ciphertext; // The encrypted data
        std::vector<uint8_t> nonce;      // Nonce/IV used for encryption
        std::vector<uint8_t> tag;        // Authentication tag
        std::string algorithm;           // Algorithm used for encryption
        std::string version;             // Format version
        bool compressed = false;         // Whether data was compressed before encryption
        KDFParams kdfParams;             // Key derivation parameters
    };

    /**
     * Key type enumeration
     */
    enum class KeyType
    {
        MASTER_KEY,             // Master encryption key
        DATA_KEY,               // Key for data encryption
        FILE_KEY,               // Key for file encryption
        SESSION_KEY,            // Temporary session key
        PASSWORD_PROTECTION_KEY // Key for protecting stored passwords
    };

    /**
     * Cryptographic hash algorithm
     */
    enum class HashAlgorithm
    {
        SHA256,
        SHA384,
        SHA512,
        SHA3_256,
        SHA3_512,
        BLAKE2B
    };

    /**
     * Signature verification result
     */
    struct VerificationResult
    {
        bool valid;                                      // Signature is valid
        std::string error;                               // Error message if invalid
        std::chrono::system_clock::time_point timestamp; // Verification time
    };

    /**
     * Key information
     */
    struct KeyInfo
    {
        KeyType type;                                         // Type of key
        std::string id;                                       // Unique key identifier
        std::chrono::system_clock::time_point creationTime;   // When key was created
        std::chrono::system_clock::time_point expirationTime; // When key expires
        int rotationCount;                                    // How many times rotated
        bool isActive;                                        // Whether key is active
    };

    /**
     * Default constructor
     */
    Encryption();

    /**
     * Constructor with configuration
     * @param config Encryption configuration
     */
    explicit Encryption(const EncryptionConfig &config);

    /**
     * Destructor
     */
    ~Encryption();

    /**
     * Initialize the encryption system with the given configuration
     * @param config Encryption configuration
     * @return True if initialization succeeded
     */
    bool initialize(const EncryptionConfig &config);

    /**
     * Derive a key from a password
     * @param password Password to derive key from
     * @param params Key derivation parameters
     * @return Derived key as bytes
     */
    std::vector<uint8_t> deriveKey(const std::string &password, const KDFParams &params);

    /**
     * Generate a random salt for key derivation
     * @param length Length of salt in bytes
     * @return Random salt
     */
    std::string generateSalt(int length = 32);

    /**
     * Generate random bytes
     * @param length Number of bytes to generate
     * @return Random bytes
     */
    std::vector<uint8_t> generateRandomBytes(int length);

    /**
     * Generate a secure random password
     * @param length Length of password
     * @param includeUppercase Include uppercase letters
     * @param includeLowercase Include lowercase letters
     * @param includeNumbers Include numbers
     * @param includeSpecial Include special characters
     * @param excludeSimilar Exclude similar characters (0, O, 1, l, etc.)
     * @return Randomly generated password
     */
    std::string generatePassword(
        int length = 16,
        bool includeUppercase = true,
        bool includeLowercase = true,
        bool includeNumbers = true,
        bool includeSpecial = true,
        bool excludeSimilar = false);

    /**
     * Encrypt data using the current algorithm and key
     * @param plaintext Data to encrypt
     * @param key Encryption key
     * @return Encrypted data structure
     */
    EncryptedData encrypt(const std::string &plaintext, const std::vector<uint8_t> &key);

    /**
     * Decrypt data
     * @param data Encrypted data structure
     * @param key Decryption key
     * @return Decrypted data as string
     * @throws std::runtime_error if decryption fails
     */
    std::string decrypt(const EncryptedData &data, const std::vector<uint8_t> &key);

    /**
     * Encrypt a file
     * @param inputPath Path to input file
     * @param outputPath Path to output encrypted file
     * @param key Encryption key
     * @return True if encryption succeeded
     */
    bool encryptFile(
        const std::string &inputPath,
        const std::string &outputPath,
        const std::vector<uint8_t> &key);

    /**
     * Decrypt a file
     * @param inputPath Path to encrypted file
     * @param outputPath Path to output decrypted file
     * @param key Decryption key
     * @return True if decryption succeeded
     */
    bool decryptFile(
        const std::string &inputPath,
        const std::string &outputPath,
        const std::vector<uint8_t> &key);

    /**
     * Compute cryptographic hash of data
     * @param data Data to hash
     * @param algorithm Hash algorithm to use
     * @return Hash as bytes
     */
    std::vector<uint8_t> hash(
        const std::string &data,
        HashAlgorithm algorithm = HashAlgorithm::SHA256);

    /**
     * Compute cryptographic hash of a file
     * @param filePath Path to file
     * @param algorithm Hash algorithm to use
     * @return Hash as bytes
     */
    std::vector<uint8_t> hashFile(
        const std::string &filePath,
        HashAlgorithm algorithm = HashAlgorithm::SHA256);

    /**
     * Convert byte vector to hexadecimal string
     * @param bytes Bytes to convert
     * @return Hexadecimal string
     */
    std::string bytesToHex(const std::vector<uint8_t> &bytes);

    /**
     * Convert hexadecimal string to byte vector
     * @param hex Hexadecimal string
     * @return Byte vector
     */
    std::vector<uint8_t> hexToBytes(const std::string &hex);

    /**
     * Create a digital signature for data
     * @param data Data to sign
     * @param privateKey Private key for signing
     * @return Signature as bytes
     */
    std::vector<uint8_t> sign(
        const std::string &data,
        const std::vector<uint8_t> &privateKey);

    /**
     * Verify a digital signature
     * @param data Original data
     * @param signature Signature to verify
     * @param publicKey Public key for verification
     * @return Verification result
     */
    VerificationResult verifySignature(
        const std::string &data,
        const std::vector<uint8_t> &signature,
        const std::vector<uint8_t> &publicKey);

    /**
     * Generate a keypair for asymmetric cryptography
     * @param keyType Type of key to generate
     * @return Pair of (privateKey, publicKey)
     */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeyPair(KeyType keyType);

    /**
     * Encrypt data using asymmetric encryption
     * @param plaintext Data to encrypt
     * @param publicKey Public key for encryption
     * @return Encrypted data
     */
    std::vector<uint8_t> encryptAsymmetric(
        const std::string &plaintext,
        const std::vector<uint8_t> &publicKey);

    /**
     * Decrypt data using asymmetric encryption
     * @param ciphertext Encrypted data
     * @param privateKey Private key for decryption
     * @return Decrypted data
     */
    std::string decryptAsymmetric(
        const std::vector<uint8_t> &ciphertext,
        const std::vector<uint8_t> &privateKey);

    /**
     * Securely wipe a file
     * @param filePath Path to file
     * @param passes Number of passes (more passes = more secure but slower)
     * @return True if wiping succeeded
     */
    bool secureWipeFile(const std::string &filePath, int passes = 3);

    /**
     * Securely wipe memory
     * @param data Pointer to memory
     * @param size Size of memory in bytes
     */
    void secureWipeMemory(void *data, size_t size);

    /**
     * Generate a secure token (for authentication, etc.)
     * @param length Length of token
     * @return Secure random token
     */
    std::string generateSecureToken(int length = 32);

    /**
     * Encrypt data with a password
     * @param plaintext Data to encrypt
     * @param password Password for encryption
     * @return Encrypted data
     */
    EncryptedData encryptWithPassword(
        const std::string &plaintext,
        const std::string &password);

    /**
     * Decrypt data with a password
     * @param data Encrypted data
     * @param password Password for decryption
     * @return Decrypted data
     * @throws std::runtime_error if decryption fails
     */
    std::string decryptWithPassword(
        const EncryptedData &data,
        const std::string &password);

    /**
     * Create a key that will be used for encryption
     * @param keyType Type of key to create
     * @return Key information
     */
    KeyInfo createKey(KeyType keyType);

    /**
     * Rotate a key (create a new key and re-encrypt data with it)
     * @param keyId ID of key to rotate
     * @return ID of new key
     */
    std::string rotateKey(const std::string &keyId);

    /**
     * Get information about a key
     * @param keyId ID of key
     * @return Key information
     */
    KeyInfo getKeyInfo(const std::string &keyId);

    /**
     * Convert encrypted data to a format that can be stored or transmitted
     * @param data Encrypted data structure
     * @return Serialized data
     */
    std::string serializeEncryptedData(const EncryptedData &data);

    /**
     * Convert serialized data back to encrypted data structure
     * @param serialized Serialized data
     * @return Encrypted data structure
     */
    EncryptedData deserializeEncryptedData(const std::string &serialized);

    /**
     * Get supported encryption algorithms
     * @return Vector of supported algorithm names
     */
    std::vector<std::string> getSupportedAlgorithms();

    /**
     * Get supported key derivation functions
     * @return Vector of supported KDF names
     */
    std::vector<std::string> getSupportedKDFs();

    /**
     * Get current encryption configuration
     * @return Current configuration
     */
    EncryptionConfig getConfig() const;

    /**
     * Update encryption configuration
     * @param config New configuration
     * @return True if update succeeded
     */
    bool updateConfig(const EncryptionConfig &config);

    /**
     * Check if hardware acceleration is available
     * @return True if hardware acceleration is available
     */
    bool isHardwareAccelerationAvailable();

    /**
     * Perform a constant-time comparison of two strings
     * Helps prevent timing attacks
     * @param a First string
     * @param b Second string
     * @return True if strings are equal
     */
    bool secureCompare(const std::string &a, const std::string &b);

    /**
     * Envelope encryption - encrypt data with data key, then encrypt data key with master key
     * @param plaintext Data to encrypt
     * @param masterKey Master key for encrypting the data key
     * @return Pair of (encrypted data, encrypted data key)
     */
    std::pair<EncryptedData, EncryptedData> envelopeEncrypt(
        const std::string &plaintext,
        const std::vector<uint8_t> &masterKey);

    /**
     * Envelope decryption - decrypt data key with master key, then decrypt data with data key
     * @param encryptedData Encrypted data
     * @param encryptedDataKey Encrypted data key
     * @param masterKey Master key for decrypting the data key
     * @return Decrypted data
     */
    std::string envelopeDecrypt(
        const EncryptedData &encryptedData,
        const EncryptedData &encryptedDataKey,
        const std::vector<uint8_t> &masterKey);

    /**
     * Reset internal state, clearing sensitive data
     */
    void resetState();

    /**
     * Securely wipe a string
     * @param data String to wipe
     */
    void secureWipe(std::string &data);

    /**
     * Securely wipe a vector
     * @param data Vector to wipe
     */
    template <typename T>
    void secureWipe(std::vector<T> &data);

private:
    // Implementation details
    class EncryptionImpl;
    std::unique_ptr<EncryptionImpl> impl_;

    // Current configuration
    EncryptionConfig config_;

    // Random number generator
    std::random_device rd_;
    std::mt19937 rng_;

    // Supported algorithms and parameters
    std::map<std::string, std::function<EncryptedData(const std::string &, const std::vector<uint8_t> &)>> encryptors_;
    std::map<std::string, std::function<std::string(const EncryptedData &, const std::vector<uint8_t> &)>> decryptors_;
    std::map<std::string, std::function<std::vector<uint8_t>(const std::string &, const KDFParams &)>> kdfs_;

    // Key management
    std::map<std::string, std::vector<uint8_t>> keyStore_;
    std::map<std::string, KeyInfo> keyInfo_;

    // Initialize the encryption implementation
    void initImplementation();
    void registerAlgorithms();
    void registerKDFs();

    // Helper methods for specific algorithms
    EncryptedData encryptAesGcm(const std::string &plaintext, const std::vector<uint8_t> &key);
    std::string decryptAesGcm(const EncryptedData &data, const std::vector<uint8_t> &key);

    // Key derivation implementations
    std::vector<uint8_t> deriveKeyPbkdf2(const std::string &password, const KDFParams &params);
    std::vector<uint8_t> deriveKeyArgon2(const std::string &password, const KDFParams &params);

    // Compression utilities
    std::vector<uint8_t> compressData(const std::vector<uint8_t> &data);
    std::vector<uint8_t> decompressData(const std::vector<uint8_t> &compressedData);

    // Internal validation
    bool validateKey(const std::vector<uint8_t> &key, int expectedSize);
    bool validateEncryptedData(const EncryptedData &data);

    // Logging and diagnostics (internal)
    void logCryptoOperation(const std::string &operation, bool success);
};