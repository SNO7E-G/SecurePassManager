#pragma once

#include "encryption.h"
#include "config.h"
#include <string>
#include <vector>
#include <memory>
#include <functional>

/**
 * EnhancedSecurity provides a simplified facade over the encryption, authentication,
 * and key management functionality. It uses best practices for cryptography and
 * security to protect sensitive data.
 */
class EnhancedSecurity
{
public:
    /**
     * Initializes the security system with default configuration
     */
    EnhancedSecurity();

    /**
     * Initializes the security system with custom configuration
     * @param config Encryption configuration
     */
    explicit EnhancedSecurity(const EncryptionConfig &config);

    /**
     * Destructor - securely wipes all sensitive data
     */
    ~EnhancedSecurity();

    /**
     * Sets the master password for encryption/decryption operations
     * @param masterPassword The master password to use
     * @return True if successfully set
     */
    bool setMasterPassword(const std::string &masterPassword);

    /**
     * Changes the master password
     * @param oldPassword Current master password
     * @param newPassword New master password to set
     * @return True if password was successfully changed
     */
    bool changeMasterPassword(const std::string &oldPassword, const std::string &newPassword);

    /**
     * Verifies if a password matches the stored master password
     * @param password Password to verify
     * @return True if password matches
     */
    bool verifyMasterPassword(const std::string &password);

    /**
     * Encrypts data using the master key
     * @param plaintext Data to encrypt
     * @return Encrypted data as base64 string
     */
    std::string encrypt(const std::string &plaintext);

    /**
     * Decrypts data using the master key
     * @param ciphertext Encrypted data as base64 string
     * @return Decrypted data
     */
    std::string decrypt(const std::string &ciphertext);

    /**
     * Encrypts data using a specific password
     * @param plaintext Data to encrypt
     * @param password Password to use for encryption
     * @return Encrypted data as base64 string
     */
    std::string encryptWithPassword(const std::string &plaintext, const std::string &password);

    /**
     * Decrypts data using a specific password
     * @param ciphertext Encrypted data as base64 string
     * @param password Password to use for decryption
     * @return Decrypted data
     */
    std::string decryptWithPassword(const std::string &ciphertext, const std::string &password);

    /**
     * Encrypts a file using the master key
     * @param inputFile Path to input file
     * @param outputFile Path to output encrypted file
     * @return True if file was successfully encrypted
     */
    bool encryptFile(const std::string &inputFile, const std::string &outputFile);

    /**
     * Decrypts a file using the master key
     * @param inputFile Path to encrypted file
     * @param outputFile Path to output decrypted file
     * @return True if file was successfully decrypted
     */
    bool decryptFile(const std::string &inputFile, const std::string &outputFile);

    /**
     * Generates a secure random password
     * @param length Password length
     * @param includeUppercase Include uppercase letters
     * @param includeLowercase Include lowercase letters
     * @param includeNumbers Include numbers
     * @param includeSpecial Include special characters
     * @return Random password
     */
    std::string generatePassword(
        int length = 16,
        bool includeUppercase = true,
        bool includeLowercase = true,
        bool includeNumbers = true,
        bool includeSpecial = true);

    /**
     * Generates a secure passphrase from dictionary words
     * @param wordCount Number of words to include
     * @param separator Character to separate words
     * @return Random passphrase
     */
    std::string generatePassphrase(int wordCount = 5, const std::string &separator = "-");

    /**
     * Securely erases a file from disk
     * @param filePath Path to file to erase
     * @param passes Number of overwrite passes
     * @return True if file was successfully erased
     */
    bool secureEraseFile(const std::string &filePath, int passes = 3);

    /**
     * Checks if a password is strong enough
     * @param password Password to check
     * @return True if password meets strength requirements
     */
    bool isPasswordStrong(const std::string &password);

    /**
     * Checks if a password is in a known breach database
     * @param password Password to check
     * @return True if password is found in a breach
     */
    bool isPasswordBreached(const std::string &password);

    /**
     * Gets the strength score of a password (0-100)
     * @param password Password to score
     * @return Strength score between 0 and 100
     */
    int getPasswordStrength(const std::string &password);

    /**
     * Gets suggestions to improve a password
     * @param password Password to analyze
     * @return List of suggestions
     */
    std::vector<std::string> getPasswordSuggestions(const std::string &password);

    /**
     * Updates security settings
     * @param algorithm Encryption algorithm to use
     * @param keySize Key size in bytes
     * @param iterations KDF iterations
     * @return True if settings were updated
     */
    bool updateSecuritySettings(
        const std::string &algorithm,
        int keySize,
        int iterations);

    /**
     * Locks the security system, clearing sensitive data from memory
     * After locking, the master password needs to be set again
     */
    void lock();

    /**
     * Checks if the security system is locked
     * @return True if locked
     */
    bool isLocked() const;

    /**
     * Gets information about the current security configuration
     * @return Security information as key-value map
     */
    std::map<std::string, std::string> getSecurityInfo() const;

private:
    std::unique_ptr<Encryption> encryption_;
    bool isInitialized_;
    bool isLocked_;

    // Current master key hash for verification
    std::string masterKeyHash_;

    // Salt used for the master key
    std::string masterKeySalt_;

    // Parse serialized encrypted data
    Encryption::EncryptedData parseEncryptedData(const std::string &serializedData);

    // Serialize encrypted data
    std::string serializeEncryptedData(const Encryption::EncryptedData &data);
};