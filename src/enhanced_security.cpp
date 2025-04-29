#include "enhanced_security.h"
#include <openssl/sha.h>
#include <stdexcept>
#include <fstream>
#include <regex>

// Constructor with default configuration
EnhancedSecurity::EnhancedSecurity()
    : isInitialized_(false), isLocked_(true)
{
    // Create encryption instance with default configuration
    encryption_ = std::make_unique<Encryption>();
}

// Constructor with custom configuration
EnhancedSecurity::EnhancedSecurity(const EncryptionConfig &config)
    : isInitialized_(false), isLocked_(true)
{
    // Create encryption instance with provided configuration
    encryption_ = std::make_unique<Encryption>(config);
}

// Destructor
EnhancedSecurity::~EnhancedSecurity()
{
    // Secure wipe of sensitive data
    encryption_->secureWipe(masterKeyHash_);
    encryption_->secureWipe(masterKeySalt_);
    lock();
}

// Set master password
bool EnhancedSecurity::setMasterPassword(const std::string &masterPassword)
{
    try
    {
        if (masterKeySalt_.empty())
        {
            masterKeySalt_ = encryption_->generateSalt(16);
        }

        // Create KDF parameters
        Encryption::KDFParams kdfParams;
        kdfParams.salt = masterKeySalt_;
        kdfParams.algorithm = encryption_->getConfig().keyDerivationFunction;
        kdfParams.iterations = encryption_->getConfig().iterations;
        kdfParams.memorySize = encryption_->getConfig().memorySize;
        kdfParams.parallelism = encryption_->getConfig().parallelism;

        // Derive the master key
        std::vector<uint8_t> masterKey = encryption_->deriveKey(masterPassword, kdfParams);

        // Hash the master key for verification later
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(masterKey.data(), masterKey.size(), hash);
        masterKeyHash_ = std::string(reinterpret_cast<char *>(hash), SHA256_DIGEST_LENGTH);

        // Initialize encryption with the master key
        if (!encryption_->initialize(std::string(masterKey.begin(), masterKey.end())))
        {
            return false;
        }

        // Securely wipe the key from memory
        encryption_->secureWipeMemory(masterKey.data(), masterKey.size());

        isInitialized_ = true;
        isLocked_ = false;
        return true;
    }
    catch (const std::exception &e)
    {
        return false;
    }
}

// Change master password
bool EnhancedSecurity::changeMasterPassword(const std::string &oldPassword, const std::string &newPassword)
{
    // Verify old password first
    if (!verifyMasterPassword(oldPassword))
    {
        return false;
    }

    // Generate new salt
    masterKeySalt_ = encryption_->generateSalt(16);

    // Set the new password
    return setMasterPassword(newPassword);
}

// Verify master password
bool EnhancedSecurity::verifyMasterPassword(const std::string &password)
{
    try
    {
        Encryption::KDFParams kdfParams;
        kdfParams.salt = masterKeySalt_;
        kdfParams.algorithm = encryption_->getConfig().keyDerivationFunction;
        kdfParams.iterations = encryption_->getConfig().iterations;
        kdfParams.memorySize = encryption_->getConfig().memorySize;
        kdfParams.parallelism = encryption_->getConfig().parallelism;

        // Derive the key
        std::vector<uint8_t> key = encryption_->deriveKey(password, kdfParams);

        // Hash the key for comparison
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(key.data(), key.size(), hash);
        std::string keyHash(reinterpret_cast<char *>(hash), SHA256_DIGEST_LENGTH);

        // Compare with stored hash using constant-time comparison
        return encryption_->secureCompare(keyHash, masterKeyHash_);
    }
    catch (const std::exception &e)
    {
        return false;
    }
}

// Encrypt data using master key
std::string EnhancedSecurity::encrypt(const std::string &plaintext)
{
    if (!isInitialized_ || isLocked_)
    {
        throw std::runtime_error("Security system is locked or not initialized");
    }

    try
    {
        // Encrypt the data
        Encryption::EncryptedData encryptedData = encryption_->encrypt(
            plaintext,
            std::vector<uint8_t>() // Empty vector since key is already in encryption_
        );

        // Serialize and return
        return serializeEncryptedData(encryptedData);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(std::string("Encryption failed: ") + e.what());
    }
}

// Decrypt data using master key
std::string EnhancedSecurity::decrypt(const std::string &ciphertext)
{
    if (!isInitialized_ || isLocked_)
    {
        throw std::runtime_error("Security system is locked or not initialized");
    }

    try
    {
        // Parse the encrypted data
        Encryption::EncryptedData encryptedData = parseEncryptedData(ciphertext);

        // Decrypt the data
        return encryption_->decrypt(
            encryptedData,
            std::vector<uint8_t>() // Empty vector since key is already in encryption_
        );
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(std::string("Decryption failed: ") + e.what());
    }
}

// Encrypt with a specific password
std::string EnhancedSecurity::encryptWithPassword(const std::string &plaintext, const std::string &password)
{
    try
    {
        // Encrypt the data
        Encryption::EncryptedData encryptedData = encryption_->encryptWithPassword(plaintext, password);

        // Serialize and return
        return serializeEncryptedData(encryptedData);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(std::string("Encryption failed: ") + e.what());
    }
}

// Decrypt with a specific password
std::string EnhancedSecurity::decryptWithPassword(const std::string &ciphertext, const std::string &password)
{
    try
    {
        // Parse the encrypted data
        Encryption::EncryptedData encryptedData = parseEncryptedData(ciphertext);

        // Decrypt the data
        return encryption_->decryptWithPassword(encryptedData, password);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(std::string("Decryption failed: ") + e.what());
    }
}

// Encrypt a file
bool EnhancedSecurity::encryptFile(const std::string &inputFile, const std::string &outputFile)
{
    if (!isInitialized_ || isLocked_)
    {
        return false;
    }

    try
    {
        std::ifstream input(inputFile, std::ios::binary);
        if (!input.is_open())
        {
            return false;
        }

        // Read the file
        std::string content(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
        input.close();

        // Encrypt the content
        std::string encrypted = encrypt(content);

        // Write to output file
        std::ofstream output(outputFile, std::ios::binary);
        if (!output.is_open())
        {
            return false;
        }

        output.write(encrypted.c_str(), encrypted.size());
        output.close();

        return true;
    }
    catch (const std::exception &e)
    {
        return false;
    }
}

// Decrypt a file
bool EnhancedSecurity::decryptFile(const std::string &inputFile, const std::string &outputFile)
{
    if (!isInitialized_ || isLocked_)
    {
        return false;
    }

    try
    {
        std::ifstream input(inputFile, std::ios::binary);
        if (!input.is_open())
        {
            return false;
        }

        // Read the file
        std::string encrypted(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
        input.close();

        // Decrypt the content
        std::string decrypted = decrypt(encrypted);

        // Write to output file
        std::ofstream output(outputFile, std::ios::binary);
        if (!output.is_open())
        {
            return false;
        }

        output.write(decrypted.c_str(), decrypted.size());
        output.close();

        return true;
    }
    catch (const std::exception &e)
    {
        return false;
    }
}

// Generate a secure password
std::string EnhancedSecurity::generatePassword(
    int length,
    bool includeUppercase,
    bool includeLowercase,
    bool includeNumbers,
    bool includeSpecial)
{
    return encryption_->generatePassword(
        length,
        includeUppercase,
        includeLowercase,
        includeNumbers,
        includeSpecial,
        false // Don't exclude similar characters
    );
}

// Generate a passphrase
std::string EnhancedSecurity::generatePassphrase(int wordCount, const std::string &separator)
{
    // Simple word list for demonstration - in a real implementation, this would be much larger
    static const std::vector<std::string> wordList = {
        "apple", "banana", "carrot", "diamond", "elephant", "fortress", "giraffe", "harmony",
        "island", "jungle", "kingdom", "lighthouse", "mountain", "notebook", "octopus", "paradise",
        "quantum", "rainbow", "sapphire", "treasure", "umbrella", "vanilla", "whisper", "xylophone",
        "yellow", "zebra", "airplane", "balloon", "calendar", "dolphin", "evening", "freedom"};

    // Generate random indices
    std::vector<uint8_t> randomBytes = encryption_->generateRandomBytes(wordCount);

    // Build passphrase
    std::string passphrase;
    for (int i = 0; i < wordCount; i++)
    {
        if (i > 0)
        {
            passphrase += separator;
        }

        // Select word from list
        passphrase += wordList[randomBytes[i] % wordList.size()];
    }

    return passphrase;
}

// Securely erase a file
bool EnhancedSecurity::secureEraseFile(const std::string &filePath, int passes)
{
    return encryption_->secureWipeFile(filePath, passes);
}

// Check if a password is strong
bool EnhancedSecurity::isPasswordStrong(const std::string &password)
{
    // Simple password strength check - in a real implementation this would be more sophisticated
    if (password.length() < 12)
    {
        return false;
    }

    // Check for character variety
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (char c : password)
    {
        if (std::isupper(c))
            hasUpper = true;
        else if (std::islower(c))
            hasLower = true;
        else if (std::isdigit(c))
            hasDigit = true;
        else
            hasSpecial = true;
    }

    // Must have at least 3 of the 4 character types
    int typeCount = hasUpper + hasLower + hasDigit + hasSpecial;
    return typeCount >= 3;
}

// Check if a password is breached
bool EnhancedSecurity::isPasswordBreached(const std::string &password)
{
    // In a real implementation, this would check against a breach database or API
    // For this example, we'll just check a few common passwords
    static const std::vector<std::string> commonPasswords = {
        "password", "123456", "qwerty", "admin", "welcome", "letmein", "monkey", "password123"};

    return std::find(commonPasswords.begin(), commonPasswords.end(), password) != commonPasswords.end();
}

// Get password strength score
int EnhancedSecurity::getPasswordStrength(const std::string &password)
{
    // Calculate password entropy and other factors
    int score = 0;

    // Length score - each character up to 16 is worth 4 points
    score += std::min(16, static_cast<int>(password.length())) * 4;

    // Check for character variety
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;
    bool hasMiddleNumberOrSymbol = false;
    bool hasRequirements = false;

    for (char c : password)
    {
        if (std::isupper(c))
            hasUpper = true;
        else if (std::islower(c))
            hasLower = true;
        else if (std::isdigit(c))
            hasDigit = true;
        else
            hasSpecial = true;
    }

    // Middle numbers or symbols
    for (size_t i = 1; i < password.length() - 1; i++)
    {
        if (std::isdigit(password[i]) || !std::isalpha(password[i]))
        {
            hasMiddleNumberOrSymbol = true;
            break;
        }
    }

    // Basic requirements
    hasRequirements = password.length() >= 8 && hasUpper && hasLower && hasDigit && hasSpecial;

    // Add scores for variety
    if (hasUpper)
        score += 5;
    if (hasLower)
        score += 5;
    if (hasDigit)
        score += 5;
    if (hasSpecial)
        score += 5;
    if (hasMiddleNumberOrSymbol)
        score += 5;
    if (hasRequirements)
        score += 15;

    // Deductions for patterns
    if (std::regex_search(password, std::regex("(.)\\1{2,}"))) // Repeated characters
        score -= 10;
    if (std::regex_search(password, std::regex("(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", std::regex_constants::icase))) // Sequential letters
        score -= 10;
    if (std::regex_search(password, std::regex("(?:012|123|234|345|456|567|678|789|890)"))) // Sequential numbers
        score -= 10;

    // Cap score between 0 and 100
    return std::max(0, std::min(100, score));
}

// Get password improvement suggestions
std::vector<std::string> EnhancedSecurity::getPasswordSuggestions(const std::string &password)
{
    std::vector<std::string> suggestions;

    if (password.length() < 12)
    {
        suggestions.push_back("Use at least 12 characters");
    }

    if (password.length() < 16)
    {
        suggestions.push_back("For better security, use 16 or more characters");
    }

    // Check for character variety
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (char c : password)
    {
        if (std::isupper(c))
            hasUpper = true;
        else if (std::islower(c))
            hasLower = true;
        else if (std::isdigit(c))
            hasDigit = true;
        else
            hasSpecial = true;
    }

    if (!hasUpper)
        suggestions.push_back("Add uppercase letters");
    if (!hasLower)
        suggestions.push_back("Add lowercase letters");
    if (!hasDigit)
        suggestions.push_back("Add numbers");
    if (!hasSpecial)
        suggestions.push_back("Add special characters");

    // Check for common patterns
    if (std::regex_search(password, std::regex("(.)\\1{2,}")))
    {
        suggestions.push_back("Avoid repeating characters (e.g., 'aaa')");
    }

    if (std::regex_search(password, std::regex("(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", std::regex_constants::icase)))
    {
        suggestions.push_back("Avoid sequential letters (e.g., 'abc')");
    }

    if (std::regex_search(password, std::regex("(?:012|123|234|345|456|567|678|789|890)")))
    {
        suggestions.push_back("Avoid sequential numbers (e.g., '123')");
    }

    return suggestions;
}

// Update security settings
bool EnhancedSecurity::updateSecuritySettings(
    const std::string &algorithm,
    int keySize,
    int iterations)
{
    if (!isInitialized_)
    {
        return false;
    }

    EncryptionConfig config = encryption_->getConfig();

    // Update config
    config.algorithm = algorithm;
    config.keySize = keySize;
    config.iterations = iterations;

    return encryption_->updateConfig(config);
}

// Lock the security system
void EnhancedSecurity::lock()
{
    if (!isLocked_)
    {
        // Reset encryption
        encryption_->resetState();
        isLocked_ = true;
    }
}

// Check if system is locked
bool EnhancedSecurity::isLocked() const
{
    return isLocked_;
}

// Get security info
std::map<std::string, std::string> EnhancedSecurity::getSecurityInfo() const
{
    std::map<std::string, std::string> info;

    EncryptionConfig config = encryption_->getConfig();

    info["algorithm"] = config.algorithm;
    info["key_size"] = std::to_string(config.keySize);
    info["iterations"] = std::to_string(config.iterations);
    info["kdf"] = config.keyDerivationFunction;
    info["hardware_acceleration"] = encryption_->isHardwareAccelerationAvailable() ? "available" : "unavailable";
    info["status"] = isLocked_ ? "locked" : "unlocked";

    return info;
}

// Parse serialized encrypted data
Encryption::EncryptedData EnhancedSecurity::parseEncryptedData(const std::string &serializedData)
{
    return encryption_->deserializeEncryptedData(serializedData);
}

// Serialize encrypted data
std::string EnhancedSecurity::serializeEncryptedData(const Encryption::EncryptedData &data)
{
    return encryption_->serializeEncryptedData(data);
}