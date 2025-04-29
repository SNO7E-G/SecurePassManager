#include "authenticator.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <vector>
#include <random>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <cctype>

// Constructor
Authenticator::Authenticator() : failedAttempts_(0), lockUntil_(std::chrono::system_clock::now()) {
    initialize();
}

// Destructor
Authenticator::~Authenticator() {
    // Clean up if needed
}

// Initialize the authenticator
bool Authenticator::initialize() {
    // Initialize OpenSSL if needed
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    return true;
}

// Hash a password with a salt
std::pair<std::string, std::string> Authenticator::hashPassword(
    const std::string& password, 
    const std::string& salt) {
    
    // If no salt provided, generate one
    std::string usedSalt = salt;
    if (usedSalt.empty()) {
        // Generate a random 16-byte salt
        unsigned char saltData[16];
        if (RAND_bytes(saltData, sizeof(saltData)) != 1) {
            throw std::runtime_error("Failed to generate random salt");
        }
        usedSalt = std::string(reinterpret_cast<char*>(saltData), sizeof(saltData));
    }
    
    // Hash the password using PBKDF2-HMAC-SHA256
    unsigned char hash[32]; // SHA-256 hash is 32 bytes
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                         reinterpret_cast<const unsigned char*>(usedSalt.c_str()),
                         usedSalt.length(), 100000, EVP_sha256(), sizeof(hash), hash) != 1) {
        throw std::runtime_error("Failed to hash password");
    }
    
    return {std::string(reinterpret_cast<char*>(hash), sizeof(hash)), usedSalt};
}

// Verify a password against a stored hash
bool Authenticator::verifyPassword(const std::string& password, 
                                 const std::string& hash, 
                                 const std::string& salt) {
    // Check if authentication is locked
    if (isLocked()) {
        return false;
    }
    
    // Hash the provided password with the same salt
    auto [newHash, _] = hashPassword(password, salt);
    
    // Check if the hashes match
    bool match = (newHash == hash);
    
    // Update failed attempts
    if (!match) {
        failedAttempts_++;
        if (failedAttempts_ >= 5) {
            lockAfterFailedAttempts();
        }
    } else {
        failedAttempts_ = 0;
    }
    
    return match;
}

// Generate a base32-encoded TOTP secret key
std::string Authenticator::generateTOTPSecret() {
    // Generate 20 random bytes (160 bits)
    std::vector<unsigned char> bytes(20);
    if (RAND_bytes(bytes.data(), bytes.size()) != 1) {
        throw std::runtime_error("Failed to generate random bytes for TOTP secret");
    }
    
    // Base32 encoding
    static const char* base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string result;
    
    for (size_t i = 0; i < bytes.size(); i += 5) {
        int buffer = 0;
        int bitsLeft = 0;
        int count = 0;
        
        for (size_t j = 0; j < 5 && i + j < bytes.size(); ++j) {
            buffer <<= 8;
            buffer |= bytes[i + j] & 0xFF;
            bitsLeft += 8;
            
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                bitsLeft -= 5;
                result += base32Chars[index];
                count++;
            }
        }
        
        // Handle padding
        if (count < 8) {
            buffer <<= (5 - bitsLeft);
            int index = buffer & 0x1F;
            result += base32Chars[index];
            count++;
            
            // Add padding if needed
            while (count < 8) {
                result += '=';
                count++;
            }
        }
    }
    
    return result;
}

// Generate a TOTP code for the current time
std::string Authenticator::generateTOTPCode(const std::string& secret) {
    // Get current time
    auto now = std::time(nullptr);
    return generateTOTPCodeAtTime(secret, now);
}

// Private helper to generate TOTP code at a specific time
std::string Authenticator::generateTOTPCodeAtTime(const std::string& secret, time_t time) {
    // TOTP parameters
    const unsigned long timeStep = 30; // 30 seconds
    const unsigned int codeDigits = 6; // 6-digit code
    
    // Calculate the time counter (T)
    unsigned long T = time / timeStep;
    
    // Decode base32 secret
    std::string decodedSecret = decodeBase32(secret);
    
    // Calculate HMAC-SHA1 of the time counter using the secret key
    unsigned char counter[8];
    for (int i = 7; i >= 0; i--) {
        counter[i] = T & 0xFF;
        T >>= 8;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    
    HMAC(EVP_sha1(), decodedSecret.c_str(), decodedSecret.length(),
         counter, sizeof(counter), hash, &hashLen);
    
    // Dynamic truncation
    int offset = hash[hashLen - 1] & 0x0F;
    int binary = ((hash[offset] & 0x7F) << 24) |
                 ((hash[offset + 1] & 0xFF) << 16) |
                 ((hash[offset + 2] & 0xFF) << 8) |
                 (hash[offset + 3] & 0xFF);
    
    // Calculate the TOTP code
    int code = binary % static_cast<int>(std::pow(10, codeDigits));
    
    // Format as a 6-digit string with leading zeros
    std::stringstream ss;
    ss << std::setw(codeDigits) << std::setfill('0') << code;
    return ss.str();
}

// Verify a TOTP code
bool Authenticator::verifyTOTPCode(const std::string& code, const std::string& secret) {
    // Get current time
    auto now = std::time(nullptr);
    
    // Check current time step and adjacent time steps (allow +/- 30 seconds)
    for (int i = -1; i <= 1; i++) {
        auto timeToCheck = now + (i * 30);
        std::string generatedCode = generateTOTPCodeAtTime(secret, timeToCheck);
        if (code == generatedCode) {
            return true;
        }
    }
    
    return false;
}

// Generate a TOTP provisioning URI for QR code generation
std::string Authenticator::getTOTPProvisioningURI(
    const std::string& secret,
    const std::string& accountName,
    const std::string& issuer) {
    
    std::string escapedAccountName = urlEncode(accountName);
    std::string escapedIssuer = urlEncode(issuer);
    
    std::stringstream uri;
    uri << "otpauth://totp/"
        << escapedIssuer << ":" << escapedAccountName
        << "?secret=" << secret
        << "&issuer=" << escapedIssuer
        << "&algorithm=SHA1&digits=6&period=30";
    
    return uri.str();
}

// Generate a recovery code
std::string Authenticator::generateRecoveryCode() {
    // Generate a random 16-character recovery code with groups separated by hyphens
    static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    
    std::vector<unsigned char> randomData(20);
    if (RAND_bytes(randomData.data(), randomData.size()) != 1) {
        throw std::runtime_error("Failed to generate random recovery code");
    }
    
    for (int i = 0; i < 20; i++) {
        if (i > 0 && i % 4 == 0) {
            result += '-';
        }
        result += chars[randomData[i] % 36];
    }
    
    return result;
}

// Check if biometric authentication is available
bool Authenticator::isBiometricAvailable() {
    // This is platform-dependent and would require platform-specific implementation
    // For now, return false as a placeholder
    return false;
}

// Authenticate using biometrics
bool Authenticator::authenticateWithBiometrics(const std::string& reason) {
    // This is platform-dependent and would require platform-specific implementation
    // For now, return false as a placeholder
    return false;
}

// Lock authentication after too many failed attempts
void Authenticator::lockAfterFailedAttempts(const std::chrono::seconds& duration) {
    lockUntil_ = std::chrono::system_clock::now() + duration;
}

// Check if authentication is locked
bool Authenticator::isLocked() {
    return std::chrono::system_clock::now() < lockUntil_;
}

// Get the time remaining until authentication is unlocked
std::chrono::seconds Authenticator::getTimeUntilUnlock() {
    if (!isLocked()) {
        return std::chrono::seconds(0);
    }
    
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(lockUntil_ - now);
    return duration > std::chrono::seconds(0) ? duration : std::chrono::seconds(0);
}

// Helper function to decode base32
std::string Authenticator::decodeBase32(const std::string& input) {
    std::string cleanInput = input;
    
    // Remove padding and whitespace
    cleanInput.erase(std::remove(cleanInput.begin(), cleanInput.end(), '='), cleanInput.end());
    cleanInput.erase(std::remove_if(cleanInput.begin(), cleanInput.end(), isspace), cleanInput.end());
    
    // Convert to uppercase
    std::transform(cleanInput.begin(), cleanInput.end(), cleanInput.begin(), ::toupper);
    
    // Base32 character map
    static const char* base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static const unsigned char base32Values[256] = {
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 26, 27, 28, 29, 30, 31, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
        255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
    };
    
    std::string result;
    result.reserve((cleanInput.length() * 5) / 8);
    
    int buffer = 0;
    int bitsLeft = 0;
    
    for (char c : cleanInput) {
        unsigned char value = base32Values[static_cast<unsigned char>(c)];
        if (value == 255) {
            throw std::invalid_argument("Invalid base32 character");
        }
        
        buffer <<= 5;
        buffer |= value;
        bitsLeft += 5;
        
        if (bitsLeft >= 8) {
            bitsLeft -= 8;
            result += static_cast<char>((buffer >> bitsLeft) & 0xFF);
        }
    }
    
    return result;
}

// Helper function for URL encoding
std::string Authenticator::urlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    
    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
        }
    }
    
    return escaped.str();
} 