#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <ctime>

/**
 * Class for handling user authentication and MFA
 */
class Authenticator {
public:
    Authenticator();
    ~Authenticator();
    
    /**
     * Initialize the authenticator
     * @return True if initialization succeeded
     */
    bool initialize();
    
    /**
     * Hash a password with a salt using a secure algorithm
     * @param password The password to hash
     * @param salt The salt to use (will be generated if empty)
     * @return A pair containing the hash and the salt used
     */
    std::pair<std::string, std::string> hashPassword(
        const std::string& password, 
        const std::string& salt = "");
    
    /**
     * Verify a password against a stored hash
     * @param password The password to verify
     * @param hash The stored hash
     * @param salt The salt used for hashing
     * @return True if the password matches
     */
    bool verifyPassword(const std::string& password, 
                       const std::string& hash, 
                       const std::string& salt);
    
    /**
     * Generate a new TOTP secret
     * @return The generated secret
     */
    std::string generateTOTPSecret();
    
    /**
     * Generate the current TOTP code
     * @param secret The TOTP secret
     * @return The current TOTP code
     */
    std::string generateTOTPCode(const std::string& secret);
    
    /**
     * Verify a TOTP code
     * @param code The code to verify
     * @param secret The TOTP secret
     * @return True if the code is valid
     */
    bool verifyTOTPCode(const std::string& code, const std::string& secret);
    
    /**
     * Generate a TOTP provisioning URI for QR code generation
     * @param secret The TOTP secret
     * @param accountName The account name (e.g., "user@example.com")
     * @param issuer The issuer name (e.g., "SecurePassManager")
     * @return The provisioning URI
     */
    std::string getTOTPProvisioningURI(const std::string& secret, 
                                      const std::string& accountName,
                                      const std::string& issuer = "SecurePassManager");
    
    /**
     * Generate a recovery code
     * @return The generated recovery code
     */
    std::string generateRecoveryCode();
    
    /**
     * Check if biometric authentication is available
     * @return True if biometric authentication is available
     */
    bool isBiometricAvailable();
    
    /**
     * Authenticate using biometrics
     * @param reason The reason for authentication to display to the user
     * @return True if authentication succeeded
     */
    bool authenticateWithBiometrics(const std::string& reason = "Authenticate to unlock vault");
    
    /**
     * Lock authentication after too many failed attempts
     * @param duration The duration to lock for
     */
    void lockAfterFailedAttempts(const std::chrono::seconds& duration = std::chrono::minutes(5));
    
    /**
     * Check if authentication is currently locked
     * @return True if locked
     */
    bool isLocked();
    
    /**
     * Get the time remaining until authentication is unlocked
     * @return The time remaining
     */
    std::chrono::seconds getTimeUntilUnlock();

private:
    int failedAttempts_;
    std::chrono::system_clock::time_point lockUntil_;
    
    // Helper methods
    std::string generateTOTPCodeAtTime(const std::string& secret, time_t time);
    std::string decodeBase32(const std::string& input);
    std::string urlEncode(const std::string& value);
}; 