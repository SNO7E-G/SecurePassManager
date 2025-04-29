#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

#include "enhanced_security.h"
#include "database.h"
#include "password_generator.h"
#include "authenticator.h"
#include "password_strength.h"

/**
 * Main PasswordManager class that coordinates all functionality
 */
class PasswordManager
{
public:
    struct PasswordEntry
    {
        int id;
        std::string title;
        std::string username;
        std::string password;
        std::string url;
        std::string notes;
        std::string category;
        std::vector<std::string> tags;
        std::chrono::system_clock::time_point created;
        std::chrono::system_clock::time_point modified;
        std::chrono::system_clock::time_point expiry;
    };

    PasswordManager();
    ~PasswordManager();

    // Authentication
    bool initialize(const std::string &dbPath);
    bool createVault(const std::string &masterPassword, const std::string &dbPath);
    bool unlockVault(const std::string &masterPassword);
    bool lockVault();
    bool changeMasterPassword(const std::string &currentPassword, const std::string &newPassword);
    bool isLocked() const;

    // Password management
    bool addPassword(const PasswordEntry &entry);
    bool updatePassword(const PasswordEntry &entry);
    bool deletePassword(int id);
    PasswordEntry getPassword(int id);
    std::vector<PasswordEntry> getAllPasswords();
    std::vector<PasswordEntry> searchPasswords(const std::string &query);
    std::vector<PasswordEntry> getPasswordsByCategory(const std::string &category);
    std::vector<PasswordEntry> getPasswordsByTag(const std::string &tag);

    // Password generation
    std::string generatePassword(int length, bool includeUpper, bool includeLower,
                                 bool includeNumbers, bool includeSymbols);
    std::string generatePronounceable(int wordCount);
    std::string generatePassphrase(int wordCount);

    // Password strength and security
    double evaluatePasswordStrength(const std::string &password);
    bool checkPasswordBreached(const std::string &password);

    // Categories and tags
    std::vector<std::string> getAllCategories();
    std::vector<std::string> getAllTags();

    // Import/Export
    bool exportPasswords(const std::string &filePath, const std::string &password);
    bool importPasswords(const std::string &filePath, const std::string &password);

    // Clipboard and auto-type
    bool copyToClipboard(const std::string &text, int timeoutSeconds = 30);
    bool performAutoType(const PasswordEntry &entry);

private:
    std::unique_ptr<EnhancedSecurity> encryption_;
    std::unique_ptr<Database> database_;
    std::unique_ptr<PasswordGenerator> generator_;
    std::unique_ptr<Authenticator> authenticator_;
    std::unique_ptr<PasswordStrength> strengthChecker_;

    bool locked_;
    std::string masterKeyHash_;
    std::string encryptionKey_;

    // Internal methods
    bool validateMasterPassword(const std::string &password);
    std::string deriveEncryptionKey(const std::string &masterPassword);
};