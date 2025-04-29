#include "passwordmanager.h"
#include <stdexcept>
#include <chrono>
#include <fstream>
#include <iostream>
#include <algorithm>

// Constructor
PasswordManager::PasswordManager()
    : locked_(true)
{

    // Initialize components
    encryption_ = std::make_unique<EnhancedSecurity>();
    database_ = std::make_unique<Database>();
    generator_ = std::make_unique<PasswordGenerator>();
    authenticator_ = std::make_unique<Authenticator>();
    strengthChecker_ = std::make_unique<PasswordStrength>();
}

// Destructor
PasswordManager::~PasswordManager()
{
    // Lock the vault to ensure sensitive data is cleared
    lockVault();
}

// Initialize the password manager
bool PasswordManager::initialize(const std::string &dbPath)
{
    // Already initialized
    if (database_->initialize(dbPath, encryption_.get()))
    {
        return true;
    }

    return false;
}

// Create a new vault
bool PasswordManager::createVault(const std::string &masterPassword, const std::string &dbPath)
{
    try
    {
        // Set master password in enhanced security
        if (!encryption_->setMasterPassword(masterPassword))
        {
            return false;
        }

        // Hash the master password
        auto [masterHash, salt] = authenticator_->hashPassword(masterPassword);

        // Create the vault
        if (!database_->createVault(dbPath, masterHash, salt, 100000))
        {
            return false;
        }

        // Derive the encryption key
        auto [key, _] = Encryption::deriveKeyFromPassword(masterPassword, salt, 100000);

        // Initialize encryption with the key
        if (!encryption_->initialize(key))
        {
            return false;
        }

        // Store the key temporarily
        encryptionKey_ = key;

        // Unlock the vault
        locked_ = false;

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error creating vault: " << e.what() << std::endl;
        return false;
    }
}

// Unlock the vault
bool PasswordManager::unlockVault(const std::string &masterPassword)
{
    if (!database_)
    {
        return false;
    }

    try
    {
        // Verify master password
        if (!encryption_->verifyMasterPassword(masterPassword))
        {
            return false;
        }

        // Set up encryption with the master password
        if (!encryption_->setMasterPassword(masterPassword))
        {
            return false;
        }

        // Load passwords from database
        // ... database loading code

        // Unlock the vault
        locked_ = false;

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error unlocking vault: " << e.what() << std::endl;
        return false;
    }
}

// Lock the vault
bool PasswordManager::lockVault()
{
    if (!locked_)
    {
        // Clear sensitive data
        encryption_->lock();
        // ... clear other sensitive data

        locked_ = true;
    }
    return true;
}

// Change the master password
bool PasswordManager::changeMasterPassword(const std::string &currentPassword, const std::string &newPassword)
{
    if (locked_)
    {
        return false;
    }

    try
    {
        // Verify current password
        if (!encryption_->verifyMasterPassword(currentPassword))
        {
            return false;
        }

        // Change master password
        if (!encryption_->changeMasterPassword(currentPassword, newPassword))
        {
            return false;
        }

        // Update database encryption
        // ... database re-encryption code

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error changing master password: " << e.what() << std::endl;
        return false;
    }
}

// Check if the vault is locked
bool PasswordManager::isLocked() const
{
    return locked_;
}

// Add a password
bool PasswordManager::addPassword(const PasswordEntry &entry)
{
    if (locked_)
    {
        return false;
    }

    // Encrypt sensitive fields
    std::string encryptedPassword = encryption_->encrypt(entry.password);

    // ... store in database

    return true;
}

// Update a password
bool PasswordManager::updatePassword(const PasswordEntry &entry)
{
    if (locked_)
    {
        return false;
    }

    // Get the current password entry
    auto currentEntry = getPassword(entry.id);

    // If the password changed, add it to the history
    if (currentEntry.password != entry.password)
    {
        // Add the old password to history
        database_->addPasswordHistoryEntry(
            entry.id,
            currentEntry.password,
            std::chrono::system_clock::now());
    }

    return database_->updatePasswordEntry(entry);
}

// Delete a password
bool PasswordManager::deletePassword(int id)
{
    if (locked_)
    {
        return false;
    }

    return database_->deletePasswordEntry(id);
}

// Get a password by ID
PasswordManager::PasswordEntry PasswordManager::getPassword(int id)
{
    if (locked_)
    {
        throw std::runtime_error("Vault is locked");
    }

    // ... get from database

    // Decrypt password
    PasswordEntry entry = /* retrieve from database */;
    entry.password = encryption_->decrypt(entry.password);

    return entry;
}

// Get all passwords
std::vector<PasswordManager::PasswordEntry> PasswordManager::getAllPasswords()
{
    if (locked_)
    {
        return {};
    }

    return database_->getAllPasswordEntries();
}

// Search for passwords
std::vector<PasswordManager::PasswordEntry> PasswordManager::searchPasswords(const std::string &query)
{
    if (locked_)
    {
        return {};
    }

    return database_->searchPasswordEntries(query);
}

// Get passwords by category
std::vector<PasswordManager::PasswordEntry> PasswordManager::getPasswordsByCategory(const std::string &category)
{
    if (locked_)
    {
        return {};
    }

    return database_->getPasswordEntriesByCategory(category);
}

// Get passwords by tag
std::vector<PasswordManager::PasswordEntry> PasswordManager::getPasswordsByTag(const std::string &tag)
{
    if (locked_)
    {
        return {};
    }

    return database_->getPasswordEntriesByTag(tag);
}

// Generate a password
std::string PasswordManager::generatePassword(
    int length,
    bool includeUpper,
    bool includeLower,
    bool includeNumbers,
    bool includeSymbols)
{

    return encryption_->generatePassword(
        length,
        includeUpper,
        includeLower,
        includeNumbers,
        includeSymbols);
}

// Generate a pronounceable password
std::string PasswordManager::generatePronounceable(int wordCount)
{
    return generator_->generatePronounceable(wordCount);
}

// Generate a passphrase
std::string PasswordManager::generatePassphrase(int wordCount)
{
    return encryption_->generatePassphrase(wordCount);
}

// Evaluate password strength
double PasswordManager::evaluatePasswordStrength(const std::string &password)
{
    return encryption_->getPasswordStrength(password) / 100.0;
}

// Check if a password has been breached
bool PasswordManager::checkPasswordBreached(const std::string &password)
{
    return encryption_->isPasswordBreached(password);
}

// Get all categories
std::vector<std::string> PasswordManager::getAllCategories()
{
    if (locked_)
    {
        return {};
    }

    return database_->getAllCategories();
}

// Get all tags
std::vector<std::string> PasswordManager::getAllTags()
{
    if (locked_)
    {
        return {};
    }

    return database_->getAllTags();
}

// Export passwords to a file
bool PasswordManager::exportPasswords(const std::string &filePath, const std::string &password)
{
    if (locked_)
    {
        return false;
    }

    try
    {
        // Get all passwords
        auto entries = database_->getAllPasswordEntries();

        // Create a JSON structure
        std::stringstream json;
        json << "{\n";
        json << "  \"version\": 1,\n";
        json << "  \"entries\": [\n";

        for (size_t i = 0; i < entries.size(); ++i)
        {
            const auto &entry = entries[i];

            json << "    {\n";
            json << "      \"title\": \"" << entry.title << "\",\n";
            json << "      \"username\": \"" << entry.username << "\",\n";
            json << "      \"password\": \"" << entry.password << "\",\n";
            json << "      \"url\": \"" << entry.url << "\",\n";
            json << "      \"notes\": \"" << entry.notes << "\",\n";
            json << "      \"category\": \"" << entry.category << "\",\n";
            json << "      \"tags\": [";

            for (size_t j = 0; j < entry.tags.size(); ++j)
            {
                json << "\"" << entry.tags[j] << "\"";
                if (j < entry.tags.size() - 1)
                {
                    json << ", ";
                }
            }

            json << "],\n";

            // Convert time points to ISO 8601 strings
            auto to_iso8601 = [](const std::chrono::system_clock::time_point &tp)
            {
                auto time = std::chrono::system_clock::to_time_t(tp);
                std::tm *tm = std::gmtime(&time);
                char buffer[30];
                std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", tm);
                return std::string(buffer);
            };

            json << "      \"created\": \"" << to_iso8601(entry.created) << "\",\n";
            json << "      \"modified\": \"" << to_iso8601(entry.modified) << "\"";

            if (entry.expiry.time_since_epoch().count() > 0)
            {
                json << ",\n      \"expiry\": \"" << to_iso8601(entry.expiry) << "\"\n";
            }
            else
            {
                json << "\n";
            }

            json << "    }";

            if (i < entries.size() - 1)
            {
                json << ",";
            }

            json << "\n";
        }

        json << "  ]\n";
        json << "}\n";

        // Encrypt the JSON using the provided password
        auto [key, salt] = Encryption::deriveKeyFromPassword(password);

        // Create a temporary encryption object for the export
        Encryption exportEncryption;
        exportEncryption.initialize(key);

        std::string jsonStr = json.str();
        std::string encryptedData = exportEncryption.encrypt(jsonStr);

        // Write the encrypted data to the file
        std::ofstream file(filePath, std::ios::binary);
        if (!file)
        {
            return false;
        }

        // Write the salt
        file.write(salt.c_str(), salt.size());

        // Write the encrypted data
        file.write(encryptedData.c_str(), encryptedData.size());

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error exporting passwords: " << e.what() << std::endl;
        return false;
    }
}

// Import passwords from a file
bool PasswordManager::importPasswords(const std::string &filePath, const std::string &password)
{
    if (locked_)
    {
        return false;
    }

    try
    {
        // Read the file
        std::ifstream file(filePath, std::ios::binary);
        if (!file)
        {
            return false;
        }

        // Read the salt (first 16 bytes)
        char saltBuffer[16];
        file.read(saltBuffer, 16);
        std::string salt(saltBuffer, 16);

        // Read the rest of the file
        std::string encryptedData((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());

        // Derive the key from the password and salt
        auto [key, _] = Encryption::deriveKeyFromPassword(password, salt);

        // Create a temporary encryption object for the import
        Encryption importEncryption;
        importEncryption.initialize(key);

        // Decrypt the data
        std::string jsonStr = importEncryption.decrypt(encryptedData);

        // Parse the JSON and import the passwords
        // (This would typically use a JSON parser, but for simplicity
        // we'll just do a placeholder operation here)

        // For now, just check if the data seems valid
        if (jsonStr.find("\"version\": 1") == std::string::npos)
        {
            return false;
        }

        // TODO: Actually parse the JSON and import the passwords

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error importing passwords: " << e.what() << std::endl;
        return false;
    }
}

// Copy to clipboard
bool PasswordManager::copyToClipboard(const std::string &text, int timeoutSeconds)
{
    // This would typically use platform-specific code to copy to clipboard
    // and set up a timer to clear it after the timeout

    // For now, just return success
    return true;
}

// Perform auto-type
bool PasswordManager::performAutoType(const PasswordEntry &entry)
{
    // This would typically use platform-specific code to simulate keystrokes

    // For now, just return success
    return true;
}

// Validate master password
bool PasswordManager::validateMasterPassword(const std::string &password)
{
    if (!database_)
    {
        return false;
    }

    // Get the salt and iterations from the database
    std::string salt = database_->getSalt();

    if (salt.empty())
    {
        return false;
    }

    // Hash the password
    auto [hash, _] = authenticator_->hashPassword(password, salt);

    // Verify the password
    return database_->verifyMasterPassword(hash);
}

// Derive encryption key
std::string PasswordManager::deriveEncryptionKey(const std::string &masterPassword)
{
    if (!database_)
    {
        return "";
    }

    // Get the salt and iterations from the database
    std::string salt = database_->getSalt();
    int iterations = database_->getIterations();

    if (salt.empty() || iterations <= 0)
    {
        return "";
    }

    // Derive the key
    auto [key, _] = Encryption::deriveKeyFromPassword(masterPassword, salt, iterations);

    return key;
}