#include "enhanced_security.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <string>

// Function to run a test and print result
void runTest(const std::string &testName, std::function<bool()> testFunc)
{
    std::cout << "Running test: " << testName << "... ";
    bool result = testFunc();
    std::cout << (result ? "PASSED" : "FAILED") << std::endl;
    if (!result)
    {
        std::cerr << "  Test failed: " << testName << std::endl;
    }
}

// Test the basic encryption and decryption functionality
bool testBasicEncryption()
{
    try
    {
        // Create an instance with default configuration
        EnhancedSecurity security;

        // Set master password
        bool success = security.setMasterPassword("StrongTestPassword123!");
        if (!success)
            return false;

        // Test encryption and decryption
        std::string originalText = "This is a secret message that needs to be encrypted.";
        std::string encrypted = security.encrypt(originalText);
        std::string decrypted = security.decrypt(encrypted);

        return originalText == decrypted;
    }
    catch (const std::exception &e)
    {
        std::cerr << "  Exception: " << e.what() << std::endl;
        return false;
    }
}

// Test password-specific encryption
bool testPasswordEncryption()
{
    try
    {
        // Create an instance with default configuration
        EnhancedSecurity security;

        // Test encryption and decryption with specific password
        std::string originalText = "Another secret message with password-specific encryption.";
        std::string password = "SpecificPassword456!";

        std::string encrypted = security.encryptWithPassword(originalText, password);
        std::string decrypted = security.decryptWithPassword(encrypted, password);

        return originalText == decrypted;
    }
    catch (const std::exception &e)
    {
        std::cerr << "  Exception: " << e.what() << std::endl;
        return false;
    }
}

// Test password verification
bool testPasswordVerification()
{
    try
    {
        EnhancedSecurity security;

        // Set master password
        std::string masterPassword = "MasterPassword789!";
        bool success = security.setMasterPassword(masterPassword);
        if (!success)
            return false;

        // Test correct password verification
        if (!security.verifyMasterPassword(masterPassword))
            return false;

        // Test incorrect password verification
        if (security.verifyMasterPassword("WrongPassword"))
            return false;

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "  Exception: " << e.what() << std::endl;
        return false;
    }
}

// Test password strength evaluation
bool testPasswordStrength()
{
    try
    {
        EnhancedSecurity security;

        // Test weak password
        std::string weakPassword = "password123";
        if (security.isPasswordStrong(weakPassword))
            return false;

        // Test strong password
        std::string strongPassword = "K7&pX9$mQ2@bG5!";
        if (!security.isPasswordStrong(strongPassword))
            return false;

        // Test password strength score
        int weakScore = security.getPasswordStrength(weakPassword);
        int strongScore = security.getPasswordStrength(strongPassword);

        if (weakScore >= strongScore)
            return false;

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "  Exception: " << e.what() << std::endl;
        return false;
    }
}

// Test password generation
bool testPasswordGeneration()
{
    try
    {
        EnhancedSecurity security;

        // Generate password with all character types
        std::string password = security.generatePassword(16, true, true, true, true);

        // Verify length
        if (password.length() != 16)
            return false;

        // Generate passphrase
        std::string passphrase = security.generatePassphrase(5, "-");

        // Count separators to verify word count
        int separatorCount = 0;
        for (char c : passphrase)
        {
            if (c == '-')
                separatorCount++;
        }

        if (separatorCount != 4)
            return false; // 5 words should have 4 separators

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "  Exception: " << e.what() << std::endl;
        return false;
    }
}

// Test file encryption and decryption
bool testFileEncryption()
{
    try
    {
        EnhancedSecurity security;

        // Set master password
        bool success = security.setMasterPassword("FileEncryptionTest123!");
        if (!success)
            return false;

        // Create a test file
        std::string testFile = "test_file.txt";
        std::string encryptedFile = "test_file.enc";
        std::string decryptedFile = "test_file_decrypted.txt";

        std::string originalContent = "This is test content for file encryption and decryption.";

        // Write original file
        {
            std::ofstream file(testFile);
            file << originalContent;
        }

        // Encrypt the file
        if (!security.encryptFile(testFile, encryptedFile))
            return false;

        // Decrypt the file
        if (!security.decryptFile(encryptedFile, decryptedFile))
            return false;

        // Read the decrypted content
        std::string decryptedContent;
        {
            std::ifstream file(decryptedFile);
            std::stringstream buffer;
            buffer << file.rdbuf();
            decryptedContent = buffer.str();
        }

        // Clean up test files
        std::remove(testFile.c_str());
        std::remove(encryptedFile.c_str());
        std::remove(decryptedFile.c_str());

        return originalContent == decryptedContent;
    }
    catch (const std::exception &e)
    {
        std::cerr << "  Exception: " << e.what() << std::endl;
        return false;
    }
}

// Test changing master password
bool testChangeMasterPassword()
{
    try
    {
        EnhancedSecurity security;

        // Set initial master password
        std::string oldPassword = "OldMasterPassword123!";
        std::string newPassword = "NewMasterPassword456!";

        bool success = security.setMasterPassword(oldPassword);
        if (!success)
            return false;

        // Encrypt something with old password
        std::string originalText = "This is encrypted with the old password.";
        std::string encrypted = security.encrypt(originalText);

        // Change password
        success = security.changeMasterPassword(oldPassword, newPassword);
        if (!success)
            return false;

        // Try to decrypt with new password setup
        std::string decrypted = security.decrypt(encrypted);

        // Verify the original text can still be decrypted after password change
        return originalText == decrypted;
    }
    catch (const std::exception &e)
    {
        std::cerr << "  Exception: " << e.what() << std::endl;
        return false;
    }
}

// Test security information
bool testSecurityInfo()
{
    try
    {
        EnhancedSecurity security;

        // Get security info
        auto info = security.getSecurityInfo();

        // Check if essential fields exist
        if (info.find("algorithm") == info.end())
            return false;
        if (info.find("key_size") == info.end())
            return false;
        if (info.find("iterations") == info.end())
            return false;
        if (info.find("status") == info.end())
            return false;

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "  Exception: " << e.what() << std::endl;
        return false;
    }
}

// Main test runner
int main()
{
    std::cout << "Running Enhanced Security Tests\n";
    std::cout << "============================\n";

    runTest("Basic Encryption and Decryption", testBasicEncryption);
    runTest("Password-Specific Encryption", testPasswordEncryption);
    runTest("Password Verification", testPasswordVerification);
    runTest("Password Strength Evaluation", testPasswordStrength);
    runTest("Password Generation", testPasswordGeneration);
    runTest("File Encryption and Decryption", testFileEncryption);
    runTest("Changing Master Password", testChangeMasterPassword);
    runTest("Security Information", testSecurityInfo);

    std::cout << "============================\n";
    std::cout << "Tests completed.\n";

    return 0;
}