#include "cli.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <functional>
#include <map>
#include <cctype>
#include <regex>
#include <chrono>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// Constructor
CLI::CLI(PasswordManager* manager) 
    : manager_(manager), running_(false), isVaultOpen_(false), colorMode_(ColorMode::COLORFUL) {
    
    // Initialize ANSI colors
    initializeColors();
    
    // Initialize command handlers
    initializeCommands();
}

// Destructor
CLI::~CLI() {
    // Nothing to clean up
}

// Start the CLI application
int CLI::run() {
    running_ = true;
    
    // Print welcome message
    std::cout << formatWithColor("\n======= Secure Password Manager =======\n", "bold")
              << "Type " << formatWithColor("help", "command") << " for a list of commands.\n"
              << std::endl;
    
    // Main command loop
    while (running_) {
        // Display prompt
        std::string prompt = isVaultOpen_ ? 
            formatWithColor("securepass> ", "prompt") : 
            formatWithColor("securepass (locked)> ", "warning");
        
        std::cout << prompt;
        
        // Get user input
        std::string input;
        std::getline(std::cin, input);
        
        if (std::cin.eof()) {
            // Ctrl+D or Ctrl+Z (EOF) was pressed
            running_ = false;
            continue;
        }
        
        // Process the command
        if (!input.empty()) {
            processCommand(input);
        }
    }
    
    return 0;
}

// Process a command
bool CLI::processCommand(const std::string& command) {
    // Split the command into arguments
    std::vector<std::string> args;
    std::string arg;
    bool inQuotes = false;
    
    for (size_t i = 0; i < command.size(); ++i) {
        char c = command[i];
        
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (c == ' ' && !inQuotes) {
            if (!arg.empty()) {
                args.push_back(arg);
                arg.clear();
            }
        } else {
            arg += c;
        }
    }
    
    if (!arg.empty()) {
        args.push_back(arg);
    }
    
    if (args.empty()) {
        return true;
    }
    
    // Get the command and convert to lowercase
    std::string cmd = args[0];
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
    
    // Remove the command from args
    args.erase(args.begin());
    
    // Find and execute the command handler
    auto it = commandHandlers_.find(cmd);
    if (it != commandHandlers_.end()) {
        return it->second(args);
    } else {
        printError("Unknown command: " + cmd);
        std::cout << "Type " << formatWithColor("help", "command") << " for a list of commands." << std::endl;
        return true;
    }
}

// Show help information
void CLI::showHelp(const std::string& command) {
    if (command.empty()) {
        // Show general help
        std::cout << formatWithColor("\nAvailable Commands:\n", "bold");
        
        // Group commands by category
        std::map<std::string, std::vector<std::string>> commandsByCategory = {
            {"Vault Management", {"create", "open", "close", "masterpass"}},
            {"Password Management", {"add", "edit", "delete", "get", "list", "search"}},
            {"Tools", {"generate", "analyze", "copy"}},
            {"Import/Export", {"export", "import"}},
            {"Security", {"2fa"}},
            {"Settings", {"settings", "help", "quit"}}
        };
        
        for (const auto& [category, commands] : commandsByCategory) {
            std::cout << formatWithColor("\n" + category + ":", "header") << std::endl;
            
            for (const auto& cmd : commands) {
                std::string helpText = helpText_.count(cmd) ? helpText_.at(cmd) : "No help available";
                std::cout << "  " << formatWithColor(cmd, "command") 
                        << std::string(15 - cmd.length(), ' ') 
                        << helpText << std::endl;
            }
        }
        
        std::cout << "\nFor detailed help on a specific command, type: "
                 << formatWithColor("help <command>", "command") << std::endl;
    } else {
        // Show help for a specific command
        std::string cmd = command;
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
        
        if (helpText_.count(cmd)) {
            std::cout << formatWithColor("\nCommand: ", "bold") << formatWithColor(cmd, "command") << std::endl;
            std::cout << helpText_.at(cmd) << std::endl;
            
            // Additional usage information
            if (cmd == "create") {
                std::cout << "\nUsage: " << formatWithColor("create [path]", "command") << std::endl;
                std::cout << "Creates a new password vault at the specified path (or the default location)." << std::endl;
            } else if (cmd == "open") {
                std::cout << "\nUsage: " << formatWithColor("open [path]", "command") << std::endl;
                std::cout << "Opens an existing password vault at the specified path (or the default location)." << std::endl;
            } else if (cmd == "add") {
                std::cout << "\nUsage: " << formatWithColor("add", "command") << std::endl;
                std::cout << "Adds a new password entry. You'll be prompted for the details." << std::endl;
            } else if (cmd == "generate") {
                std::cout << "\nUsage: " << formatWithColor("generate [length] [options]", "command") << std::endl;
                std::cout << "Options:\n"
                         << "  --no-upper    Exclude uppercase letters\n"
                         << "  --no-lower    Exclude lowercase letters\n"
                         << "  --no-digits   Exclude digits\n"
                         << "  --no-symbols  Exclude symbols\n"
                         << "  --pronounce   Generate a pronounceable password\n"
                         << "  --phrase      Generate a passphrase\n" << std::endl;
            }
        } else {
            printError("No help available for command: " + cmd);
        }
    }
}

// Set color mode
void CLI::setColorMode(const std::string& mode) {
    if (mode == "normal") {
        colorMode_ = ColorMode::NORMAL;
        printSuccess("Color mode set to normal");
    } else if (mode == "colorful") {
        colorMode_ = ColorMode::COLORFUL;
        printSuccess("Color mode set to colorful");
    } else if (mode == "high-contrast") {
        colorMode_ = ColorMode::HIGH_CONTRAST;
        printSuccess("Color mode set to high-contrast");
    } else {
        printError("Invalid color mode: " + mode);
        std::cout << "Available modes: normal, colorful, high-contrast" << std::endl;
    }
    
    // Re-initialize colors with the new mode
    initializeColors();
}

// Initialize command handlers and help text
void CLI::initializeCommands() {
    // Define command handlers
    commandHandlers_["create"] = [this](const std::vector<std::string>& args) {
        return handleCreateVault(args);
    };
    
    commandHandlers_["open"] = [this](const std::vector<std::string>& args) {
        return handleOpenVault(args);
    };
    
    commandHandlers_["close"] = [this](const std::vector<std::string>& args) {
        return handleCloseVault(args);
    };
    
    commandHandlers_["masterpass"] = [this](const std::vector<std::string>& args) {
        return handleChangeMasterPassword(args);
    };
    
    commandHandlers_["add"] = [this](const std::vector<std::string>& args) {
        return handleAdd(args);
    };
    
    commandHandlers_["edit"] = [this](const std::vector<std::string>& args) {
        return handleEdit(args);
    };
    
    commandHandlers_["delete"] = [this](const std::vector<std::string>& args) {
        return handleDelete(args);
    };
    
    commandHandlers_["list"] = [this](const std::vector<std::string>& args) {
        return handleList(args);
    };
    
    commandHandlers_["get"] = [this](const std::vector<std::string>& args) {
        return handleGet(args);
    };
    
    commandHandlers_["search"] = [this](const std::vector<std::string>& args) {
        return handleSearch(args);
    };
    
    commandHandlers_["generate"] = [this](const std::vector<std::string>& args) {
        return handleGenerate(args);
    };
    
    commandHandlers_["analyze"] = [this](const std::vector<std::string>& args) {
        return handleAnalyze(args);
    };
    
    commandHandlers_["copy"] = [this](const std::vector<std::string>& args) {
        return handleCopy(args);
    };
    
    commandHandlers_["export"] = [this](const std::vector<std::string>& args) {
        return handleExport(args);
    };
    
    commandHandlers_["import"] = [this](const std::vector<std::string>& args) {
        return handleImport(args);
    };
    
    commandHandlers_["2fa"] = [this](const std::vector<std::string>& args) {
        return handleSetup2FA(args);
    };
    
    commandHandlers_["settings"] = [this](const std::vector<std::string>& args) {
        return handleSettings(args);
    };
    
    commandHandlers_["help"] = [this](const std::vector<std::string>& args) {
        if (args.empty()) {
            showHelp("");
        } else {
            showHelp(args[0]);
        }
        return true;
    };
    
    commandHandlers_["quit"] = [this](const std::vector<std::string>& args) {
        return handleQuit(args);
    };
    
    commandHandlers_["exit"] = commandHandlers_["quit"];
    
    // Define help text for each command
    helpText_["create"] = "Create a new password vault";
    helpText_["open"] = "Open an existing password vault";
    helpText_["close"] = "Close the current vault";
    helpText_["masterpass"] = "Change the master password";
    helpText_["add"] = "Add a new password entry";
    helpText_["edit"] = "Edit an existing password entry";
    helpText_["delete"] = "Delete a password entry";
    helpText_["list"] = "List all password entries";
    helpText_["get"] = "Show details of a specific password";
    helpText_["search"] = "Search for a password entry";
    helpText_["generate"] = "Generate a new password";
    helpText_["analyze"] = "Analyze the strength of a password";
    helpText_["copy"] = "Copy a password to the clipboard";
    helpText_["export"] = "Export passwords to a file";
    helpText_["import"] = "Import passwords from a file";
    helpText_["2fa"] = "Set up two-factor authentication";
    helpText_["settings"] = "Modify application settings";
    helpText_["help"] = "Show help information";
    helpText_["quit"] = "Exit the application";
    helpText_["exit"] = "Exit the application";
}

// Initialize color schemes
void CLI::initializeColors() {
    // Reset all colors
    colors_.clear();
    
    switch (colorMode_) {
        case ColorMode::NORMAL:
            // Minimal colors
            colors_["reset"] = "\033[0m";
            colors_["bold"] = "\033[1m";
            colors_["error"] = "\033[1m";
            colors_["warning"] = "\033[1m";
            colors_["success"] = "\033[1m";
            colors_["info"] = "\033[1m";
            colors_["prompt"] = "";
            colors_["command"] = "\033[1m";
            colors_["header"] = "\033[1m";
            break;
            
        case ColorMode::HIGH_CONTRAST:
            // High contrast colors
            colors_["reset"] = "\033[0m";
            colors_["bold"] = "\033[1m";
            colors_["error"] = "\033[1;37;41m";  // White on red background
            colors_["warning"] = "\033[1;30;43m"; // Black on yellow background
            colors_["success"] = "\033[1;37;42m"; // White on green background
            colors_["info"] = "\033[1;37;44m";    // White on blue background
            colors_["prompt"] = "\033[1;37m";     // Bright white
            colors_["command"] = "\033[1;37m";    // Bright white
            colors_["header"] = "\033[1;37;40m";  // White on black background
            
            // Password strength colors
            colors_["very_weak"] = "\033[1;37;41m";   // White on red background
            colors_["weak"] = "\033[1;30;43m";        // Black on yellow background
            colors_["moderate"] = "\033[1;30;43m";    // Black on yellow background
            colors_["strong"] = "\033[1;37;42m";      // White on green background
            colors_["very_strong"] = "\033[1;37;42m"; // White on green background
            break;
            
        case ColorMode::COLORFUL:
        default:
            // Default colorful scheme
            colors_["reset"] = "\033[0m";
            colors_["bold"] = "\033[1m";
            colors_["error"] = "\033[1;31m";     // Bright red
            colors_["warning"] = "\033[1;33m";   // Bright yellow
            colors_["success"] = "\033[1;32m";   // Bright green
            colors_["info"] = "\033[1;36m";      // Bright cyan
            colors_["prompt"] = "\033[1;35m";    // Bright magenta
            colors_["command"] = "\033[1;34m";   // Bright blue
            colors_["header"] = "\033[1;37m";    // Bright white
            
            // Password strength colors
            colors_["very_weak"] = "\033[1;31m";  // Bright red
            colors_["weak"] = "\033[1;33m";       // Bright yellow
            colors_["moderate"] = "\033[1;33m";   // Bright yellow
            colors_["strong"] = "\033[1;32m";     // Bright green
            colors_["very_strong"] = "\033[1;32m"; // Bright green
            break;
    }
}

// Get user input, optionally masking for passwords
std::string CLI::getInput(const std::string& prompt, bool isPassword) {
    std::cout << prompt;
    
    if (!isPassword) {
        std::string input;
        std::getline(std::cin, input);
        return input;
    } else {
        // Password input - hide characters
        std::string password;
        
#ifdef _WIN32
        // Windows-specific code to hide input
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hStdin, &mode);
        SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
        
        std::getline(std::cin, password);
        
        // Restore console mode
        SetConsoleMode(hStdin, mode);
#else
        // Unix-specific code to hide input
        termios oldt;
        tcgetattr(STDIN_FILENO, &oldt);
        termios newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        
        std::getline(std::cin, password);
        
        // Restore terminal settings
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
        std::cout << std::endl; // Add a newline after hidden input
        return password;
    }
}

// Get confirmation from user
bool CLI::confirmAction(const std::string& prompt) {
    std::cout << prompt << " (y/n): ";
    std::string input;
    std::getline(std::cin, input);
    
    std::transform(input.begin(), input.end(), input.begin(), ::tolower);
    return input == "y" || input == "yes";
}

// Print status message
void CLI::printStatus(const std::string& message, bool success) {
    if (success) {
        printSuccess(message);
    } else {
        printError(message);
    }
}

// Print error message
void CLI::printError(const std::string& message) {
    std::cout << formatWithColor("Error: " + message, "error") << std::endl;
}

// Print warning message
void CLI::printWarning(const std::string& message) {
    std::cout << formatWithColor("Warning: " + message, "warning") << std::endl;
}

// Print success message
void CLI::printSuccess(const std::string& message) {
    std::cout << formatWithColor("Success: " + message, "success") << std::endl;
}

// Print info message
void CLI::printInfo(const std::string& message) {
    std::cout << formatWithColor("Info: " + message, "info") << std::endl;
}

// Format text with color
std::string CLI::formatWithColor(const std::string& text, const std::string& colorName) {
    if (colors_.count(colorName)) {
        return colors_.at(colorName) + text + colors_.at("reset");
    }
    return text;
}

// Get password strength color
std::string CLI::getPasswordStrengthColor(double strength) {
    if (strength < 0.2) return formatWithColor("Very Weak", "very_weak");
    if (strength < 0.4) return formatWithColor("Weak", "weak");
    if (strength < 0.6) return formatWithColor("Moderate", "moderate");
    if (strength < 0.8) return formatWithColor("Strong", "strong");
    return formatWithColor("Very Strong", "very_strong");
}

// Command handlers (basic implementations)

bool CLI::handleCreateVault(const std::vector<std::string>& args) {
    if (!manager_) {
        printError("Password manager not initialized");
        return true;
    }
    
    if (isVaultOpen_) {
        if (!confirmAction("A vault is already open. Close it and create a new one?")) {
            return true;
        }
        manager_->lockVault();
        isVaultOpen_ = false;
    }
    
    std::string dbPath = args.empty() ? "passwords.db" : args[0];
    
    std::string masterPassword = getInput("Enter new master password: ", true);
    std::string confirmPassword = getInput("Confirm master password: ", true);
    
    if (masterPassword != confirmPassword) {
        printError("Passwords do not match");
        return true;
    }
    
    if (masterPassword.length() < 8) {
        printWarning("Master password is too short (minimum 8 characters)");
        if (!confirmAction("Continue anyway?")) {
            return true;
        }
    }
    
    std::cout << "Creating new vault... ";
    
    if (manager_->createVault(masterPassword, dbPath)) {
        std::cout << "Done!" << std::endl;
        printSuccess("Vault created successfully at " + dbPath);
        isVaultOpen_ = true;
        return true;
    } else {
        std::cout << "Failed!" << std::endl;
        printError("Failed to create vault");
        return true;
    }
}

bool CLI::handleOpenVault(const std::vector<std::string>& args) {
    if (!manager_) {
        printError("Password manager not initialized");
        return true;
    }
    
    if (isVaultOpen_) {
        if (!confirmAction("A vault is already open. Close it and open a different one?")) {
            return true;
        }
        manager_->lockVault();
        isVaultOpen_ = false;
    }
    
    std::string dbPath = args.empty() ? "passwords.db" : args[0];
    
    if (!manager_->initialize(dbPath)) {
        printError("Failed to initialize vault at " + dbPath);
        return true;
    }
    
    std::string masterPassword = getInput("Enter master password: ", true);
    
    std::cout << "Unlocking vault... ";
    
    if (manager_->unlockVault(masterPassword)) {
        std::cout << "Done!" << std::endl;
        printSuccess("Vault unlocked successfully");
        isVaultOpen_ = true;
        return true;
    } else {
        std::cout << "Failed!" << std::endl;
        printError("Failed to unlock vault (wrong password?)");
        return true;
    }
}

bool CLI::handleCloseVault(const std::vector<std::string>& args) {
    if (!manager_) {
        printError("Password manager not initialized");
        return true;
    }
    
    if (!isVaultOpen_) {
        printError("No vault is currently open");
        return true;
    }
    
    manager_->lockVault();
    isVaultOpen_ = false;
    printSuccess("Vault has been locked");
    return true;
}

bool CLI::handleChangeMasterPassword(const std::vector<std::string>& args) {
    if (!manager_) {
        printError("Password manager not initialized");
        return true;
    }
    
    if (!isVaultOpen_) {
        printError("No vault is currently open");
        return true;
    }
    
    std::string currentPassword = getInput("Enter current master password: ", true);
    std::string newPassword = getInput("Enter new master password: ", true);
    std::string confirmPassword = getInput("Confirm new master password: ", true);
    
    if (newPassword != confirmPassword) {
        printError("Passwords do not match");
        return true;
    }
    
    if (newPassword.length() < 8) {
        printWarning("Master password is too short (minimum 8 characters)");
        if (!confirmAction("Continue anyway?")) {
            return true;
        }
    }
    
    std::cout << "Changing master password... ";
    
    if (manager_->changeMasterPassword(currentPassword, newPassword)) {
        std::cout << "Done!" << std::endl;
        printSuccess("Master password changed successfully");
        return true;
    } else {
        std::cout << "Failed!" << std::endl;
        printError("Failed to change master password (wrong current password?)");
        return true;
    }
}

bool CLI::handleAdd(const std::vector<std::string>& args) {
    if (!manager_) {
        printError("Password manager not initialized");
        return true;
    }
    
    if (!isVaultOpen_) {
        printError("No vault is currently open");
        return true;
    }
    
    PasswordManager::PasswordEntry entry;
    
    // Set creation and modification time
    entry.created = std::chrono::system_clock::now();
    entry.modified = entry.created;
    
    // Get the entry details
    entry.title = getInput("Title: ");
    entry.username = getInput("Username: ");
    
    std::string password = getInput("Password (Press Enter to generate): ", true);
    if (password.empty()) {
        // Generate a password
        std::cout << "Generating password..." << std::endl;
        password = manager_->generatePassword(16, true, true, true, true);
        std::cout << "Generated password: " << password << std::endl;
    }
    entry.password = password;
    
    entry.url = getInput("URL: ");
    entry.notes = getInput("Notes: ");
    entry.category = getInput("Category: ");
    
    std::string tags = getInput("Tags (comma separated): ");
    std::stringstream ss(tags);
    std::string tag;
    while (std::getline(ss, tag, ',')) {
        // Trim whitespace
        tag.erase(0, tag.find_first_not_of(" \t\n\r\f\v"));
        tag.erase(tag.find_last_not_of(" \t\n\r\f\v") + 1);
        
        if (!tag.empty()) {
            entry.tags.push_back(tag);
        }
    }
    
    // Ask for expiry date
    std::string expiryStr = getInput("Expiry date (YYYY-MM-DD, empty for none): ");
    if (!expiryStr.empty()) {
        // Parse the date
        std::regex dateRegex(R"(\d{4}-\d{2}-\d{2})");
        if (std::regex_match(expiryStr, dateRegex)) {
            std::tm tm = {};
            std::istringstream ss(expiryStr);
            ss >> std::get_time(&tm, "%Y-%m-%d");
            
            if (!ss.fail()) {
                entry.expiry = std::chrono::system_clock::from_time_t(std::mktime(&tm));
            } else {
                printWarning("Invalid date format, expiry not set");
            }
        } else {
            printWarning("Invalid date format, expiry not set");
        }
    }
    
    std::cout << "Adding password entry... ";
    
    if (manager_->addPassword(entry)) {
        std::cout << "Done!" << std::endl;
        printSuccess("Password entry added successfully");
        return true;
    } else {
        std::cout << "Failed!" << std::endl;
        printError("Failed to add password entry");
        return true;
    }
}

bool CLI::handleGenerateAndExit() {
    running_ = false;
    return false;
}

bool CLI::handleQuit(const std::vector<std::string>& args) {
    if (isVaultOpen_) {
        if (confirmAction("A vault is currently open. Lock it and exit?")) {
            manager_->lockVault();
            isVaultOpen_ = false;
            running_ = false;
            return false;
        }
        return true;
    }
    
    running_ = false;
    return false;
} 