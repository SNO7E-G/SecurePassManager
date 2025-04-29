#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <iostream>

#include "passwordmanager.h"

/**
 * Defines UI/UX color themes for the application
 */
enum class UITheme {
    DEFAULT,        // Standard theme
    DARK,           // Dark mode theme
    LIGHT,          // Light mode theme
    HIGH_CONTRAST,  // High contrast for accessibility
    COLORBLIND,     // Colorblind-friendly mode
    CUSTOM          // Custom user-defined theme
};

/**
 * Keyboard shortcut mapping structure
 */
struct KeyboardShortcut {
    std::string key;
    std::string description;
    std::string command;
};

/**
 * Class for handling command-line interface and user interaction
 * Enhanced with modern UI/UX elements and accessibility features
 */
class CLI {
public:
    CLI(PasswordManager* manager);
    ~CLI();
    
    /**
     * Start the CLI application
     * @return The exit code
     */
    int run();
    
    /**
     * Process a command from the user
     * @param command The command to process
     * @return True if the application should continue, false to exit
     */
    bool processCommand(const std::string& command);
    
    /**
     * Display help information
     * @param command The command to show help for (or empty for general help)
     */
    void showHelp(const std::string& command = "");
    
    /**
     * Set color mode/theme
     * @param theme The theme to set
     */
    void setTheme(UITheme theme);
    
    /**
     * Set custom theme colors
     * @param colors Map of color names to ANSI color codes
     */
    void setCustomTheme(const std::map<std::string, std::string>& colors);
    
    /**
     * Enable or disable animated transitions
     * @param enabled Whether animations should be enabled
     */
    void setAnimations(bool enabled);
    
    /**
     * Set UI display mode
     * @param compact Whether to use compact mode
     */
    void setCompactMode(bool compact);
    
    /**
     * Enable or disable keyboard shortcuts
     * @param enabled Whether shortcuts should be enabled
     */
    void setShortcutsEnabled(bool enabled);
    
    /**
     * Set custom keyboard shortcuts
     * @param shortcuts Map of shortcut keys to commands
     */
    void setCustomShortcuts(const std::map<std::string, std::string>& shortcuts);
    
    /**
     * Display notification or alert to user
     * @param message The message to display
     * @param type The type of notification (info, warning, error, success)
     * @param timeout How long to display (-1 for until dismissed)
     */
    void showNotification(const std::string& message, const std::string& type, int timeout = -1);
    
    /**
     * Enable progress indicator for long operations
     * @param message The message to display during operation
     * @param total Total units of work (for percentage calculations)
     * @return Progress handler ID
     */
    int startProgress(const std::string& message, int total = 100);
    
    /**
     * Update progress indicator
     * @param id The progress handler ID
     * @param current Current progress value
     * @param message Optional updated message
     */
    void updateProgress(int id, int current, const std::string& message = "");
    
    /**
     * End progress indicator
     * @param id The progress handler ID
     */
    void endProgress(int id);

private:
    PasswordManager* manager_; // Pointer to the password manager
    bool running_; // Flag to indicate if the CLI is running
    bool isVaultOpen_; // Flag to indicate if a vault is open
    
    // UI/UX settings
    UITheme currentTheme_;
    bool animationsEnabled_;
    bool compactMode_;
    bool shortcutsEnabled_;
    
    // Keyboard shortcuts mapping
    std::map<std::string, KeyboardShortcut> shortcuts_;
    
    // Progress indicators
    struct ProgressIndicator {
        std::string message;
        int total;
        int current;
        bool active;
    };
    
    std::map<int, ProgressIndicator> progressIndicators_;
    int nextProgressId_;
    
    // Command handlers
    using CommandHandler = std::function<bool(const std::vector<std::string>&)>;
    std::map<std::string, CommandHandler> commandHandlers_;
    
    // Terminal colors
    std::map<std::string, std::string> colors_;
    
    // Help text for each command
    std::map<std::string, std::string> helpText_;
    
    // Command aliases for better UX
    std::map<std::string, std::string> commandAliases_;
    
    // Initialize command handlers and help text
    void initializeCommands();
    
    // Initialize color schemes
    void initializeColors();
    
    // Initialize keyboard shortcuts
    void initializeShortcuts();
    
    // Helper methods for user interaction
    std::string getInput(const std::string& prompt, bool isPassword = false);
    bool confirmAction(const std::string& prompt);
    void printStatus(const std::string& message, bool success = true);
    void printError(const std::string& message);
    void printWarning(const std::string& message);
    void printSuccess(const std::string& message);
    void printInfo(const std::string& message);
    
    // Interactive menu helpers
    void showInteractiveMenu(const std::string& title, const std::vector<std::string>& options);
    int getMenuSelection(int numOptions);
    
    // Command handlers
    bool handleCreateVault(const std::vector<std::string>& args);
    bool handleOpenVault(const std::vector<std::string>& args);
    bool handleCloseVault(const std::vector<std::string>& args);
    bool handleChangeMasterPassword(const std::vector<std::string>& args);
    bool handleAdd(const std::vector<std::string>& args);
    bool handleEdit(const std::vector<std::string>& args);
    bool handleDelete(const std::vector<std::string>& args);
    bool handleList(const std::vector<std::string>& args);
    bool handleGet(const std::vector<std::string>& args);
    bool handleSearch(const std::vector<std::string>& args);
    bool handleGenerate(const std::vector<std::string>& args);
    bool handleAnalyze(const std::vector<std::string>& args);
    bool handleCopy(const std::vector<std::string>& args);
    bool handleExport(const std::vector<std::string>& args);
    bool handleImport(const std::vector<std::string>& args);
    bool handleSetup2FA(const std::vector<std::string>& args);
    bool handleSettings(const std::vector<std::string>& args);
    bool handleQuit(const std::vector<std::string>& args);
    bool handleTheme(const std::vector<std::string>& args);
    bool handleShortcuts(const std::vector<std::string>& args);
    bool handleFavorites(const std::vector<std::string>& args);
    bool handleAutoFill(const std::vector<std::string>& args);
    bool handleSync(const std::vector<std::string>& args);
    bool handleBackup(const std::vector<std::string>& args);
    
    // Helper for displaying password entries
    void displayPasswordEntry(const PasswordManager::PasswordEntry& entry, bool showPassword = false);
    void displayPasswordList(const std::vector<PasswordManager::PasswordEntry>& entries);
    
    // Tab completion
    std::vector<std::string> getCompletions(const std::string& prefix);
    
    // Keyboard shortcuts handling
    void handleKeyboardShortcut(const std::string& key);
    
    // Formatting helpers
    std::string formatWithColor(const std::string& text, const std::string& colorName);
    std::string getPasswordStrengthColor(double strength);
    
    // Animation helpers
    void animateText(const std::string& text, int delayMs = 5);
    void showSpinner(const std::string& message, int durationMs);
    
    // Interactive password generation
    std::string interactivePasswordGeneration();
    
    // Interactive strength analysis
    void interactiveStrengthAnalysis();
    
    // Password entry management helpers
    PasswordManager::PasswordEntry editPasswordInteractively(const PasswordManager::PasswordEntry& entry);
    void bulkTagsOperation(const std::vector<int>& entryIds, const std::string& operation);
    
    // Clipboard management with security timeout
    void setClipboardWithTimeout(const std::string& text, int timeoutSeconds);
}; 