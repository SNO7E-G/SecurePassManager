#include <iostream>
#include <string>
#include <memory>
#include <cstdlib>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <thread>
#include <chrono>
#include <stdexcept>

#include "passwordmanager.h"
#include "cli.h"
#include "config.h"

// If there are system header issues, we can add fallback simple declarations
#ifndef __has_include
#define __has_include(x) 0
#endif

#if !__has_include(<filesystem>)
namespace std
{
    namespace filesystem
    {
        bool exists(const std::string &path)
        {
            FILE *file = fopen(path.c_str(), "r");
            if (file)
            {
                fclose(file);
                return true;
            }
            return false;
        }
    }
}
#endif

// Version and build info
const char *VERSION = SECUREPASS_VERSION;
const char *AUTHOR = SECUREPASS_AUTHOR;
const char *BUILD_DATE = __DATE__;
const char *BUILD_TIME = __TIME__;

// Signal handler for secure exit
void signalHandler(int signal)
{
    std::cout << "\nReceived signal " << signal << ". Exiting securely..." << std::endl;
    // Perform secure cleanup here if needed
    std::exit(signal);
}

// Advanced banner with animation support
void printBanner(bool animate = true)
{
// Clear screen for better presentation
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif

    // Animation delay
    const int delay = animate ? 5 : 0;

    const char *bannerLines[] = {
        "\n",
        "  _____                         _____                 ",
        " / ____|                       |  __ \\                ",
        "| (___   ___  ___ _   _ _ __ ___| |__) |_ _ ___ ___ ",
        " \\___ \\ / _ \\/ __| | | | '__/ _ \\  ___/ _` / __/ __|",
        " ____) |  __/ (__| |_| | | |  __/ |  | (_| \\__ \\__ \\",
        "|_____/ \\___|\\___|\\__,_|_|  \\___|_|   \\__,_|___/___/",
        "                                                    ",
        "          Secure Password Manager v" + std::string(VERSION),
        "          Developed by " + std::string(AUTHOR),
        "                                                    ",
        nullptr};

    for (int i = 0; bannerLines[i] != nullptr; i++)
    {
        std::cout << bannerLines[i] << std::endl;
        if (animate)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay * 10));
        }
    }
}

// Print help information
void printHelp(const char *programName)
{
    std::cout << "Usage: " << programName << " [OPTIONS]" << std::endl;
    std::cout << std::endl;

    std::cout << "General Options:" << std::endl;
    std::cout << "  -h, --help                   Show this help message" << std::endl;
    std::cout << "  -v, --version                Show version information" << std::endl;
    std::cout << "  -d, --database PATH          Specify database file path" << std::endl;
    std::cout << "  -c, --command CMD            Execute a single command and exit" << std::endl;
    std::cout << "  -n, --no-animation           Disable animations" << std::endl;
    std::cout << "  -s, --safe-mode              Run in safe mode with minimal features" << std::endl;
    std::cout << "  --reset-config               Reset configuration to defaults" << std::endl;
    std::cout << std::endl;

    std::cout << "UI Options:" << std::endl;
    std::cout << "  --theme THEME                Set UI theme (default, dark, light, high-contrast, colorblind)" << std::endl;
    std::cout << "  --color-mode MODE            Set color mode (full, basic, monochrome)" << std::endl;
    std::cout << "  --font-size SIZE             Set font size" << std::endl;
    std::cout << "  --ui-scale SCALE             Set UI scaling factor (0.5-2.0)" << std::endl;
    std::cout << "  --touch-mode                 Enable touch-optimized UI" << std::endl;
#ifdef HAVE_QT
    std::cout << "  --gui                        Launch with graphical user interface" << std::endl;
#endif
    std::cout << std::endl;

    std::cout << "Security Options:" << std::endl;
    std::cout << "  --encryption ALGO            Set encryption algorithm (aes256, chacha20, twofish, serpent)" << std::endl;
    std::cout << "  --auto-lock MINUTES          Set auto-lock timeout in minutes (0 to disable)" << std::endl;
    std::cout << "  --pbkdf-iterations NUM       Set PBKDF2 iterations" << std::endl;
    std::cout << "  --memory-limit MB            Set memory limit for key derivation (for Argon2)" << std::endl;
#ifdef HAVE_YUBIKEY
    std::cout << "  --yubikey                    Enable YubiKey authentication" << std::endl;
#endif
    std::cout << std::endl;

    std::cout << "Storage & Sync Options:" << std::endl;
    std::cout << "  --auto-backup                Enable automatic backups" << std::endl;
    std::cout << "  --backup-dir PATH            Set backup directory" << std::endl;
    std::cout << "  --backup-count NUM           Set number of backups to keep" << std::endl;
#ifdef HAVE_CLOUD_SYNC
    std::cout << "  --enable-sync                Enable cloud synchronization" << std::endl;
    std::cout << "  --sync-provider PROVIDER     Set sync provider (gdrive, dropbox, onedrive)" << std::endl;
    std::cout << "  --sync-interval MINUTES      Set sync interval in minutes" << std::endl;
#endif
    std::cout << std::endl;

    std::cout << "Import/Export Options:" << std::endl;
    std::cout << "  --import FILE                Import passwords from file" << std::endl;
    std::cout << "  --import-format FORMAT       Set import format (csv, json, xml, keepass, 1password, lastpass)" << std::endl;
    std::cout << "  --export FILE                Export passwords to file" << std::endl;
    std::cout << "  --export-format FORMAT       Set export format (csv, json, xml, keepass)" << std::endl;
    std::cout << std::endl;

    std::cout << "Password Generation Options:" << std::endl;
    std::cout << "  --password-policy POLICY     Set default password policy (high, medium, standard)" << std::endl;
    std::cout << "  --default-length LENGTH      Set default password length for generator" << std::endl;
    std::cout << std::endl;

    std::cout << "Language & Localization:" << std::endl;
    std::cout << "  --language LANG              Set interface language (en, es, fr, de, ja, zh)" << std::endl;
    std::cout << std::endl;
}

// Print version information
void printVersion()
{
    std::cout << "Secure Password Manager v" << VERSION << std::endl;
    std::cout << "Developed by " << AUTHOR << std::endl;
    std::cout << "Build date: " << BUILD_DATE << " " << BUILD_TIME << std::endl;
    std::cout << "License: MIT" << std::endl;

    // Print built-in features
    std::cout << "\nCompiled with support for:" << std::endl;

#ifdef HAVE_TWOFISH
    std::cout << " • Twofish encryption" << std::endl;
#endif
#ifdef HAVE_SERPENT
    std::cout << " • Serpent encryption" << std::endl;
#endif
#ifdef HAVE_CHACHA20_POLY1305
    std::cout << " • ChaCha20-Poly1305 encryption" << std::endl;
#endif
#ifdef HAVE_XCHACHA20_POLY1305
    std::cout << " • XChaCha20-Poly1305 encryption" << std::endl;
#endif
#if Argon2_FOUND
    std::cout << " • Argon2 key derivation" << std::endl;
#endif
#ifdef HAVE_MOBILE_SUPPORT
    std::cout << " • Mobile device support" << std::endl;
#endif
#ifdef HAVE_QT
    std::cout << " • Graphical user interface" << std::endl;
#endif
#ifdef HAVE_HSM
    std::cout << " • Hardware Security Module support" << std::endl;
#endif
#ifdef HAVE_CLOUD_SYNC
    std::cout << " • Cloud synchronization" << std::endl;
#endif
#ifdef HAVE_YUBIKEY
    std::cout << " • YubiKey authentication" << std::endl;
#endif
#ifdef HAVE_WINDOWS_BIOMETRIC_FRAMEWORK
    std::cout << " • Windows Hello biometrics" << std::endl;
#endif
#ifdef HAVE_TOUCH_ID
    std::cout << " • Touch ID / Face ID biometrics" << std::endl;
#endif
#ifdef HAVE_ANDROID_BIOMETRICS
    std::cout << " • Android biometric authentication" << std::endl;
#endif
}

int main(int argc, char *argv[])
{
    // Register signal handlers for secure exit
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // Default settings
    std::string dbPath;
    std::string singleCommand;
    bool noAnimation = false;
    bool safeMode = false;
    std::string theme = "default";
    bool resetConfig = false;

    // UI options
    std::string colorMode = "full";
    int fontSize = DEFAULT_FONT_SIZE;
    float uiScale = DEFAULT_UI_SCALE;
    bool touchMode = DEFAULT_TOUCH_TARGETS;
    bool useGui = false;

    // Security options
    std::string encryptionAlgo = "aes256";
    int autoLockMinutes = DEFAULT_AUTO_LOCK_TIMEOUT / 60;
    int pbkdfIterations = DEFAULT_PBKDF2_ITERATIONS;
    int memoryLimitMB = DEFAULT_ARGON2_MEMORY / 1024;
    bool useYubiKey = false;

    // Storage & sync options
    bool autoBackup = false;
    std::string backupDir;
    int backupCount = DEFAULT_BACKUP_COUNT;
    bool enableSync = false;
    std::string syncProvider;
    int syncInterval = 30;

    // Import/export options
    std::string importFile;
    std::string importFormat = "csv";
    std::string exportFile;
    std::string exportFormat = "csv";

    // Password generation options
    std::string passwordPolicy = "standard";
    int defaultPasswordLength = DEFAULT_PASSWORD_LENGTH;

    // Language options
    std::string language = "en";

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help")
        {
            printHelp(argv[0]);
            return 0;
        }
        else if (arg == "-v" || arg == "--version")
        {
            printVersion();
            return 0;
        }
        else if ((arg == "-d" || arg == "--database") && i + 1 < argc)
        {
            dbPath = argv[++i];
        }
        else if ((arg == "-c" || arg == "--command") && i + 1 < argc)
        {
            singleCommand = argv[++i];
        }
        else if (arg == "-n" || arg == "--no-animation")
        {
            noAnimation = true;
        }
        else if (arg == "-s" || arg == "--safe-mode")
        {
            safeMode = true;
        }
        else if (arg == "--reset-config")
        {
            resetConfig = true;
        }
        // UI options
        else if (arg == "--theme" && i + 1 < argc)
        {
            theme = argv[++i];
        }
        else if (arg == "--color-mode" && i + 1 < argc)
        {
            colorMode = argv[++i];
        }
        else if (arg == "--font-size" && i + 1 < argc)
        {
            fontSize = std::stoi(argv[++i]);
        }
        else if (arg == "--ui-scale" && i + 1 < argc)
        {
            uiScale = std::stof(argv[++i]);
        }
        else if (arg == "--touch-mode")
        {
            touchMode = true;
        }
        else if (arg == "--gui")
        {
            useGui = true;
        }
        // Security options
        else if (arg == "--encryption" && i + 1 < argc)
        {
            encryptionAlgo = argv[++i];
        }
        else if (arg == "--auto-lock" && i + 1 < argc)
        {
            autoLockMinutes = std::stoi(argv[++i]);
        }
        else if (arg == "--pbkdf-iterations" && i + 1 < argc)
        {
            pbkdfIterations = std::stoi(argv[++i]);
        }
        else if (arg == "--memory-limit" && i + 1 < argc)
        {
            memoryLimitMB = std::stoi(argv[++i]);
        }
        else if (arg == "--yubikey")
        {
            useYubiKey = true;
        }
        // Storage & sync options
        else if (arg == "--auto-backup")
        {
            autoBackup = true;
        }
        else if (arg == "--backup-dir" && i + 1 < argc)
        {
            backupDir = argv[++i];
        }
        else if (arg == "--backup-count" && i + 1 < argc)
        {
            backupCount = std::stoi(argv[++i]);
        }
        else if (arg == "--enable-sync")
        {
            enableSync = true;
        }
        else if (arg == "--sync-provider" && i + 1 < argc)
        {
            syncProvider = argv[++i];
        }
        else if (arg == "--sync-interval" && i + 1 < argc)
        {
            syncInterval = std::stoi(argv[++i]);
        }
        // Import/export options
        else if (arg == "--import" && i + 1 < argc)
        {
            importFile = argv[++i];
        }
        else if (arg == "--import-format" && i + 1 < argc)
        {
            importFormat = argv[++i];
        }
        else if (arg == "--export" && i + 1 < argc)
        {
            exportFile = argv[++i];
        }
        else if (arg == "--export-format" && i + 1 < argc)
        {
            exportFormat = argv[++i];
        }
        // Password generation options
        else if (arg == "--password-policy" && i + 1 < argc)
        {
            passwordPolicy = argv[++i];
        }
        else if (arg == "--default-length" && i + 1 < argc)
        {
            defaultPasswordLength = std::stoi(argv[++i]);
        }
        // Language options
        else if (arg == "--language" && i + 1 < argc)
        {
            language = argv[++i];
        }
        else
        {
            std::cerr << "Unknown option: " << arg << std::endl;
            printHelp(argv[0]);
            return 1;
        }
    }

    // Print banner
    printBanner(!noAnimation);

    try
    {
        // Create password manager instance
        auto passwordManager = std::make_shared<PasswordManager>();

        // Configure password manager
        passwordManager->setEncryptionAlgorithm(encryptionAlgo);
        passwordManager->setPBKDFIterations(pbkdfIterations);
        passwordManager->setMemoryLimit(memoryLimitMB * 1024);
        passwordManager->setPasswordPolicy(passwordPolicy);
        passwordManager->setDefaultPasswordLength(defaultPasswordLength);

        if (useYubiKey)
        {
            passwordManager->enableYubiKey();
        }

        if (autoBackup)
        {
            passwordManager->enableAutoBackup(true);
            if (!backupDir.empty())
            {
                passwordManager->setBackupDirectory(backupDir);
            }
            passwordManager->setBackupCount(backupCount);
        }

        // Initialize with database path if provided
        if (!dbPath.empty())
        {
            if (!passwordManager->initialize(dbPath))
            {
                std::cerr << "Failed to initialize password manager with database: " << dbPath << std::endl;
                return 1;
            }
        }

        // Determine if we should use GUI or CLI
#ifdef HAVE_QT
        if (useGui)
        {
            // Initialize GUI (Not implemented in this example)
            std::cout << "GUI mode is not implemented in this version." << std::endl;
            return 1;
        }
#endif

        // Create CLI with the password manager
        CLI cli(passwordManager.get());

        // Configure CLI based on arguments
        if (safeMode)
        {
            std::cout << "Running in safe mode with minimal features" << std::endl;
            // Configure safe mode here
        }

        // Set the theme
        if (theme == "dark")
        {
            cli.setTheme(UITheme::DARK);
        }
        else if (theme == "light")
        {
            cli.setTheme(UITheme::LIGHT);
        }
        else if (theme == "high-contrast")
        {
            cli.setTheme(UITheme::HIGH_CONTRAST);
        }
        else if (theme == "colorblind")
        {
            cli.setTheme(UITheme::COLORBLIND);
        }

        // Set color mode
        cli.setColorMode(colorMode);

        // Set font size and UI scale
        cli.setFontSize(fontSize);
        cli.setUIScale(uiScale);

        // Set touch mode
        cli.setTouchMode(touchMode);

        // Set auto-lock timeout
        cli.setAutoLockTimeout(autoLockMinutes * 60);

        // Configure cloud sync if enabled
        if (enableSync)
        {
            cli.enableSync(true);
            if (!syncProvider.empty())
            {
                cli.setSyncProvider(syncProvider);
            }
            cli.setSyncInterval(syncInterval);
        }

        // Set language
        cli.setLanguage(language);

        // Configure import/export
        cli.setImportFormat(importFormat);
        cli.setExportFormat(exportFormat);

        // Enable/disable animations
        cli.setAnimations(!noAnimation);

        // Reset configuration if requested
        if (resetConfig)
        {
            std::cout << "Resetting configuration to defaults" << std::endl;
            passwordManager->resetToDefaults();
        }

        // Import file if specified
        if (!importFile.empty())
        {
            std::cout << "Importing from " << importFile << " in " << importFormat << " format..." << std::endl;
            if (cli.processCommand("import " + importFile + " " + importFormat))
            {
                std::cout << "Import completed successfully." << std::endl;
            }
            else
            {
                std::cerr << "Import failed." << std::endl;
                return 1;
            }
        }

        // Export file if specified
        if (!exportFile.empty())
        {
            std::cout << "Exporting to " << exportFile << " in " << exportFormat << " format..." << std::endl;
            if (cli.processCommand("export " + exportFile + " " + exportFormat))
            {
                std::cout << "Export completed successfully." << std::endl;
            }
            else
            {
                std::cerr << "Export failed." << std::endl;
                return 1;
            }
        }

        // Process a single command if provided
        if (!singleCommand.empty())
        {
            return cli.processCommand(singleCommand) ? 0 : 1;
        }

        // Start interactive CLI
        return cli.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "Unknown fatal error occurred" << std::endl;
        return 1;
    }
}