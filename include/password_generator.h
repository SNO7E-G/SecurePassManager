#pragma once

#include <string>
#include <vector>
#include <random>
#include <functional>
#include <memory>
#include <map>

/**
 * Class for generating various types of passwords with advanced generation algorithms
 */
class PasswordGenerator {
public:
    /**
     * Generation method to use
     */
    enum class Method {
        RANDOM,           // Standard random generation
        PRONOUNCEABLE,    // Pronounceable syllables
        DICEWARE,         // Diceware words
        MARKOV,           // Markov chain based
        XKCD,             // XKCD style (correct-horse-battery-staple)
        EMOJI,            // With emoji characters
        QUANTUM,          // Using quantum random sources if available
        NEURAL,           // AI-assisted password generation
        BLOCKCHAIN        // Blockchain compatible seed phrase
    };

    /**
     * Formatting options for generated passwords
     */
    struct FormatOptions {
        bool capitalizeFirst = false;     // Capitalize first letter of words
        bool insertSpaces = true;         // Insert spaces between words/components
        bool insertNumbers = false;       // Insert random numbers
        bool insertSymbols = false;       // Insert random symbols
        int minLength = 8;                // Minimum total length
        int maxLength = 64;               // Maximum total length
        bool leet = false;                // Use leet speak replacements
        bool multiLanguage = false;       // Use multiple languages for passphrases
        std::string language = "en";      // Default language for wordlists
    };

    PasswordGenerator();
    ~PasswordGenerator();
    
    /**
     * Generate a random password with specified characteristics
     * @param length The length of the password
     * @param includeUpper Include uppercase letters
     * @param includeLower Include lowercase letters
     * @param includeNumbers Include numbers
     * @param includeSymbols Include symbols
     * @return The generated password
     */
    std::string generatePassword(int length, 
                                bool includeUpper = true, 
                                bool includeLower = true,
                                bool includeNumbers = true, 
                                bool includeSymbols = true);
    
    /**
     * Generate a pronounceable password
     * @param wordCount Number of syllables or components
     * @return The generated pronounceable password
     */
    std::string generatePronounceable(int wordCount = 3);
    
    /**
     * Generate a passphrase using diceware or similar wordlist
     * @param wordCount Number of words in the passphrase
     * @return The generated passphrase
     */
    std::string generatePassphrase(int wordCount = 5);
    
    /**
     * Generate a PIN code
     * @param length The length of the PIN
     * @return The generated PIN
     */
    std::string generatePIN(int length = 4);
    
    /**
     * Generate a password using a specific method
     * @param method The generation method to use
     * @param complexity The complexity level (1-5)
     * @param options Formatting options
     * @return The generated password
     */
    std::string generateWithMethod(Method method, int complexity = 3, 
                                  const FormatOptions& options = FormatOptions());
    
    /**
     * Generate an XKCD-style passphrase (correct-horse-battery-staple)
     * @param wordCount Number of words
     * @param options Formatting options
     * @return The generated passphrase
     */
    std::string generateXkcdStyle(int wordCount = 4, const FormatOptions& options = FormatOptions());
    
    /**
     * Generate a password using Markov chain model for more realistic pronounceable passwords
     * @param length Approximate length
     * @param order Markov chain order (1-3)
     * @return The generated password
     */
    std::string generateMarkovPassword(int length = 12, int order = 2);
    
    /**
     * Generate a password containing emoji characters
     * @param length Number of characters
     * @param emojiCount Number of emoji to include
     * @return The generated password
     */
    std::string generateWithEmoji(int length = 12, int emojiCount = 2);
    
    /**
     * Generate a quantum-random password if quantum sources available
     * @param length Password length
     * @param fallback Whether to fall back to pseudo-random if quantum not available
     * @return The generated password
     */
    std::string generateQuantumRandom(int length = 16, bool fallback = true);
    
    /**
     * Generate a neural network assisted password
     * @param length Approximate password length
     * @param adaptToRequirements Whether to adapt to common password requirements
     * @return The generated password
     */
    std::string generateNeuralPassword(int length = 16, bool adaptToRequirements = true);
    
    /**
     * Generate a blockchain-compatible seed phrase
     * @param wordCount Number of words (12, 15, 18, 21, 24)
     * @param bip39Compatible Whether to follow BIP-39 standard
     * @return The generated seed phrase
     */
    std::string generateBlockchainSeed(int wordCount = 12, bool bip39Compatible = true);
    
    /**
     * Generate a multi-language passphrase
     * @param wordCount Total number of words
     * @param languages List of language codes to use (e.g., "en", "es", "fr")
     * @return The generated multi-language passphrase
     */
    std::string generateMultiLanguagePassphrase(int wordCount, 
                                              const std::vector<std::string>& languages);
    
    /**
     * Set a custom character set for password generation
     * @param charSet The custom character set
     */
    void setCustomCharSet(const std::string& charSet);
    
    /**
     * Set a custom word list for passphrase generation
     * @param wordList Vector of words to use
     */
    void setCustomWordList(const std::vector<std::string>& wordList);
    
    /**
     * Load a wordlist from a file
     * @param filePath Path to the wordlist file
     * @return True if loading succeeded
     */
    bool loadWordListFromFile(const std::string& filePath);
    
    /**
     * Get available wordlists
     * @return Map of wordlist name to description
     */
    std::map<std::string, std::string> getAvailableWordlists() const;
    
    /**
     * Select a specific wordlist by name
     * @param name Name of the wordlist
     * @return True if wordlist was selected
     */
    bool selectWordlist(const std::string& name);
    
    /**
     * Load a wordlist for a specific language
     * @param languageCode ISO language code (e.g., "en", "es", "fr")
     * @return True if loading succeeded
     */
    bool loadLanguageWordlist(const std::string& languageCode);
    
    /**
     * Get a method name as string
     * @param method The generation method
     * @return The method name
     */
    static std::string methodToString(Method method);

private:
    // Default character sets
    static const std::string UPPERCASE_CHARS;
    static const std::string LOWERCASE_CHARS;
    static const std::string NUMBER_CHARS;
    static const std::string SYMBOL_CHARS;
    static const std::string EMOJI_CHARS;
    
    // Word components for pronounceable passwords
    static const std::vector<std::string> CONSONANTS;
    static const std::vector<std::string> VOWELS;
    
    // Custom character set if specified
    std::string customCharSet_;
    
    // Word list for passphrases
    std::vector<std::string> wordList_;
    std::map<std::string, std::vector<std::string>> availableWordlists_;
    std::string currentWordlistName_;
    
    // Multi-language support
    std::map<std::string, std::vector<std::string>> languageWordlists_;
    
    // Markov chain model data
    std::map<std::string, std::vector<std::pair<char, double>>> markovModel_;
    bool markovModelInitialized_;
    
    // Neural model data
    bool neuralModelInitialized_;
    
    // BIP-39 wordlist for blockchain compatibility
    std::vector<std::string> bip39Wordlist_;
    bool bip39Initialized_;
    
    // Random number generator
    std::mt19937 rng_;
    
    // Helper methods
    std::string getCharSet(bool includeUpper, bool includeLower,
                          bool includeNumbers, bool includeSymbols);
    
    std::string getRandomString(const std::string& charSet, int length);
    
    std::string getRandomWord();
    std::string getRandomWord(const std::string& language);
    
    // Initialize the Markov model
    void initializeMarkovModel(int order = 2);
    
    // Initialize the neural model for AI assistance
    void initializeNeuralModel();
    
    // Initialize BIP-39 wordlist
    void initializeBip39Wordlist();
    
    // Apply formatting options to a generated password
    std::string applyFormatting(const std::string& password, const FormatOptions& options);
    
    // Check for potential quantum random sources
    bool hasQuantumRandomSource() const;
    
    // Calculate entropy of the generated password
    double calculateEntropy(const std::string& password) const;
    
    // Apply leet speak transformations
    std::string applyLeetSpeak(const std::string& input);
}; 