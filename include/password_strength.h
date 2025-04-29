#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

/**
 * Class for evaluating password strength and security
 * Implements enhanced entropy calculations, zxcvbn algorithm, and ML-based analysis
 */
class PasswordStrength {
public:
    enum class Strength {
        VERY_WEAK,    // 0-20%
        WEAK,         // 21-40%
        MODERATE,     // 41-60%
        STRONG,       // 61-80%
        VERY_STRONG   // 81-100%
    };

    /**
     * Detailed password analysis results
     */
    struct AnalysisResult {
        double score;                      // 0.0 to 1.0
        Strength strength;                 // Categorical strength
        std::vector<std::string> feedback; // Improvement suggestions
        double entropy;                    // Entropy bits
        std::map<std::string, std::chrono::seconds> crackTimes; // Estimated crack times
        bool breached;                     // Found in breach database
        int matchSequences;                // Number of pattern matches
        std::vector<std::string> weaknesses; // Identified weaknesses
        std::map<std::string, double> subscores; // Detailed subscores
        std::vector<std::string> matchedPatterns; // Patterns found in password
        int passwordAge;                  // Age in days, if provided
        bool isExpiring;                  // Whether password is close to expiration
        double uniquenessScore;           // How unique compared to common passwords
    };
    
    /**
     * Threat model for crack time estimation
     */
    enum class ThreatModel {
        OFFLINE_FAST_HASHING,     // Fast hash (MD5, SHA1) - 10B guesses/sec
        OFFLINE_SLOW_HASHING,     // Slow hash (bcrypt, PBKDF2) - 10K guesses/sec
        ONLINE_THROTTLED,         // Throttled online attack - 100 guesses/sec
        ONLINE_UNTHROTTLED,       // Unthrottled online attack - 10 guesses/sec
        QUANTUM_COMPUTER          // Theoretical quantum computer attack
    };
    
    /**
     * Detection options for password analysis
     */
    struct DetectionOptions {
        bool checkDictionary = true;       // Check against common password dictionaries
        bool detectPatterns = true;        // Look for patterns (keyboard, dates, etc.)
        bool detectRepeats = true;         // Look for repeated characters or sequences
        bool detectLeetSpeak = true;       // Detect leet speak substitutions
        bool detectNamesDates = true;      // Detect names and dates
        bool checkContextual = false;      // Check for contextual information
        bool useNeuralAnalysis = false;    // Use neural network for advanced analysis
    };
    
    PasswordStrength();
    ~PasswordStrength();
    
    /**
     * Evaluate the strength of a password
     * @param password The password to evaluate
     * @return A score from 0.0 to 1.0 representing strength
     */
    double evaluatePassword(const std::string& password);
    
    /**
     * Get the strength category of a password
     * @param password The password to evaluate
     * @return The strength category
     */
    Strength getStrengthCategory(const std::string& password);
    
    /**
     * Get strength category as a string
     * @param strength The strength category
     * @return The category name as a string
     */
    static std::string strengthToString(Strength strength);
    
    /**
     * Check if a password exists in known breached passwords
     * @param password The password to check
     * @param useKAnonymity Whether to use k-anonymity to protect the password
     * @return True if the password has been breached
     */
    bool isPasswordBreached(const std::string& password, bool useKAnonymity = true);
    
    /**
     * Get suggestions to improve a password
     * @param password The password to get suggestions for
     * @return A vector of improvement suggestions
     */
    std::vector<std::string> getPasswordImprovementSuggestions(const std::string& password);
    
    /**
     * Calculate the estimated time to crack a password
     * @param password The password to evaluate
     * @param threatModel The threat model to use for calculation
     * @return A map with different crack time estimates based on attack type
     */
    std::map<std::string, std::chrono::seconds> getTimeToCrack(
        const std::string& password,
        ThreatModel threatModel = ThreatModel::OFFLINE_SLOW_HASHING);
    
    /**
     * Get a formatted description of crack time
     * @param seconds The time in seconds
     * @return A human-readable string (e.g., "2 years, 3 months")
     */
    static std::string formatCrackTime(const std::chrono::seconds& seconds);
    
    /**
     * Calculate entropy bits for a password
     * @param password The password to evaluate
     * @param useZxcvbnMethod Whether to use zxcvbn pattern detection
     * @return The entropy in bits
     */
    double calculateEntropy(const std::string& password, bool useZxcvbnMethod = true);
    
    /**
     * Get comprehensive password analysis
     * @param password The password to analyze
     * @param userContext Optional user context data for contextual analysis
     * @param options Detection options for analysis
     * @return Detailed analysis results
     */
    AnalysisResult analyzePassword(
        const std::string& password,
        const std::map<std::string, std::string>& userContext = {},
        const DetectionOptions& options = DetectionOptions());
    
    /**
     * Set the API key for Have I Been Pwned
     * @param apiKey The API key
     */
    void setHIBPApiKey(const std::string& apiKey);
    
    /**
     * Configure and optimize the strength checking algorithm
     * @param detectPatterns Whether to detect common patterns (slower but more accurate)
     * @param useAI Whether to use machine learning models for analysis
     * @param checkDictionary Whether to check against common password dictionaries
     */
    void configure(bool detectPatterns = true, bool useAI = false, bool checkDictionary = true);
    
    /**
     * Compare password with previous passwords to check for similarity
     * @param password The new password to check
     * @param previousPasswords List of previous passwords to compare against
     * @param similarityThreshold Threshold for similarity (0.0-1.0)
     * @return True if the password is too similar to a previous one
     */
    bool isTooSimilarToPrevious(
        const std::string& password,
        const std::vector<std::string>& previousPasswords,
        double similarityThreshold = 0.7);
    
    /**
     * Check password against common policies
     * @param password The password to check
     * @param policies Map of policy names to required values
     * @return Map of policy names to compliance status
     */
    std::map<std::string, bool> checkPolicyCompliance(
        const std::string& password,
        const std::map<std::string, int>& policies);
    
    /**
     * Check if a password would be vulnerable to emerging threats
     * @param password The password to check
     * @return Map of threat types to vulnerability status
     */
    std::map<std::string, bool> checkEmergingThreats(const std::string& password);
    
    /**
     * Generate a visual representation of password strength
     * @param password The password to visualize
     * @param width Width of the visualization (characters)
     * @param height Height of the visualization (lines)
     * @return ASCII/ANSI visualization of password strength
     */
    std::string visualizePasswordStrength(
        const std::string& password,
        int width = 40,
        int height = 1);
    
    /**
     * Predict how long a password will remain secure
     * @param password The password to evaluate
     * @return Estimated time in days until the password should be changed
     */
    int predictPasswordLifetime(const std::string& password);
    
    /**
     * Get personalized password improvement recommendations
     * @param password The password to analyze
     * @param userPreferences User preferences for recommendations
     * @return Personalized recommendations
     */
    std::vector<std::string> getPersonalizedRecommendations(
        const std::string& password,
        const std::map<std::string, std::string>& userPreferences);
    
private:
    // API key for Have I Been Pwned if used
    std::string hibpApiKey_;
    
    // Configuration options
    bool detectPatterns_;
    bool useAI_;
    bool checkDictionary_;
    
    // Large dictionaries and pattern tables
    std::vector<std::string> commonPasswords_;
    std::map<std::string, double> patternPenalties_;
    
    // Neural network model data
    bool neuralModelInitialized_;
    
    // Check for various weaknesses
    double checkLength(const std::string& password);
    double checkCharacterSets(const std::string& password);
    double checkPatterns(const std::string& password);
    double checkCommonPasswords(const std::string& password);
    double checkRepetition(const std::string& password);
    double checkSequences(const std::string& password);
    double checkLeetSpeak(const std::string& password);
    double checkKeyboardPatterns(const std::string& password);
    double checkContextualInfo(
        const std::string& password,
        const std::map<std::string, std::string>& userInfo);
    double checkNamesAndDates(const std::string& password);
    double checkWordVariations(const std::string& password);
    
    // Advanced pattern detection (zxcvbn-inspired)
    std::vector<std::pair<std::string, std::string>> detectPatterns(const std::string& password);
    
    // Machine learning based evaluation (if enabled)
    double evaluateWithAI(const std::string& password);
    
    // Helper for checking with Have I Been Pwned API
    bool checkWithHIBP(const std::string& password, bool useKAnonymity);
    
    // Helper for getting the number of guesses needed to crack
    double getGuessesForPassword(const std::string& password);
    
    // Load dictionaries and pattern data
    void loadDictionaries();
    
    // Initialize neural model for analysis
    void initializeNeuralModel();
    
    // Calculate similarity between passwords
    double calculatePasswordSimilarity(const std::string& password1, const std::string& password2);
    
    // Get the character set size for a password
    int getCharacterSetSize(const std::string& password);
    
    // Check for emerging threats
    void updateThreatIntelligence();
}; 