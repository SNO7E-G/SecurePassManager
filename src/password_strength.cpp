#include "password_strength.h"
#include <algorithm>
#include <cmath>
#include <regex>
#include <set>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <curl/curl.h>
#include <openssl/sha.h>

// Common password prefixes for the 10,000 most common passwords
// These would typically be loaded from a file, but for brevity we'll include a small sample
const std::set<std::string> COMMON_PASSWORDS = {
    "password", "123456", "12345678", "1234", "qwerty", "admin", "welcome", 
    "monkey", "login", "abc123", "letmein", "dragon", "baseball", "football",
    "shadow", "master", "superman", "trustno1", "hello", "freedom"
};

// Common patterns for keyboard sequences
const std::vector<std::string> KEYBOARD_SEQUENCES = {
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
    "qazwsxedc", "plmoknijb", "azsxdcfvgbhnjmk"
};

// Constructor
PasswordStrength::PasswordStrength() : hibpApiKey_("") {
    // Nothing to initialize for now
}

// Destructor
PasswordStrength::~PasswordStrength() {
    // Nothing to clean up
}

// Evaluate password strength
double PasswordStrength::evaluatePassword(const std::string& password) {
    if (password.empty()) {
        return 0.0;
    }
    
    // Compute individual scores (0-1 scale)
    double lengthScore = checkLength(password);
    double charSetScore = checkCharacterSets(password);
    double patternScore = checkPatterns(password);
    double commonScore = checkCommonPasswords(password);
    double repetitionScore = checkRepetition(password);
    double sequenceScore = checkSequences(password);
    
    // Calculate entropy
    double entropy = calculateEntropy(password);
    double entropyScore = std::min(entropy / 100.0, 1.0);
    
    // Weights for different criteria (sum to 1.0)
    const double lengthWeight = 0.2;
    const double charSetWeight = 0.2;
    const double patternWeight = 0.15;
    const double commonWeight = 0.15;
    const double repetitionWeight = 0.1;
    const double sequenceWeight = 0.1;
    const double entropyWeight = 0.1;
    
    // Calculate weighted average
    double score = lengthScore * lengthWeight +
                  charSetScore * charSetWeight +
                  patternScore * patternWeight +
                  commonScore * commonWeight +
                  repetitionScore * repetitionWeight +
                  sequenceScore * sequenceWeight +
                  entropyScore * entropyWeight;
    
    // Account for very short passwords
    if (password.length() < 4) {
        score *= 0.5;
    }
    
    // Ensure score is in range 0-1
    return std::max(0.0, std::min(1.0, score));
}

// Get strength category
PasswordStrength::Strength PasswordStrength::getStrengthCategory(const std::string& password) {
    double score = evaluatePassword(password);
    
    if (score < 0.2) return Strength::VERY_WEAK;
    if (score < 0.4) return Strength::WEAK;
    if (score < 0.6) return Strength::MODERATE;
    if (score < 0.8) return Strength::STRONG;
    return Strength::VERY_STRONG;
}

// Convert strength category to string
std::string PasswordStrength::strengthToString(Strength strength) {
    switch (strength) {
        case Strength::VERY_WEAK: return "Very Weak";
        case Strength::WEAK: return "Weak";
        case Strength::MODERATE: return "Moderate";
        case Strength::STRONG: return "Strong";
        case Strength::VERY_STRONG: return "Very Strong";
        default: return "Unknown";
    }
}

// Check if password has been breached
bool PasswordStrength::isPasswordBreached(const std::string& password) {
    return checkWithHIBP(password);
}

// Get suggestions to improve a password
std::vector<std::string> PasswordStrength::getPasswordImprovementSuggestions(const std::string& password) {
    std::vector<std::string> suggestions;
    double score = evaluatePassword(password);
    
    // Check length
    if (password.length() < 12) {
        suggestions.push_back("Increase password length to at least 12 characters");
    }
    
    // Check character sets
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSymbol = false;
    for (char c : password) {
        if (std::isupper(c)) hasUpper = true;
        else if (std::islower(c)) hasLower = true;
        else if (std::isdigit(c)) hasDigit = true;
        else hasSymbol = true;
    }
    
    if (!hasUpper) {
        suggestions.push_back("Add uppercase letters (A-Z)");
    }
    
    if (!hasLower) {
        suggestions.push_back("Add lowercase letters (a-z)");
    }
    
    if (!hasDigit) {
        suggestions.push_back("Add digits (0-9)");
    }
    
    if (!hasSymbol) {
        suggestions.push_back("Add special symbols (!@#$%^&*...)");
    }
    
    // Check for common passwords
    if (checkCommonPasswords(password) < 0.5) {
        suggestions.push_back("Avoid common or easily guessable passwords");
    }
    
    // Check for patterns
    if (checkPatterns(password) < 0.5) {
        suggestions.push_back("Avoid common patterns like 'abc', '123', or 'qwerty'");
    }
    
    // Check for repetition
    if (checkRepetition(password) < 0.7) {
        suggestions.push_back("Avoid repeating characters or sequences");
    }
    
    // Check for sequences
    if (checkSequences(password) < 0.7) {
        suggestions.push_back("Avoid keyboard sequences or adjacent character patterns");
    }
    
    // Add a general suggestion for weak passwords
    if (score < 0.4) {
        suggestions.push_back("Consider using a passphrase or generated password");
    }
    
    return suggestions;
}

// Calculate time to crack
std::map<std::string, std::chrono::seconds> PasswordStrength::getTimeToCrack(const std::string& password) {
    // Estimated number of guesses needed to crack the password
    double guesses = getGuessesForPassword(password);
    
    // Different cracking speeds for different scenarios (guesses per second)
    const double onlineThrottled = 100;       // 100 guesses/second (online service with throttling)
    const double onlineUnthrottled = 10000;   // 10k guesses/second (online service without throttling)
    const double offlineSlowHash = 1e6;       // 1M guesses/second (offline attack on slow hash)
    const double offlineFastHash = 1e9;       // 1B guesses/second (offline attack on fast hash)
    const double offlineGPU = 1e11;           // 100B guesses/second (offline attack with GPUs)
    
    // Calculate time to crack in each scenario
    std::map<std::string, std::chrono::seconds> results;
    
    results["Online (Throttled)"] = std::chrono::seconds(static_cast<long long>(guesses / onlineThrottled));
    results["Online (Unthrottled)"] = std::chrono::seconds(static_cast<long long>(guesses / onlineUnthrottled));
    results["Offline (Slow Hash)"] = std::chrono::seconds(static_cast<long long>(guesses / offlineSlowHash));
    results["Offline (Fast Hash)"] = std::chrono::seconds(static_cast<long long>(guesses / offlineFastHash));
    results["Offline (GPU)"] = std::chrono::seconds(static_cast<long long>(guesses / offlineGPU));
    
    return results;
}

// Format crack time
std::string PasswordStrength::formatCrackTime(const std::chrono::seconds& seconds) {
    if (seconds.count() < 60) {
        return std::to_string(seconds.count()) + " seconds";
    }
    
    if (seconds.count() < 3600) {
        auto minutes = std::chrono::duration_cast<std::chrono::minutes>(seconds);
        return std::to_string(minutes.count()) + " minutes";
    }
    
    if (seconds.count() < 86400) {
        auto hours = std::chrono::duration_cast<std::chrono::hours>(seconds);
        return std::to_string(hours.count()) + " hours";
    }
    
    if (seconds.count() < 31536000) {
        auto days = std::chrono::duration_cast<std::chrono::hours>(seconds) / 24;
        return std::to_string(days.count()) + " days";
    }
    
    auto years = std::chrono::duration_cast<std::chrono::hours>(seconds) / 24 / 365;
    
    if (years.count() < 100) {
        return std::to_string(years.count()) + " years";
    }
    
    if (years.count() < 1000000) {
        return std::to_string(years.count() / 1000) + " thousand years";
    }
    
    if (years.count() < 1000000000) {
        return std::to_string(years.count() / 1000000) + " million years";
    }
    
    return std::to_string(years.count() / 1000000000) + " billion years";
}

// Calculate entropy
double PasswordStrength::calculateEntropy(const std::string& password) {
    if (password.empty()) {
        return 0.0;
    }
    
    // Determine character set size
    std::set<char> uniqueChars(password.begin(), password.end());
    int charSetSize = uniqueChars.size();
    
    // Calculate entropy using Shannon's formula: E = L * log_2(C)
    // Where L is length and C is character set size
    double entropy = password.length() * std::log2(charSetSize);
    
    // Reduce entropy for patterns and repetitions
    if (checkPatterns(password) < 0.5) {
        entropy *= 0.8; // 20% reduction for patterns
    }
    
    if (checkRepetition(password) < 0.7) {
        entropy *= 0.9; // 10% reduction for repetition
    }
    
    return entropy;
}

// Check length (returns a score from 0 to 1)
double PasswordStrength::checkLength(const std::string& password) {
    const int minLength = 4;
    const int optimalLength = 20;
    
    int length = password.length();
    
    if (length < minLength) {
        return 0.0;
    }
    
    if (length >= optimalLength) {
        return 1.0;
    }
    
    // Linear scaling between minLength and optimalLength
    return static_cast<double>(length - minLength) / (optimalLength - minLength);
}

// Check character sets (returns a score from 0 to 1)
double PasswordStrength::checkCharacterSets(const std::string& password) {
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSymbol = false;
    
    for (char c : password) {
        if (std::isupper(c)) hasUpper = true;
        else if (std::islower(c)) hasLower = true;
        else if (std::isdigit(c)) hasDigit = true;
        else hasSymbol = true;
    }
    
    int setCount = hasUpper + hasLower + hasDigit + hasSymbol;
    return setCount / 4.0;
}

// Check for common patterns (returns a score from 0 to 1, where 1 is good)
double PasswordStrength::checkPatterns(const std::string& password) {
    std::string lower = password;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Check for date patterns (MMDDYYYY, DDMMYYYY, MMDDYY, DDMMYY)
    std::regex datePattern1("\\d{8}");
    std::regex datePattern2("\\d{6}");
    std::regex datePattern3("\\d{1,2}[/.-]\\d{1,2}[/.-]\\d{2,4}");
    
    if (std::regex_search(lower, datePattern1) || 
        std::regex_search(lower, datePattern2) || 
        std::regex_search(lower, datePattern3)) {
        return 0.3;
    }
    
    // Check for alphabetic sequences (abc, xyz, etc.)
    std::string alphabet = "abcdefghijklmnopqrstuvwxyz";
    for (size_t i = 0; i <= alphabet.length() - 3; ++i) {
        std::string sequence = alphabet.substr(i, 3);
        if (lower.find(sequence) != std::string::npos) {
            return 0.4;
        }
        
        // Check for reverse sequences
        std::string reverseSeq = sequence;
        std::reverse(reverseSeq.begin(), reverseSeq.end());
        if (lower.find(reverseSeq) != std::string::npos) {
            return 0.4;
        }
    }
    
    // Check for numeric sequences (123, 987, etc.)
    std::string numbers = "0123456789";
    for (size_t i = 0; i <= numbers.length() - 3; ++i) {
        std::string sequence = numbers.substr(i, 3);
        if (lower.find(sequence) != std::string::npos) {
            return 0.4;
        }
        
        // Check for reverse sequences
        std::string reverseSeq = sequence;
        std::reverse(reverseSeq.begin(), reverseSeq.end());
        if (lower.find(reverseSeq) != std::string::npos) {
            return 0.4;
        }
    }
    
    return 1.0;
}

// Check for common passwords (returns a score from 0 to 1, where 1 is good)
double PasswordStrength::checkCommonPasswords(const std::string& password) {
    std::string lower = password;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Check if the password is in the common passwords set
    if (COMMON_PASSWORDS.find(lower) != COMMON_PASSWORDS.end()) {
        return 0.0;
    }
    
    // Check if the password contains a common password
    for (const auto& common : COMMON_PASSWORDS) {
        if (lower.find(common) != std::string::npos) {
            return 0.2;
        }
    }
    
    return 1.0;
}

// Check for repetition (returns a score from 0 to 1, where 1 is good)
double PasswordStrength::checkRepetition(const std::string& password) {
    if (password.length() < 2) {
        return 1.0;
    }
    
    // Check for repeating characters (aaa, bbb, etc.)
    int maxRepeat = 1;
    int currentRepeat = 1;
    
    for (size_t i = 1; i < password.length(); ++i) {
        if (password[i] == password[i - 1]) {
            currentRepeat++;
        } else {
            maxRepeat = std::max(maxRepeat, currentRepeat);
            currentRepeat = 1;
        }
    }
    
    maxRepeat = std::max(maxRepeat, currentRepeat);
    
    // Penalize more for longer repeats
    if (maxRepeat >= 3) {
        return 0.3;
    } else if (maxRepeat == 2) {
        return 0.7;
    }
    
    // Check for repeating sequences (abcabc, 123123, etc.)
    int pwdLength = password.length();
    for (int seqLen = 2; seqLen <= pwdLength / 2; ++seqLen) {
        for (int i = 0; i <= pwdLength - 2 * seqLen; ++i) {
            std::string seq1 = password.substr(i, seqLen);
            std::string seq2 = password.substr(i + seqLen, seqLen);
            
            if (seq1 == seq2) {
                return 0.4;
            }
        }
    }
    
    return 1.0;
}

// Check for sequences (returns a score from 0 to 1, where 1 is good)
double PasswordStrength::checkSequences(const std::string& password) {
    std::string lower = password;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Check for keyboard sequences
    for (const auto& sequence : KEYBOARD_SEQUENCES) {
        for (size_t i = 0; i <= sequence.length() - 3; ++i) {
            std::string subseq = sequence.substr(i, 3);
            if (lower.find(subseq) != std::string::npos) {
                return 0.4;
            }
            
            // Check for reverse sequences
            std::string reverseSubseq = subseq;
            std::reverse(reverseSubseq.begin(), reverseSubseq.end());
            if (lower.find(reverseSubseq) != std::string::npos) {
                return 0.4;
            }
        }
    }
    
    return 1.0;
}

// Check with Have I Been Pwned API using k-anonymity model
bool PasswordStrength::checkWithHIBP(const std::string& password) {
    // Calculate SHA-1 hash of the password
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), hash);
    
    // Convert hash to uppercase hex string
    std::stringstream ss;
    ss << std::hex << std::uppercase;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::string hashStr = ss.str();
    
    // Get the first 5 characters of the hash (prefix) and the rest (suffix)
    std::string prefix = hashStr.substr(0, 5);
    std::string suffix = hashStr.substr(5);
    
    // Initialize libcurl
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }
    
    // Set up the request
    std::string url = "https://api.pwnedpasswords.com/range/" + prefix;
    std::string response;
    
    // Set up callback function to write received data
    auto writeCallback = [](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        std::string* response = static_cast<std::string*>(userdata);
        response->append(ptr, size * nmemb);
        return size * nmemb;
    };
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        return false; // Request failed
    }
    
    // Parse the response and check if the suffix is found
    std::istringstream iss(response);
    std::string line;
    while (std::getline(iss, line)) {
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            std::string hashSuffix = line.substr(0, pos);
            
            // Compare with our suffix (case-insensitive)
            if (hashSuffix.size() == suffix.size()) {
                bool match = true;
                for (size_t i = 0; i < suffix.size(); i++) {
                    if (std::toupper(hashSuffix[i]) != std::toupper(suffix[i])) {
                        match = false;
                        break;
                    }
                }
                
                if (match) {
                    return true; // Password has been breached
                }
            }
        }
    }
    
    return false; // Password not found in breached database
}

// Helper for getting the number of guesses needed to crack
double PasswordStrength::getGuessesForPassword(const std::string& password) {
    // Calculate the entropy in bits
    double entropy = calculateEntropy(password);
    
    // The number of guesses is 2^entropy
    return std::pow(2, entropy);
} 