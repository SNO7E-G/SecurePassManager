#include "password_generator.h"
#include <random>
#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <chrono>

// Initialize static constants
const std::string PasswordGenerator::UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string PasswordGenerator::LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
const std::string PasswordGenerator::NUMBER_CHARS = "0123456789";
const std::string PasswordGenerator::SYMBOL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?/~";

// Consonants and vowels for pronounceable passwords
const std::vector<std::string> PasswordGenerator::CONSONANTS = {
    "b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "q", "r", "s", "t", "v", "w", "x", "z",
    "bl", "br", "ch", "cl", "cr", "dr", "fl", "fr", "gl", "gr", "ph", "pl", "pr", "sc", "sh", "sk", "sl",
    "sm", "sn", "sp", "st", "sw", "th", "tr", "tw", "wh", "wr"
};

const std::vector<std::string> PasswordGenerator::VOWELS = {
    "a", "e", "i", "o", "u", "y",
    "ae", "ai", "au", "ay", "ea", "ee", "ei", "eu", "ey", "ie", "oa", "oe", "oi", "oo", "ou", "oy", "ue", "ui"
};

// Default diceware wordlist for passphrases
const std::vector<std::string> DEFAULT_WORDLIST = {
    "about", "above", "actor", "acute", "admit", "adopt", "adult", "after", "again", "agent",
    "agree", "ahead", "alarm", "album", "alert", "alike", "alive", "allow", "alone", "along",
    "alter", "among", "anger", "angle", "angry", "apart", "apple", "apply", "arena", "argue",
    "arise", "array", "aside", "asset", "audio", "audit", "avoid", "award", "aware", "badly",
    "baker", "bases", "basic", "basis", "beach", "began", "begin", "begun", "being", "below",
    "bench", "billy", "birth", "black", "blame", "blind", "block", "blood", "board", "boost",
    "booth", "bound", "brain", "brand", "bread", "break", "breed", "brief", "bring", "broad",
    "broke", "brown", "build", "built", "buyer", "cable", "calif", "carry", "catch", "cause",
    "chain", "chair", "chart", "chase", "cheap", "check", "chest", "chief", "child", "china",
    "chose", "civil", "claim", "class", "clean", "clear", "click", "clock", "close", "coach",
    "coast", "could", "count", "court", "cover", "craft", "crash", "cream", "crime", "cross",
    "crowd", "crown", "curve", "cycle", "daily", "dance", "dated", "dealt", "death", "debut",
    "delay", "depth", "doing", "doubt", "dozen", "draft", "drama", "drawn", "dream", "dress",
    "drink", "drive", "drove", "dying", "eager", "early", "earth", "eight", "elite", "empty",
    "enemy", "enjoy", "enter", "entry", "equal", "error", "event", "every", "exact", "exist",
    "extra", "faith", "false", "fault", "fiber", "field", "fifth", "fifty", "fight", "final",
    "first", "fixed", "flash", "fleet", "floor", "fluid", "focus", "force", "forth", "forty",
    "forum", "found", "frame", "frank", "fraud", "fresh", "front", "fruit", "fully", "funny",
    "giant", "given", "glass", "globe", "going", "grace", "grade", "grand", "grant", "grass",
    "great", "green", "gross", "group", "grown", "guard", "guess", "guest", "guide", "happy",
    "harry", "heart", "heavy", "hence", "henry", "horse", "hotel", "house", "human", "ideal",
    "image", "index", "inner", "input", "issue", "japan", "jimmy", "joint", "jones", "judge",
    "known", "label", "large", "laser", "later", "laugh", "layer", "learn", "lease", "least",
    "leave", "legal", "level", "lewis", "light", "limit", "links", "lives", "local", "logic",
    "loose", "lower", "lucky", "lunch", "lying", "magic", "major", "maker", "march", "maria",
    "match", "maybe", "mayor", "meant", "media", "metal", "might", "minor", "minus", "mixed",
    "model", "money", "month", "moral", "motor", "mount", "mouse", "mouth", "movie", "music",
    "needs", "never", "newly", "night", "noise", "north", "noted", "novel", "nurse", "occur",
    "ocean", "offer", "often", "order", "other", "ought", "paint", "panel", "paper", "party",
    "peace", "peter", "phase", "phone", "photo", "piece", "pilot", "pitch", "place", "plain",
    "plane", "plant", "plate", "point", "pound", "power", "press", "price", "pride", "prime",
    "print", "prior", "prize", "proof", "proud", "prove", "queen", "quick", "quiet", "quite",
    "radio", "raise", "range", "rapid", "ratio", "reach", "ready", "refer", "right", "rival",
    "river", "robin", "roger", "roman", "rough", "round", "route", "royal", "rural", "scale",
    "scene", "scope", "score", "sense", "serve", "seven", "shall", "shape", "share", "sharp",
    "sheet", "shelf", "shell", "shift", "shirt", "shock", "shoot", "short", "shown", "sight",
    "since", "sixth", "sixty", "sized", "skill", "sleep", "slide", "small", "smart", "smile",
    "smith", "smoke", "solid", "solve", "sorry", "sound", "south", "space", "spare", "speak",
    "speed", "spend", "spent", "split", "spoke", "sport", "staff", "stage", "stake", "stand",
    "start", "state", "steam", "steel", "stick", "still", "stock", "stone", "stood", "store",
    "storm", "story", "strip", "stuck", "study", "stuff", "style", "sugar", "suite", "super",
    "sweet", "table", "taken", "taste", "taxes", "teach", "teeth", "terry", "texas", "thank",
    "theft", "their", "theme", "there", "these", "thick", "thing", "think", "third", "those",
    "three", "threw", "throw", "tight", "times", "tired", "title", "today", "topic", "total",
    "touch", "tough", "tower", "track", "trade", "train", "treat", "trend", "trial", "tried",
    "tries", "truck", "truly", "trust", "truth", "twice", "under", "undue", "union", "unity",
    "until", "upper", "upset", "urban", "usage", "usual", "valid", "value", "video", "virus",
    "visit", "vital", "voice", "waste", "watch", "water", "wheel", "where", "which", "while",
    "white", "whole", "whose", "woman", "women", "world", "worry", "worse", "worst", "worth",
    "would", "wound", "write", "wrong", "wrote", "yield", "young", "youth"
};

// Constructor
PasswordGenerator::PasswordGenerator() {
    // Seed the random number generator
    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    rng_ = std::mt19937(seed);
    
    // Initialize wordlist with default words
    wordList_ = DEFAULT_WORDLIST;
}

// Destructor
PasswordGenerator::~PasswordGenerator() {
    // Nothing to clean up
}

// Generate a random password
std::string PasswordGenerator::generatePassword(int length, 
                                              bool includeUpper, 
                                              bool includeLower,
                                              bool includeNumbers, 
                                              bool includeSymbols) {
    // Validate parameters
    if (length <= 0) {
        throw std::invalid_argument("Password length must be positive");
    }
    
    // Make sure at least one character set is included
    if (!includeUpper && !includeLower && !includeNumbers && !includeSymbols) {
        includeLower = true; // Default to lowercase if nothing is selected
    }
    
    // Get the character set to use
    std::string charSet = getCharSet(includeUpper, includeLower, includeNumbers, includeSymbols);
    
    // Generate the password
    return getRandomString(charSet, length);
}

// Generate a pronounceable password
std::string PasswordGenerator::generatePronounceable(int wordCount) {
    if (wordCount <= 0) {
        throw std::invalid_argument("Word count must be positive");
    }
    
    std::string result;
    std::uniform_int_distribution<int> consonantDist(0, CONSONANTS.size() - 1);
    std::uniform_int_distribution<int> vowelDist(0, VOWELS.size() - 1);
    
    for (int i = 0; i < wordCount; ++i) {
        // Decide whether to start with consonant or vowel
        std::bernoulli_distribution startWithConsonant(0.7); // 70% chance to start with consonant
        
        if (startWithConsonant(rng_)) {
            // Consonant-Vowel-Consonant pattern
            result += CONSONANTS[consonantDist(rng_)];
            result += VOWELS[vowelDist(rng_)];
            result += CONSONANTS[consonantDist(rng_)];
        } else {
            // Vowel-Consonant-Vowel pattern
            result += VOWELS[vowelDist(rng_)];
            result += CONSONANTS[consonantDist(rng_)];
            result += VOWELS[vowelDist(rng_)];
        }
        
        // Add a digit or special character occasionally
        if (i < wordCount - 1) {
            std::bernoulli_distribution addNumber(0.3); // 30% chance to add a number
            if (addNumber(rng_)) {
                std::uniform_int_distribution<int> digitDist(0, NUMBER_CHARS.size() - 1);
                result += NUMBER_CHARS[digitDist(rng_)];
            }
        }
    }
    
    return result;
}

// Generate a passphrase using diceware or similar wordlist
std::string PasswordGenerator::generatePassphrase(int wordCount) {
    if (wordCount <= 0) {
        throw std::invalid_argument("Word count must be positive");
    }
    
    if (wordList_.empty()) {
        throw std::runtime_error("Word list is empty");
    }
    
    std::string result;
    std::uniform_int_distribution<int> dist(0, wordList_.size() - 1);
    
    for (int i = 0; i < wordCount; ++i) {
        if (i > 0) {
            // Decide the separator between words (space, hyphen, dot, etc.)
            std::uniform_int_distribution<int> sepDist(0, 3);
            int sep = sepDist(rng_);
            switch (sep) {
                case 0: result += " "; break;    // Space
                case 1: result += "-"; break;    // Hyphen
                case 2: result += "."; break;    // Dot
                case 3: result += "_"; break;    // Underscore
            }
        }
        
        // Add a random word, possibly with capitalization
        std::string word = wordList_[dist(rng_)];
        
        std::bernoulli_distribution capsFirst(0.5); // 50% chance to capitalize first letter
        if (capsFirst(rng_) && !word.empty()) {
            word[0] = std::toupper(word[0]);
        }
        
        result += word;
        
        // Occasionally add a digit
        std::bernoulli_distribution addDigit(0.2); // 20% chance to add a digit
        if (addDigit(rng_)) {
            std::uniform_int_distribution<int> digitDist(0, 9);
            result += std::to_string(digitDist(rng_));
        }
    }
    
    return result;
}

// Generate a PIN code
std::string PasswordGenerator::generatePIN(int length) {
    if (length <= 0) {
        throw std::invalid_argument("PIN length must be positive");
    }
    
    return getRandomString(NUMBER_CHARS, length);
}

// Set a custom character set
void PasswordGenerator::setCustomCharSet(const std::string& charSet) {
    if (charSet.empty()) {
        customCharSet_.clear();
    } else {
        customCharSet_ = charSet;
    }
}

// Set a custom word list
void PasswordGenerator::setCustomWordList(const std::vector<std::string>& wordList) {
    if (wordList.empty()) {
        wordList_ = DEFAULT_WORDLIST;
    } else {
        wordList_ = wordList;
    }
}

// Load a wordlist from a file
bool PasswordGenerator::loadWordListFromFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return false;
    }
    
    std::vector<std::string> newWordList;
    std::string word;
    
    while (std::getline(file, word)) {
        // Skip empty lines or comments
        if (word.empty() || word[0] == '#') {
            continue;
        }
        
        // Trim whitespace
        word.erase(0, word.find_first_not_of(" \t\n\r\f\v"));
        word.erase(word.find_last_not_of(" \t\n\r\f\v") + 1);
        
        if (!word.empty()) {
            newWordList.push_back(word);
        }
    }
    
    if (newWordList.empty()) {
        return false;
    }
    
    wordList_ = std::move(newWordList);
    return true;
}

// Get the character set to use
std::string PasswordGenerator::getCharSet(bool includeUpper, bool includeLower,
                                        bool includeNumbers, bool includeSymbols) {
    // If a custom character set is specified, use it
    if (!customCharSet_.empty()) {
        return customCharSet_;
    }
    
    std::string charSet;
    
    if (includeUpper) {
        charSet += UPPERCASE_CHARS;
    }
    
    if (includeLower) {
        charSet += LOWERCASE_CHARS;
    }
    
    if (includeNumbers) {
        charSet += NUMBER_CHARS;
    }
    
    if (includeSymbols) {
        charSet += SYMBOL_CHARS;
    }
    
    return charSet;
}

// Get a random string of specified length from a character set
std::string PasswordGenerator::getRandomString(const std::string& charSet, int length) {
    if (charSet.empty()) {
        throw std::invalid_argument("Character set cannot be empty");
    }
    
    std::uniform_int_distribution<int> dist(0, charSet.size() - 1);
    std::string result;
    result.reserve(length);
    
    for (int i = 0; i < length; ++i) {
        result += charSet[dist(rng_)];
    }
    
    return result;
}

// Get a random word from the wordlist
std::string PasswordGenerator::getRandomWord() {
    if (wordList_.empty()) {
        throw std::runtime_error("Word list is empty");
    }
    
    std::uniform_int_distribution<int> dist(0, wordList_.size() - 1);
    return wordList_[dist(rng_)];
} 