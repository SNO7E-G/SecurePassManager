#include "database.h"
#include <stdexcept>
#include <chrono>
#include <sstream>
#include <vector>

// Constructor
Database::Database() : db_(nullptr), encryption_(nullptr) {
}

// Destructor
Database::~Database() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// Initialize the database
bool Database::initialize(const std::string& dbPath, Encryption* encryption) {
    if (!encryption) {
        return false;
    }
    
    encryption_ = encryption;
    
    // Open the database
    int rc = sqlite3_open(dbPath.c_str(), &db_);
    if (rc != SQLITE_OK) {
        return false;
    }
    
    // Enable foreign keys
    executeQuery("PRAGMA foreign_keys = ON;");
    
    // Check if the database is initialized
    bool isInitialized = false;
    sqlite3_stmt* stmt;
    
    rc = sqlite3_prepare_v2(db_, "SELECT name FROM sqlite_master WHERE type='table' AND name='config';", -1, &stmt, nullptr);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            isInitialized = true;
        }
        sqlite3_finalize(stmt);
    }
    
    if (!isInitialized) {
        // Initialize the schema
        if (!initializeSchema()) {
            sqlite3_close(db_);
            db_ = nullptr;
            return false;
        }
    }
    
    return true;
}

// Create a new vault
bool Database::createVault(const std::string& dbPath, 
                         const std::string& masterPasswordHash,
                         const std::string& salt,
                         int iterations) {
    // Open the database
    int rc = sqlite3_open(dbPath.c_str(), &db_);
    if (rc != SQLITE_OK) {
        return false;
    }
    
    // Initialize the schema
    if (!initializeSchema()) {
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    
    // Add the master password hash and salt to the config table
    std::string query = "INSERT INTO config (key, value) VALUES (?, ?);";
    
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db_, query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    
    // Insert master password hash
    sqlite3_bind_text(stmt, 1, "master_password_hash", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, masterPasswordHash.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_reset(stmt);
    
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    
    // Insert salt
    sqlite3_bind_text(stmt, 1, "salt", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, salt.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_reset(stmt);
    
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    
    // Insert iterations
    sqlite3_bind_text(stmt, 1, "iterations", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, std::to_string(iterations).c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    
    return true;
}

// Verify the master password hash
bool Database::verifyMasterPassword(const std::string& masterPasswordHash) {
    if (!db_) {
        return false;
    }
    
    std::string storedHash;
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, "SELECT value FROM config WHERE key = 'master_password_hash';", -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return false;
    }
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (value) {
            storedHash = value;
        }
    }
    
    sqlite3_finalize(stmt);
    
    return (storedHash == masterPasswordHash);
}

// Get the stored salt
std::string Database::getSalt() {
    if (!db_) {
        return "";
    }
    
    std::string salt;
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, "SELECT value FROM config WHERE key = 'salt';", -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return "";
    }
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (value) {
            salt = value;
        }
    }
    
    sqlite3_finalize(stmt);
    
    return salt;
}

// Get the stored iterations
int Database::getIterations() {
    if (!db_) {
        return 0;
    }
    
    int iterations = 0;
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, "SELECT value FROM config WHERE key = 'iterations';", -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return 0;
    }
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (value) {
            iterations = std::stoi(value);
        }
    }
    
    sqlite3_finalize(stmt);
    
    return iterations;
}

// Change the master password
bool Database::changeMasterPassword(const std::string& newPasswordHash, 
                                  const std::string& newSalt,
                                  int newIterations) {
    if (!db_) {
        return false;
    }
    
    beginTransaction();
    
    std::string query = "UPDATE config SET value = ? WHERE key = ?;";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, query.c_str(), -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        rollbackTransaction();
        return false;
    }
    
    // Update master password hash
    sqlite3_bind_text(stmt, 1, newPasswordHash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "master_password_hash", -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_reset(stmt);
    
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        rollbackTransaction();
        return false;
    }
    
    // Update salt
    sqlite3_bind_text(stmt, 1, newSalt.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "salt", -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_reset(stmt);
    
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        rollbackTransaction();
        return false;
    }
    
    // Update iterations
    sqlite3_bind_text(stmt, 1, std::to_string(newIterations).c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "iterations", -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        rollbackTransaction();
        return false;
    }
    
    commitTransaction();
    return true;
}

// Initialize database schema
bool Database::initializeSchema() {
    if (!db_) {
        return false;
    }
    
    beginTransaction();
    
    // Config table
    if (!executeQuery("CREATE TABLE IF NOT EXISTS config ("
                    "key TEXT PRIMARY KEY, "
                    "value TEXT NOT NULL"
                    ");")) {
        rollbackTransaction();
        return false;
    }
    
    // Categories table
    if (!executeQuery("CREATE TABLE IF NOT EXISTS categories ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "name TEXT NOT NULL UNIQUE"
                    ");")) {
        rollbackTransaction();
        return false;
    }
    
    // Tags table
    if (!executeQuery("CREATE TABLE IF NOT EXISTS tags ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "name TEXT NOT NULL UNIQUE"
                    ");")) {
        rollbackTransaction();
        return false;
    }
    
    // Passwords table
    if (!executeQuery("CREATE TABLE IF NOT EXISTS passwords ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "title TEXT NOT NULL, "
                    "username TEXT, "
                    "password TEXT NOT NULL, "
                    "url TEXT, "
                    "notes TEXT, "
                    "category_id INTEGER, "
                    "created INTEGER NOT NULL, "
                    "modified INTEGER NOT NULL, "
                    "expiry INTEGER, "
                    "FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL"
                    ");")) {
        rollbackTransaction();
        return false;
    }
    
    // Password-Tag relationship table
    if (!executeQuery("CREATE TABLE IF NOT EXISTS password_tags ("
                    "password_id INTEGER NOT NULL, "
                    "tag_id INTEGER NOT NULL, "
                    "PRIMARY KEY (password_id, tag_id), "
                    "FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE, "
                    "FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE"
                    ");")) {
        rollbackTransaction();
        return false;
    }
    
    // Password history table
    if (!executeQuery("CREATE TABLE IF NOT EXISTS password_history ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "password_id INTEGER NOT NULL, "
                    "old_password TEXT NOT NULL, "
                    "changed_at INTEGER NOT NULL, "
                    "FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE"
                    ");")) {
        rollbackTransaction();
        return false;
    }
    
    commitTransaction();
    return true;
}

// Execute a SQL query
bool Database::executeQuery(const std::string& query) {
    if (!db_) {
        return false;
    }
    
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, query.c_str(), nullptr, nullptr, &errMsg);
    
    if (rc != SQLITE_OK) {
        if (errMsg) {
            sqlite3_free(errMsg);
        }
        return false;
    }
    
    return true;
}

// Begin a transaction
bool Database::beginTransaction() {
    return executeQuery("BEGIN TRANSACTION;");
}

// Commit a transaction
bool Database::commitTransaction() {
    return executeQuery("COMMIT;");
}

// Rollback a transaction
bool Database::rollbackTransaction() {
    return executeQuery("ROLLBACK;");
}

// Basic implementation of password entry CRUD operations
// In a real implementation, these would be more comprehensive

bool Database::addPasswordEntry(const PasswordManager::PasswordEntry& entry) {
    if (!db_ || !encryption_) {
        return false;
    }
    
    beginTransaction();
    
    // Get or create category ID
    int categoryId = -1;
    if (!entry.category.empty()) {
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db_, 
                                  "SELECT id FROM categories WHERE name = ?;", 
                                  -1, &stmt, nullptr);
        
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, entry.category.c_str(), -1, SQLITE_STATIC);
            
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                categoryId = sqlite3_column_int(stmt, 0);
            } else {
                sqlite3_finalize(stmt);
                
                // Category doesn't exist, create it
                rc = sqlite3_prepare_v2(db_, 
                                      "INSERT INTO categories (name) VALUES (?);", 
                                      -1, &stmt, nullptr);
                
                if (rc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, entry.category.c_str(), -1, SQLITE_STATIC);
                    
                    if (sqlite3_step(stmt) == SQLITE_DONE) {
                        categoryId = sqlite3_last_insert_rowid(db_);
                    }
                }
            }
            
            sqlite3_finalize(stmt);
        }
    }
    
    // Insert password entry
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, 
                              "INSERT INTO passwords "
                              "(title, username, password, url, notes, category_id, created, modified, expiry) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);", 
                              -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        rollbackTransaction();
        return false;
    }
    
    // Encrypt sensitive fields
    std::string encryptedPassword = encryption_->encrypt(entry.password);
    std::string encryptedUsername = entry.username.empty() ? "" : encryption_->encrypt(entry.username);
    std::string encryptedNotes = entry.notes.empty() ? "" : encryption_->encrypt(entry.notes);
    
    // Convert time points to timestamps
    auto createdTime = std::chrono::system_clock::to_time_t(entry.created);
    auto modifiedTime = std::chrono::system_clock::to_time_t(entry.modified);
    auto expiryTime = entry.expiry.time_since_epoch().count() > 0 ? 
                    std::chrono::system_clock::to_time_t(entry.expiry) : 0;
    
    // Bind parameters
    sqlite3_bind_text(stmt, 1, entry.title.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, encryptedUsername.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, encryptedPassword.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry.url.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, encryptedNotes.c_str(), -1, SQLITE_STATIC);
    
    if (categoryId > 0) {
        sqlite3_bind_int(stmt, 6, categoryId);
    } else {
        sqlite3_bind_null(stmt, 6);
    }
    
    sqlite3_bind_int64(stmt, 7, createdTime);
    sqlite3_bind_int64(stmt, 8, modifiedTime);
    
    if (expiryTime > 0) {
        sqlite3_bind_int64(stmt, 9, expiryTime);
    } else {
        sqlite3_bind_null(stmt, 9);
    }
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        rollbackTransaction();
        return false;
    }
    
    // Get the inserted password ID
    int passwordId = sqlite3_last_insert_rowid(db_);
    
    // Insert tags
    for (const auto& tag : entry.tags) {
        // Get or create tag ID
        int tagId = -1;
        rc = sqlite3_prepare_v2(db_, 
                              "SELECT id FROM tags WHERE name = ?;", 
                              -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            rollbackTransaction();
            return false;
        }
        
        sqlite3_bind_text(stmt, 1, tag.c_str(), -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            tagId = sqlite3_column_int(stmt, 0);
        } else {
            sqlite3_finalize(stmt);
            
            // Tag doesn't exist, create it
            rc = sqlite3_prepare_v2(db_, 
                                  "INSERT INTO tags (name) VALUES (?);", 
                                  -1, &stmt, nullptr);
            
            if (rc != SQLITE_OK) {
                rollbackTransaction();
                return false;
            }
            
            sqlite3_bind_text(stmt, 1, tag.c_str(), -1, SQLITE_STATIC);
            
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                tagId = sqlite3_last_insert_rowid(db_);
            } else {
                sqlite3_finalize(stmt);
                rollbackTransaction();
                return false;
            }
        }
        
        sqlite3_finalize(stmt);
        
        // Associate tag with password
        rc = sqlite3_prepare_v2(db_, 
                              "INSERT INTO password_tags (password_id, tag_id) VALUES (?, ?);", 
                              -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            rollbackTransaction();
            return false;
        }
        
        sqlite3_bind_int(stmt, 1, passwordId);
        sqlite3_bind_int(stmt, 2, tagId);
        
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        
        if (rc != SQLITE_DONE) {
            rollbackTransaction();
            return false;
        }
    }
    
    commitTransaction();
    return true;
} 