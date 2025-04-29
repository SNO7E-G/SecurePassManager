#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <sqlite3.h>
#include "passwordmanager.h"
#include "encryption.h"

/**
 * Structure to hold database connection settings
 */
struct DatabaseConfig {
    std::string dbType = "sqlite";     // sqlite, postgresql, mysql, memory
    std::string dbPath = "passwords.db"; // For SQLite
    std::string host = "";             // For remote databases
    int port = 0;                      // For remote databases
    std::string username = "";         // For remote databases  
    std::string password = "";         // For remote databases
    std::string dbName = "";           // Database name for remote databases
    bool useSSL = true;                // Whether to use SSL for connection
    int connectionTimeout = 30;        // Connection timeout in seconds
    int maxConnections = 5;            // Maximum number of connections
    bool enableCompression = false;    // Enable data compression
    bool readOnly = false;             // Open in read-only mode
    bool encryptDatabase = true;       // Encrypt database file
    std::string encryptionKey = "";    // Key for database encryption
};

/**
 * Database synchronization options
 */
struct SyncOptions {
    std::string syncProvider = "none"; // none, webdav, cloud, custom
    std::string syncUrl = "";          // URL for sync service
    std::string username = "";         // Username for sync service
    std::string password = "";         // Password for sync service
    std::string apiKey = "";           // API key for sync service
    int syncInterval = 3600;           // Sync interval in seconds
    bool autoSync = false;             // Enable automatic synchronization
    bool syncOnStartup = false;        // Sync when app starts
    bool syncOnShutdown = false;       // Sync when app closes
    bool resolveConflicts = true;      // Automatically resolve conflicts
    std::string conflictStrategy = "newer"; // newer, local, remote, ask
};

/**
 * Database backup options
 */
struct BackupOptions {
    bool autoBackup = false;           // Enable automatic backups
    std::string backupDir = "";        // Directory for backups
    int backupInterval = 86400;        // Backup interval in seconds
    int maxBackups = 5;                // Maximum number of backups to keep
    bool compressBackups = true;       // Compress backup files
    bool encryptBackups = true;        // Encrypt backup files
};

/**
 * Migratable database schema version
 */
struct SchemaVersion {
    int major = 1;
    int minor = 0;
    int patch = 0;
    std::string toString() const {
        return std::to_string(major) + "." + 
               std::to_string(minor) + "." + 
               std::to_string(patch);
    }
};

/**
 * Class for managing database operations
 */
class Database {
public:
    /**
     * Result of a database operation
     */
    struct Result {
        bool success;
        std::string message;
        int affectedRows;
        int lastInsertId;
    };

    /**
     * Database query parameters
     */
    struct QueryParams {
        int limit = -1;                     // Maximum number of results
        int offset = 0;                     // Offset for pagination
        std::string orderBy = "";           // Field to order by
        bool ascending = true;              // Order direction
        std::map<std::string, std::string> filters; // Field-value filters
        std::string searchTerm = "";        // Full-text search term
        std::vector<std::string> fields;    // Fields to return (empty for all)
    };

    /**
     * Transaction isolation level
     */
    enum class IsolationLevel {
        READ_UNCOMMITTED,
        READ_COMMITTED,
        REPEATABLE_READ,
        SERIALIZABLE
    };

    Database();
    explicit Database(const DatabaseConfig& config);
    ~Database();

    /**
     * Initialize the database with the given configuration
     * @param config Configuration for the database
     * @return Result of the operation
     */
    Result initialize(const DatabaseConfig& config);

    /**
     * Open a connection to the database
     * @return Result of the operation
     */
    Result open();

    /**
     * Close the database connection
     * @return Result of the operation
     */
    Result close();

    /**
     * Check if the database is open
     * @return True if open, false otherwise
     */
    bool isOpen() const;

    /**
     * Execute a raw SQL query
     * @param query SQL query to execute
     * @param params Parameters for the query
     * @return Result of the operation
     */
    Result executeQuery(const std::string& query, 
                        const std::vector<std::string>& params = {});

    /**
     * Get all password entries
     * @param queryParams Query parameters for filtering and pagination
     * @return Vector of password entries as maps
     */
    std::vector<std::map<std::string, std::string>> getAllPasswords(
        const QueryParams& queryParams = QueryParams());

    /**
     * Add a new password entry
     * @param entry Map containing password entry fields
     * @return Result of the operation
     */
    Result addPassword(const std::map<std::string, std::string>& entry);

    /**
     * Update an existing password entry
     * @param id ID of the entry to update
     * @param entry New values for the entry
     * @return Result of the operation
     */
    Result updatePassword(int id, const std::map<std::string, std::string>& entry);

    /**
     * Delete a password entry
     * @param id ID of the entry to delete
     * @return Result of the operation
     */
    Result deletePassword(int id);

    /**
     * Get a password entry by ID
     * @param id ID of the entry to retrieve
     * @return Optional map with the entry, empty if not found
     */
    std::optional<std::map<std::string, std::string>> getPasswordById(int id);

    /**
     * Search for password entries
     * @param searchTerm Term to search for
     * @param queryParams Additional query parameters
     * @return Vector of matching entries
     */
    std::vector<std::map<std::string, std::string>> searchPasswords(
        const std::string& searchTerm,
        const QueryParams& queryParams = QueryParams());

    /**
     * Create a database backup
     * @param backupPath Path for the backup file
     * @param encrypt Whether to encrypt the backup
     * @return Result of the operation
     */
    Result createBackup(const std::string& backupPath, bool encrypt = true);

    /**
     * Restore from a backup
     * @param backupPath Path to the backup file
     * @param encryptionKey Key for decrypting the backup (if encrypted)
     * @return Result of the operation
     */
    Result restoreFromBackup(const std::string& backupPath, 
                             const std::string& encryptionKey = "");

    /**
     * Begin a transaction
     * @param isolationLevel Isolation level for the transaction
     * @return Result of the operation
     */
    Result beginTransaction(IsolationLevel isolationLevel = IsolationLevel::SERIALIZABLE);

    /**
     * Commit a transaction
     * @return Result of the operation
     */
    Result commitTransaction();

    /**
     * Rollback a transaction
     * @return Result of the operation
     */
    Result rollbackTransaction();

    /**
     * Execute function within a transaction
     * @param func Function to execute within transaction
     * @param isolationLevel Isolation level for the transaction
     * @return Result of the operation
     */
    template<typename Func>
    Result withTransaction(Func func, 
                          IsolationLevel isolationLevel = IsolationLevel::SERIALIZABLE);

    /**
     * Migrate the database schema to the latest version
     * @return Result of the operation
     */
    Result migrateSchema();

    /**
     * Get the current schema version
     * @return Current schema version
     */
    SchemaVersion getSchemaVersion();

    /**
     * Check if schema migration is needed
     * @return True if migration is needed
     */
    bool needsMigration();

    /**
     * Configure automatic backups
     * @param options Backup configuration options
     * @return Result of the operation
     */
    Result configureBackups(const BackupOptions& options);

    /**
     * Configure database synchronization
     * @param options Synchronization options
     * @return Result of the operation
     */
    Result configureSynchronization(const SyncOptions& options);

    /**
     * Manually trigger synchronization
     * @return Result of the operation
     */
    Result synchronize();

    /**
     * Get synchronization status
     * @return Map with synchronization status information
     */
    std::map<std::string, std::string> getSynchronizationStatus();

    /**
     * Enable or disable database encryption
     * @param enable Whether to enable encryption
     * @param encryptionKey Key for encryption
     * @return Result of the operation
     */
    Result setEncryption(bool enable, const std::string& encryptionKey = "");

    /**
     * Change the database encryption key
     * @param newKey New encryption key
     * @param oldKey Current encryption key
     * @return Result of the operation
     */
    Result changeEncryptionKey(const std::string& newKey, const std::string& oldKey);

    /**
     * Validate database integrity
     * @param repair Whether to attempt repairs if issues are found
     * @return Result of the operation
     */
    Result validateIntegrity(bool repair = false);

    /**
     * Compact the database to reduce size
     * @return Result of the operation
     */
    Result compact();

    /**
     * Import data from different format
     * @param filePath Path to the file to import
     * @param format Format of the file (csv, json, xml, etc.)
     * @param options Import options as map
     * @return Result of the operation
     */
    Result importData(const std::string& filePath, 
                     const std::string& format,
                     const std::map<std::string, std::string>& options = {});

    /**
     * Export data to different format
     * @param filePath Path to export to
     * @param format Format to export to (csv, json, xml, etc.)
     * @param options Export options as map
     * @return Result of the operation
     */
    Result exportData(const std::string& filePath, 
                     const std::string& format,
                     const std::map<std::string, std::string>& options = {});

    /**
     * Add an audit log entry
     * @param action Action performed
     * @param details Details of the action
     * @param userId ID of the user performing the action
     * @return Result of the operation
     */
    Result addAuditLog(const std::string& action, 
                      const std::string& details, 
                      const std::string& userId = "");

    /**
     * Get audit logs
     * @param queryParams Query parameters for filtering and pagination
     * @return Vector of audit log entries
     */
    std::vector<std::map<std::string, std::string>> getAuditLogs(
        const QueryParams& queryParams = QueryParams());

    /**
     * Register callback for database changes
     * @param callback Function to call when database changes
     * @return Identifier for the registered callback
     */
    int registerChangeCallback(
        std::function<void(const std::string&, int)> callback);

    /**
     * Unregister a change callback
     * @param callbackId ID of the callback to unregister
     * @return Result of the operation
     */
    Result unregisterChangeCallback(int callbackId);

    /**
     * Check if a table exists
     * @param tableName Name of the table to check
     * @return True if the table exists
     */
    bool tableExists(const std::string& tableName);

    /**
     * Create a new table
     * @param tableName Name of the table to create
     * @param columns Map of column names to their SQL definitions
     * @param primaryKey Name of the primary key column
     * @return Result of the operation
     */
    Result createTable(const std::string& tableName,
                      const std::map<std::string, std::string>& columns,
                      const std::string& primaryKey = "");

    /**
     * Get database statistics
     * @return Map with database statistics
     */
    std::map<std::string, std::string> getDatabaseStats();
    
    /**
     * Set a pragma value
     * @param pragma Name of the pragma
     * @param value Value to set
     * @return Result of the operation
     */
    Result setPragma(const std::string& pragma, const std::string& value);

    /**
     * Get a pragma value
     * @param pragma Name of the pragma
     * @return Value of the pragma
     */
    std::string getPragma(const std::string& pragma);

    // Password entry CRUD operations
    bool addPasswordEntry(const PasswordManager::PasswordEntry& entry);
    bool updatePasswordEntry(const PasswordManager::PasswordEntry& entry);
    bool deletePasswordEntry(int id);
    PasswordManager::PasswordEntry getPasswordEntry(int id);
    std::vector<PasswordManager::PasswordEntry> getAllPasswordEntries();
    std::vector<PasswordManager::PasswordEntry> searchPasswordEntries(const std::string& query);
    std::vector<PasswordManager::PasswordEntry> getPasswordEntriesByCategory(const std::string& category);
    std::vector<PasswordManager::PasswordEntry> getPasswordEntriesByTag(const std::string& tag);
    
    // Category and tag operations
    std::vector<std::string> getAllCategories();
    std::vector<std::string> getAllTags();
    
    // Password history
    bool addPasswordHistoryEntry(int passwordId, const std::string& oldPassword, 
                                 const std::chrono::system_clock::time_point& changeTime);
    std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> 
    getPasswordHistory(int passwordId);
    
    // Backup and restore
    bool backupDatabase(const std::string& backupPath);

private:
    // Implementation details
    class DatabaseImpl;
    std::unique_ptr<DatabaseImpl> impl_;
    
    // Current configuration
    DatabaseConfig config_;
    
    // Backup options
    BackupOptions backupOptions_;
    
    // Sync options
    SyncOptions syncOptions_;
    
    // Transaction state
    bool inTransaction_;
    
    // Schema management
    SchemaVersion currentVersion_;
    std::vector<std::pair<SchemaVersion, std::string>> migrations_;
    
    // Prepare and execute migrations
    void prepareMigrations();
    Result executeMigration(const SchemaVersion& version, const std::string& sql);
    
    // Internal utility functions
    Result initializeTables();
    bool isValidTableName(const std::string& tableName);
    bool isValidColumnName(const std::string& columnName);
    std::string sanitizeSql(const std::string& sql);
    
    // Error handling
    std::string getLastError() const;
    
    // Encryption helpers
    Result encryptDatabase(const std::string& key);
    Result decryptDatabase(const std::string& key);
    
    // Synchronization helpers
    Result uploadChanges();
    Result downloadChanges();
    Result resolveConflicts();
    
    // Audit logging
    void logInternalAction(const std::string& action, const std::string& details);
    
    // Callback management
    std::map<int, std::function<void(const std::string&, int)>> changeCallbacks_;
    int nextCallbackId_;
    void notifyCallbacks(const std::string& table, int operation);
}; 