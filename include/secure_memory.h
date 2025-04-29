#pragma once

#include <cstddef>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>

/**
 * Class that provides secure memory handling functionality
 * Designed to protect sensitive data from being exposed in memory
 */
class SecureMemory
{
public:
    /**
     * Lock memory to prevent it from being swapped to disk
     * @param addr Memory address to lock
     * @param size Size of memory region to lock
     * @return True if locking succeeded
     */
    static bool lockMemory(void *addr, size_t size);

    /**
     * Unlock previously locked memory
     * @param addr Memory address to unlock
     * @param size Size of memory region to unlock
     * @return True if unlocking succeeded
     */
    static bool unlockMemory(void *addr, size_t size);

    /**
     * Securely erase memory to remove sensitive data
     * Uses techniques to prevent compiler optimization from removing the wipe
     * @param addr Memory address to erase
     * @param size Size of memory region to erase
     */
    static void secureZeroMemory(void *addr, size_t size);

    /**
     * Allocate a memory region that is locked and will be automatically wiped
     * @param size Size of memory to allocate
     * @return Pointer to allocated memory
     */
    static void *secureAllocate(size_t size);

    /**
     * Free memory that was allocated with secureAllocate
     * Will securely wipe the memory before freeing
     * @param addr Memory address to free
     * @param size Size of memory region to free
     */
    static void secureFree(void *addr, size_t size);

    /**
     * Secure string class that keeps data in protected memory
     */
    class SecureString
    {
    public:
        /**
         * Create an empty secure string
         */
        SecureString();

        /**
         * Create a secure string from a C-style string
         * @param str String to secure
         */
        explicit SecureString(const char *str);

        /**
         * Create a secure string from a std::string
         * @param str String to secure
         */
        explicit SecureString(const std::string &str);

        /**
         * Copy constructor - creates a secure copy
         * @param other SecureString to copy
         */
        SecureString(const SecureString &other);

        /**
         * Move constructor
         * @param other SecureString to move from
         */
        SecureString(SecureString &&other) noexcept;

        /**
         * Destructor - securely wipes data
         */
        ~SecureString();

        /**
         * Copy assignment operator
         * @param other SecureString to copy
         * @return Reference to this object
         */
        SecureString &operator=(const SecureString &other);

        /**
         * Move assignment operator
         * @param other SecureString to move from
         * @return Reference to this object
         */
        SecureString &operator=(SecureString &&other) noexcept;

        /**
         * Get the size of the string
         * @return Size of the string
         */
        size_t size() const;

        /**
         * Check if the string is empty
         * @return True if string is empty
         */
        bool empty() const;

        /**
         * Clear the string (securely erases data)
         */
        void clear();

        /**
         * Append data to the string
         * @param str String to append
         */
        void append(const char *str);

        /**
         * Append data to the string
         * @param str String to append
         */
        void append(const std::string &str);

        /**
         * Append data to the string
         * @param other SecureString to append
         */
        void append(const SecureString &other);

        /**
         * Convert to std::string (creates an insecure copy, use with caution)
         * @return std::string copy of the data
         */
        std::string toString() const;

        /**
         * Get raw data pointer (use with caution)
         * @return Const pointer to the data
         */
        const char *data() const;

    private:
        char *data_;
        size_t size_;
        size_t capacity_;

        void reallocate(size_t newCapacity);
    };

    /**
     * Create a SecureVector - vector with secure memory handling
     * @tparam T Type of elements in the vector
     * @return Unique pointer to secure vector
     */
    template <typename T>
    static std::unique_ptr<std::vector<T>> createSecureVector()
    {
        auto vec = std::make_unique<std::vector<T>>();
        // Lock memory for the vector management structures
        lockMemory(vec.get(), sizeof(std::vector<T>));
        return vec;
    }

    /**
     * Destroy a SecureVector and wipe its contents
     * @tparam T Type of elements in the vector
     * @param vec Vector to destroy
     */
    template <typename T>
    static void destroySecureVector(std::unique_ptr<std::vector<T>> &vec)
    {
        if (vec)
        {
            // Wipe the vector contents
            if (!vec->empty())
            {
                secureZeroMemory(vec->data(), vec->size() * sizeof(T));
            }
            // Clear the vector
            vec->clear();
            // Unlock memory
            unlockMemory(vec.get(), sizeof(std::vector<T>));
        }
    }
};