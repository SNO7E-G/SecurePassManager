#include "../include/secure_memory.h"
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <memoryapi.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

// Securely wipe sensitive data from memory
void Encryption::secureWipeMemory(void *data, size_t size)
{
    if (data == nullptr || size == 0)
    {
        return;
    }

    // Implementation strategy:
    // 1. Write patterns that cause transitions (0xFF, 0x00)
    // 2. Write a random pattern
    // 3. Write zeros

    // First pass: 0xFF
    std::memset(data, 0xFF, size);

    // Second pass: 0x00
    std::memset(data, 0x00, size);

    // Third pass: random data
    std::vector<uint8_t> randomData(size);
    generateRandomBytes(randomData.size()).swap(randomData);
    std::memcpy(data, randomData.data(), size);

    // Final pass: zeros
    std::memset(data, 0, size);

    // Prevent compiler optimization
#ifdef _WIN32
    // On Windows use SecureZeroMemory as it's guaranteed not to be optimized away
    SecureZeroMemory(data, size);
#else
    // Use memory fence to prevent optimizations
    static void *(*const volatile memset_ptr)(void *, int, size_t) = std::memset;
    memset_ptr(data, 0, size);
#endif

    // Try to use platform-specific memory protection if available
#ifdef _WIN32
    // Windows: VirtualLock
    VirtualLock(data, size);
#else
    // Unix/Linux: mlock
    mlock(data, size);
#endif
}

// Securely wipe a string
void Encryption::secureWipe(std::string &data)
{
    if (data.empty())
    {
        return;
    }

    // Overwrite the string data
    secureWipeMemory(&data[0], data.size());

    // Resize the string to zero and swap with an empty string to ensure deallocation
    data.resize(0);
    std::string().swap(data);
}

// Securely wipe a vector
template <typename T>
void Encryption::secureWipe(std::vector<T> &data)
{
    if (data.empty())
    {
        return;
    }

    // Overwrite the vector data
    secureWipeMemory(data.data(), data.size() * sizeof(T));

    // Resize the vector to zero and swap with an empty vector to ensure deallocation
    data.clear();
    data.shrink_to_fit();
    std::vector<T>().swap(data);
}

// Securely wipe a file
bool Encryption::secureWipeFile(const std::string &filePath, int passes)
{
    if (passes < 1)
    {
        passes = 1;
    }

    // Open the file
    FILE *file = fopen(filePath.c_str(), "rb+");
    if (!file)
    {
        return false;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    // Bail on empty files
    if (fileSize <= 0)
    {
        fclose(file);
        return true;
    }

    // Create a buffer for wiping
    const size_t bufferSize = 8192; // 8 KB buffer
    std::vector<uint8_t> buffer(bufferSize);

    // Multiple overwrite passes
    for (int pass = 0; pass < passes; pass++)
    {
        uint8_t pattern;

        // Choose pattern based on pass number
        switch (pass % 3)
        {
        case 0:
            pattern = 0xFF;
            break; // All ones
        case 1:
            pattern = 0x00;
            break; // All zeros
        case 2:    // Random data
            generateRandomBytes(buffer.size()).swap(buffer);
            break;
        }

        // If not random pattern, fill buffer
        if (pass % 3 != 2)
        {
            std::memset(buffer.data(), pattern, buffer.size());
        }

        // Rewind file pointer
        rewind(file);

        // Write pattern in chunks
        long remainingBytes = fileSize;
        while (remainingBytes > 0)
        {
            size_t bytesToWrite = (remainingBytes > static_cast<long>(buffer.size()))
                                      ? buffer.size()
                                      : static_cast<size_t>(remainingBytes);

            size_t bytesWritten = fwrite(buffer.data(), 1, bytesToWrite, file);
            if (bytesWritten != bytesToWrite)
            {
                fclose(file);
                return false;
            }

            remainingBytes -= static_cast<long>(bytesWritten);
        }

        // Flush changes to disk
        fflush(file);
    }

    // Close the file
    fclose(file);

    // Delete the file
    return remove(filePath.c_str()) == 0;
}

// Generate a secure random token
std::string Encryption::generateSecureToken(int length)
{
    if (length <= 0)
    {
        return "";
    }

    // Define character set for tokens
    static const char charset[] =
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "-._~"; // URL-safe characters

    // Get random bytes
    std::vector<uint8_t> randomBytes = generateRandomBytes(length);

    // Convert to token using the character set
    std::string token(length, 0);
    for (int i = 0; i < length; i++)
    {
        token[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }

    return token;
}

// Constant-time comparison function to prevent timing attacks
bool Encryption::secureCompare(const std::string &a, const std::string &b)
{
    // If lengths differ, immediately return false, but continue with the comparison
    // to prevent timing attacks based on string length
    bool equal = (a.size() == b.size());

    // Calculate maximum comparison length
    size_t maxLength = std::max(a.size(), b.size());

    // Perform constant-time comparison
    for (size_t i = 0; i < maxLength; i++)
    {
        char aChar = (i < a.size()) ? a[i] : 0;
        char bChar = (i < b.size()) ? b[i] : 0;
        equal &= (aChar == bChar);
    }

    return equal;
}

bool SecureMemory::lockMemory(void *addr, size_t size)
{
#ifdef _WIN32
    return VirtualLock(addr, size) != 0;
#else
    return mlock(addr, size) == 0;
#endif
}

bool SecureMemory::unlockMemory(void *addr, size_t size)
{
#ifdef _WIN32
    return VirtualUnlock(addr, size) != 0;
#else
    return munlock(addr, size) == 0;
#endif
}

void SecureMemory::secureZeroMemory(void *addr, size_t size)
{
    // Use platform-specific secure zero memory function if available
#ifdef _WIN32
    ::SecureZeroMemory(addr, size);
#else
    // Volatile pointer to prevent compiler optimization
    volatile unsigned char *volatile ptr = reinterpret_cast<volatile unsigned char *volatile>(addr);

    // Write zeroes to memory
    for (size_t i = 0; i < size; ++i)
    {
        ptr[i] = 0;
    }
#endif
}

void *SecureMemory::secureAllocate(size_t size)
{
    void *ptr = malloc(size);
    if (ptr)
    {
        if (!lockMemory(ptr, size))
        {
            // If locking fails, still continue but with reduced security
            memset(ptr, 0, size);
        }
    }
    return ptr;
}

void SecureMemory::secureFree(void *addr, size_t size)
{
    if (addr)
    {
        secureZeroMemory(addr, size);
        unlockMemory(addr, size);
        free(addr);
    }
}

// SecureString implementation
SecureMemory::SecureString::SecureString()
    : data_(nullptr), size_(0), capacity_(0)
{
}

SecureMemory::SecureString::SecureString(const char *str)
    : data_(nullptr), size_(0), capacity_(0)
{
    if (str)
    {
        size_t len = strlen(str);
        if (len > 0)
        {
            reallocate(len + 1);
            memcpy(data_, str, len);
            data_[len] = '\0';
            size_ = len;
            lockMemory(data_, capacity_);
        }
    }
}

SecureMemory::SecureString::SecureString(const std::string &str)
    : data_(nullptr), size_(0), capacity_(0)
{
    if (!str.empty())
    {
        size_t len = str.length();
        reallocate(len + 1);
        memcpy(data_, str.c_str(), len);
        data_[len] = '\0';
        size_ = len;
        lockMemory(data_, capacity_);
    }
}

SecureMemory::SecureString::SecureString(const SecureString &other)
    : data_(nullptr), size_(0), capacity_(0)
{
    if (other.size_ > 0)
    {
        reallocate(other.size_ + 1);
        memcpy(data_, other.data_, other.size_ + 1);
        size_ = other.size_;
        lockMemory(data_, capacity_);
    }
}

SecureMemory::SecureString::SecureString(SecureString &&other) noexcept
    : data_(other.data_), size_(other.size_), capacity_(other.capacity_)
{
    other.data_ = nullptr;
    other.size_ = 0;
    other.capacity_ = 0;
}

SecureMemory::SecureString::~SecureString()
{
    clear();
}

SecureMemory::SecureString &SecureMemory::SecureString::operator=(const SecureString &other)
{
    if (this != &other)
    {
        clear();
        if (other.size_ > 0)
        {
            reallocate(other.size_ + 1);
            memcpy(data_, other.data_, other.size_ + 1);
            size_ = other.size_;
            lockMemory(data_, capacity_);
        }
    }
    return *this;
}

SecureMemory::SecureString &SecureMemory::SecureString::operator=(SecureString &&other) noexcept
{
    if (this != &other)
    {
        clear();
        data_ = other.data_;
        size_ = other.size_;
        capacity_ = other.capacity_;
        other.data_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
    }
    return *this;
}

size_t SecureMemory::SecureString::size() const
{
    return size_;
}

bool SecureMemory::SecureString::empty() const
{
    return size_ == 0;
}

void SecureMemory::SecureString::clear()
{
    if (data_)
    {
        unlockMemory(data_, capacity_);
        secureZeroMemory(data_, capacity_);
        free(data_);
        data_ = nullptr;
        size_ = 0;
        capacity_ = 0;
    }
}

void SecureMemory::SecureString::append(const char *str)
{
    if (str)
    {
        size_t len = strlen(str);
        if (len > 0)
        {
            size_t newSize = size_ + len;
            if (newSize + 1 > capacity_)
            {
                // Need to reallocate
                size_t newCapacity = std::max(capacity_ * 2, newSize + 1);
                char *newData = static_cast<char *>(malloc(newCapacity));
                if (newData)
                {
                    if (data_)
                    {
                        // Copy existing data
                        memcpy(newData, data_, size_);
                        // Clear old data
                        unlockMemory(data_, capacity_);
                        secureZeroMemory(data_, capacity_);
                        free(data_);
                    }
                    // Copy new data
                    memcpy(newData + size_, str, len);
                    newData[newSize] = '\0';

                    data_ = newData;
                    size_ = newSize;
                    capacity_ = newCapacity;
                    lockMemory(data_, capacity_);
                }
            }
            else
            {
                // Enough capacity, just append
                memcpy(data_ + size_, str, len);
                data_[newSize] = '\0';
                size_ = newSize;
            }
        }
    }
}

void SecureMemory::SecureString::append(const std::string &str)
{
    append(str.c_str());
}

void SecureMemory::SecureString::append(const SecureString &other)
{
    if (!other.empty())
    {
        append(other.data_);
    }
}

std::string SecureMemory::SecureString::toString() const
{
    if (data_ && size_ > 0)
    {
        return std::string(data_, size_);
    }
    return std::string();
}

const char *SecureMemory::SecureString::data() const
{
    return data_;
}

void SecureMemory::SecureString::reallocate(size_t newCapacity)
{
    if (newCapacity > capacity_)
    {
        char *newData = static_cast<char *>(malloc(newCapacity));
        if (newData)
        {
            if (data_)
            {
                // Copy old data if it exists
                memcpy(newData, data_, size_);
                // Clear and free old data
                unlockMemory(data_, capacity_);
                secureZeroMemory(data_, capacity_);
                free(data_);
            }
            data_ = newData;
            capacity_ = newCapacity;
        }
    }
}