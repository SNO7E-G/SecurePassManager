#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>

/**
 * Compression algorithm options
 */
enum class CompressionAlgorithm
{
    NONE, // No compression
    ZLIB, // ZLIB compression
    ZSTD, // Zstandard compression
    LZ4   // LZ4 compression
};

/**
 * Compression level options
 */
enum class CompressionLevel
{
    FASTEST, // Optimize for speed
    DEFAULT, // Default balance
    BEST     // Optimize for compression ratio
};

/**
 * Class that provides data compression functionality
 */
class Compression
{
public:
    /**
     * Default constructor
     */
    Compression();

    /**
     * Constructor with algorithm specification
     * @param algorithm Compression algorithm to use
     * @param level Compression level to use
     */
    Compression(CompressionAlgorithm algorithm, CompressionLevel level = CompressionLevel::DEFAULT);

    /**
     * Destructor
     */
    ~Compression();

    /**
     * Set the compression algorithm
     * @param algorithm Algorithm to use
     */
    void setAlgorithm(CompressionAlgorithm algorithm);

    /**
     * Set the compression level
     * @param level Compression level to use
     */
    void setLevel(CompressionLevel level);

    /**
     * Get the current compression algorithm
     * @return Current algorithm
     */
    CompressionAlgorithm getAlgorithm() const;

    /**
     * Get the current compression level
     * @return Current level
     */
    CompressionLevel getLevel() const;

    /**
     * Check if compression is available
     * @param algorithm Algorithm to check
     * @return True if the algorithm is available
     */
    static bool isAlgorithmAvailable(CompressionAlgorithm algorithm);

    /**
     * Compress data
     * @param data Data to compress
     * @return Compressed data
     * @throws std::runtime_error if compression fails
     */
    std::vector<uint8_t> compress(const std::vector<uint8_t> &data);

    /**
     * Compress string data
     * @param data String to compress
     * @return Compressed data
     * @throws std::runtime_error if compression fails
     */
    std::vector<uint8_t> compressString(const std::string &data);

    /**
     * Decompress data
     * @param compressedData Compressed data
     * @return Decompressed data
     * @throws std::runtime_error if decompression fails
     */
    std::vector<uint8_t> decompress(const std::vector<uint8_t> &compressedData);

    /**
     * Decompress data to string
     * @param compressedData Compressed data
     * @return Decompressed string
     * @throws std::runtime_error if decompression fails
     */
    std::string decompressToString(const std::vector<uint8_t> &compressedData);

    /**
     * Get the expected decompressed size (if algorithm supports size estimation)
     * @param compressedData Compressed data
     * @return Expected size or 0 if unknown
     */
    size_t getDecompressedSize(const std::vector<uint8_t> &compressedData);

    /**
     * Calculate the compression ratio
     * @param originalSize Original data size
     * @param compressedSize Compressed data size
     * @return Compression ratio (higher is better)
     */
    static double calculateCompressionRatio(size_t originalSize, size_t compressedSize);

private:
    // Current algorithm and level
    CompressionAlgorithm algorithm_;
    CompressionLevel level_;

    // Implementation helpers
    std::vector<uint8_t> compressZlib(const std::vector<uint8_t> &data);
    std::vector<uint8_t> decompressZlib(const std::vector<uint8_t> &compressedData);

    std::vector<uint8_t> compressZstd(const std::vector<uint8_t> &data);
    std::vector<uint8_t> decompressZstd(const std::vector<uint8_t> &compressedData);

    std::vector<uint8_t> compressLz4(const std::vector<uint8_t> &data);
    std::vector<uint8_t> decompressLz4(const std::vector<uint8_t> &compressedData);

    // Helper to convert compression level to algorithm-specific level
    int getLevelValue() const;
};