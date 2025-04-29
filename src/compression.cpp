#include "../include/compression.h"
#include <stdexcept>
#include <string.h>

#ifdef ZLIB_FOUND
#include <zlib.h>
#endif

#ifdef ZSTD_FOUND
#include <zstd.h>
#endif

#ifdef LZ4_FOUND
#include <lz4.h>
#endif

Compression::Compression()
    : algorithm_(CompressionAlgorithm::ZLIB), level_(CompressionLevel::DEFAULT)
{
}

Compression::Compression(CompressionAlgorithm algorithm, CompressionLevel level)
    : algorithm_(algorithm), level_(level)
{
    if (!isAlgorithmAvailable(algorithm))
    {
        throw std::runtime_error("Selected compression algorithm is not available");
    }
}

Compression::~Compression()
{
    // Nothing to clean up
}

void Compression::setAlgorithm(CompressionAlgorithm algorithm)
{
    if (!isAlgorithmAvailable(algorithm))
    {
        throw std::runtime_error("Selected compression algorithm is not available");
    }
    algorithm_ = algorithm;
}

void Compression::setLevel(CompressionLevel level)
{
    level_ = level;
}

CompressionAlgorithm Compression::getAlgorithm() const
{
    return algorithm_;
}

CompressionLevel Compression::getLevel() const
{
    return level_;
}

bool Compression::isAlgorithmAvailable(CompressionAlgorithm algorithm)
{
    switch (algorithm)
    {
    case CompressionAlgorithm::NONE:
        return true;

    case CompressionAlgorithm::ZLIB:
#ifdef ZLIB_FOUND
        return true;
#else
        return false;
#endif

    case CompressionAlgorithm::ZSTD:
#ifdef ZSTD_FOUND
        return true;
#else
        return false;
#endif

    case CompressionAlgorithm::LZ4:
#ifdef LZ4_FOUND
        return true;
#else
        return false;
#endif

    default:
        return false;
    }
}

std::vector<uint8_t> Compression::compress(const std::vector<uint8_t> &data)
{
    if (data.empty())
    {
        return std::vector<uint8_t>();
    }

    switch (algorithm_)
    {
    case CompressionAlgorithm::NONE:
        return data;

    case CompressionAlgorithm::ZLIB:
        return compressZlib(data);

    case CompressionAlgorithm::ZSTD:
        return compressZstd(data);

    case CompressionAlgorithm::LZ4:
        return compressLz4(data);

    default:
        throw std::runtime_error("Unsupported compression algorithm");
    }
}

std::vector<uint8_t> Compression::compressString(const std::string &data)
{
    if (data.empty())
    {
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> input(data.begin(), data.end());
    return compress(input);
}

std::vector<uint8_t> Compression::decompress(const std::vector<uint8_t> &compressedData)
{
    if (compressedData.empty())
    {
        return std::vector<uint8_t>();
    }

    switch (algorithm_)
    {
    case CompressionAlgorithm::NONE:
        return compressedData;

    case CompressionAlgorithm::ZLIB:
        return decompressZlib(compressedData);

    case CompressionAlgorithm::ZSTD:
        return decompressZstd(compressedData);

    case CompressionAlgorithm::LZ4:
        return decompressLz4(compressedData);

    default:
        throw std::runtime_error("Unsupported compression algorithm");
    }
}

std::string Compression::decompressToString(const std::vector<uint8_t> &compressedData)
{
    std::vector<uint8_t> decompressed = decompress(compressedData);
    return std::string(decompressed.begin(), decompressed.end());
}

size_t Compression::getDecompressedSize(const std::vector<uint8_t> &compressedData)
{
    if (compressedData.empty())
    {
        return 0;
    }

    switch (algorithm_)
    {
    case CompressionAlgorithm::NONE:
        return compressedData.size();

#ifdef ZSTD_FOUND
    case CompressionAlgorithm::ZSTD:
        return ZSTD_getFrameContentSize(compressedData.data(), compressedData.size());
#endif

    default:
        return 0; // Unknown for other algorithms
    }
}

double Compression::calculateCompressionRatio(size_t originalSize, size_t compressedSize)
{
    if (originalSize == 0 || compressedSize == 0)
    {
        return 1.0;
    }
    return static_cast<double>(originalSize) / static_cast<double>(compressedSize);
}

int Compression::getLevelValue() const
{
    switch (level_)
    {
    case CompressionLevel::FASTEST:
        return 1;

    case CompressionLevel::DEFAULT:
        return 6;

    case CompressionLevel::BEST:
        return 9;

    default:
        return 6;
    }
}

// ZLIB implementation
std::vector<uint8_t> Compression::compressZlib(const std::vector<uint8_t> &data)
{
#ifdef ZLIB_FOUND
    if (data.empty())
    {
        return std::vector<uint8_t>();
    }

    // Calculate max compressed buffer size
    uLongf compressedSize = compressBound(data.size());
    std::vector<uint8_t> result(compressedSize);

    // Compress data
    int zlibResult = compress2(
        result.data(),
        &compressedSize,
        data.data(),
        data.size(),
        getLevelValue());

    if (zlibResult != Z_OK)
    {
        throw std::runtime_error("ZLIB compression failed");
    }

    // Resize to actual compressed size
    result.resize(compressedSize);
    return result;
#else
    throw std::runtime_error("ZLIB compression not available");
#endif
}

std::vector<uint8_t> Compression::decompressZlib(const std::vector<uint8_t> &compressedData)
{
#ifdef ZLIB_FOUND
    if (compressedData.empty())
    {
        return std::vector<uint8_t>();
    }

    // Initial output buffer size (start with 2x compressed size)
    uLongf decompressedSize = compressedData.size() * 2;
    std::vector<uint8_t> result(decompressedSize);

    // Try decompression
    int zlibResult = uncompress(
        result.data(),
        &decompressedSize,
        compressedData.data(),
        compressedData.size());

    // If buffer was too small, retry with larger buffer
    if (zlibResult == Z_BUF_ERROR)
    {
        decompressedSize = compressedData.size() * 10; // Try 10x size
        result.resize(decompressedSize);

        zlibResult = uncompress(
            result.data(),
            &decompressedSize,
            compressedData.data(),
            compressedData.size());
    }

    if (zlibResult != Z_OK)
    {
        throw std::runtime_error("ZLIB decompression failed");
    }

    // Resize to actual decompressed size
    result.resize(decompressedSize);
    return result;
#else
    throw std::runtime_error("ZLIB decompression not available");
#endif
}

// Zstandard implementation
std::vector<uint8_t> Compression::compressZstd(const std::vector<uint8_t> &data)
{
#ifdef ZSTD_FOUND
    if (data.empty())
    {
        return std::vector<uint8_t>();
    }

    // Calculate max compressed buffer size
    size_t compressedSize = ZSTD_compressBound(data.size());
    std::vector<uint8_t> result(compressedSize);

    // Compress data
    size_t zstdResult = ZSTD_compress(
        result.data(),
        compressedSize,
        data.data(),
        data.size(),
        getLevelValue());

    if (ZSTD_isError(zstdResult))
    {
        throw std::runtime_error("ZSTD compression failed: " + std::string(ZSTD_getErrorName(zstdResult)));
    }

    // Resize to actual compressed size
    result.resize(zstdResult);
    return result;
#else
    throw std::runtime_error("ZSTD compression not available");
#endif
}

std::vector<uint8_t> Compression::decompressZstd(const std::vector<uint8_t> &compressedData)
{
#ifdef ZSTD_FOUND
    if (compressedData.empty())
    {
        return std::vector<uint8_t>();
    }

    // Get decompressed size
    size_t decompressedSize = ZSTD_getFrameContentSize(compressedData.data(), compressedData.size());

    if (decompressedSize == ZSTD_CONTENTSIZE_UNKNOWN || decompressedSize == ZSTD_CONTENTSIZE_ERROR)
    {
        throw std::runtime_error("ZSTD unknown content size");
    }

    std::vector<uint8_t> result(decompressedSize);

    // Decompress data
    size_t zstdResult = ZSTD_decompress(
        result.data(),
        decompressedSize,
        compressedData.data(),
        compressedData.size());

    if (ZSTD_isError(zstdResult))
    {
        throw std::runtime_error("ZSTD decompression failed: " + std::string(ZSTD_getErrorName(zstdResult)));
    }

    return result;
#else
    throw std::runtime_error("ZSTD decompression not available");
#endif
}

// LZ4 implementation
std::vector<uint8_t> Compression::compressLz4(const std::vector<uint8_t> &data)
{
#ifdef LZ4_FOUND
    if (data.empty())
    {
        return std::vector<uint8_t>();
    }

    // Calculate max compressed buffer size
    int maxCompressedSize = LZ4_compressBound(data.size());
    std::vector<uint8_t> result(maxCompressedSize + sizeof(int)); // Add space for original size

    // Store original size at beginning of compressed data
    *reinterpret_cast<int *>(result.data()) = static_cast<int>(data.size());

    // Compress data
    int compressedSize = LZ4_compress_default(
        reinterpret_cast<const char *>(data.data()),
        reinterpret_cast<char *>(result.data() + sizeof(int)),
        data.size(),
        maxCompressedSize);

    if (compressedSize <= 0)
    {
        throw std::runtime_error("LZ4 compression failed");
    }

    // Resize to actual compressed size plus size header
    result.resize(compressedSize + sizeof(int));
    return result;
#else
    throw std::runtime_error("LZ4 compression not available");
#endif
}

std::vector<uint8_t> Compression::decompressLz4(const std::vector<uint8_t> &compressedData)
{
#ifdef LZ4_FOUND
    if (compressedData.empty() || compressedData.size() <= sizeof(int))
    {
        return std::vector<uint8_t>();
    }

    // Get original size from beginning of compressed data
    int decompressedSize = *reinterpret_cast<const int *>(compressedData.data());

    if (decompressedSize <= 0)
    {
        throw std::runtime_error("Invalid LZ4 compressed data");
    }

    std::vector<uint8_t> result(decompressedSize);

    // Decompress data
    int lz4Result = LZ4_decompress_safe(
        reinterpret_cast<const char *>(compressedData.data() + sizeof(int)),
        reinterpret_cast<char *>(result.data()),
        compressedData.size() - sizeof(int),
        decompressedSize);

    if (lz4Result <= 0)
    {
        throw std::runtime_error("LZ4 decompression failed");
    }

    return result;
#else
    throw std::runtime_error("LZ4 decompression not available");
#endif
}