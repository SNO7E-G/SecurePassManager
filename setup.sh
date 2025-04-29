#!/bin/bash

echo "SecurePassManager Setup Script"
echo "============================="
echo ""

# Check if running with sudo/root privileges
if [ "$EUID" -ne 0 ]; then
  echo "This script requires root privileges to install dependencies."
  echo "Please run with sudo:"
  echo "  sudo $0"
  exit 1
fi

# Detect OS
if [ "$(uname)" == "Darwin" ]; then
  # macOS
  OS="macOS"
  echo "Detected macOS system"
  
  # Check for Homebrew
  if ! command -v brew &> /dev/null; then
    echo "Homebrew not found. Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    if [ $? -ne 0 ]; then
      echo "Failed to install Homebrew."
      exit 1
    fi
  fi
  
  echo "Installing/updating dependencies..."
  brew update
  brew install cmake ninja openssl sqlite
  brew upgrade cmake ninja openssl sqlite
  
  # Set OpenSSL paths for CMake
  export OPENSSL_ROOT_DIR=$(brew --prefix openssl)
  
elif [ -f /etc/debian_version ]; then
  # Debian/Ubuntu
  OS="Debian/Ubuntu"
  echo "Detected Debian/Ubuntu system"
  
  echo "Updating package lists..."
  apt-get update
  
  echo "Installing dependencies..."
  apt-get install -y build-essential cmake ninja-build libssl-dev libsqlite3-dev
  
elif [ -f /etc/fedora-release ]; then
  # Fedora
  OS="Fedora"
  echo "Detected Fedora system"
  
  echo "Installing dependencies..."
  dnf install -y gcc g++ make cmake ninja-build openssl-devel sqlite-devel
  
elif [ -f /etc/arch-release ]; then
  # Arch Linux
  OS="Arch Linux"
  echo "Detected Arch Linux system"
  
  echo "Installing dependencies..."
  pacman -Syu --noconfirm gcc make cmake ninja openssl sqlite
  
else
  echo "Unsupported Linux distribution. Please install dependencies manually:"
  echo "  - CMake (3.15+)"
  echo "  - C++ compiler with C++17 support"
  echo "  - OpenSSL development libraries"
  echo "  - SQLite3 development libraries"
  exit 1
fi

echo ""
echo "Building SecurePassManager..."
echo ""

# Create build directory
mkdir -p build
cd build

# Configure with CMake
echo "Running CMake configuration..."
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
if [ $? -ne 0 ]; then
  echo "CMake configuration failed."
  exit 1
fi

# Build the project
echo "Building project (this may take a few minutes)..."
cmake --build .
if [ $? -ne 0 ]; then
  echo "Build failed."
  exit 1
fi

echo ""
echo "============================="
echo "SecurePassManager has been successfully built!"
echo ""
echo "You can find the executable at:"
echo "  $(pwd)/securepass"
echo ""
echo "To start using SecurePassManager, run:"
echo "  $(pwd)/securepass --help"
echo ""
echo "To install system-wide (optional):"
echo "  sudo cmake --install ."
echo ""
echo "Thank you for using SecurePassManager!"
echo "=============================" 