#!/bin/bash
# Abort on the first failing command rather than pressing on and reporting success.
set -eo pipefail

# === Configuration Options ===
# Set to 1 to enable aggressive optimizations (requires CPU with AVX2/FMA support)
# Set to 0 for more compatible builds
ENABLE_OPTIMIZATIONS=1

# Navigate to project root directory
cd ../../..
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"
echo "🏠 Working from project root: $PROJECT_ROOT"


# === Check for AFL++ and select best compiler ===
echo "🔍 Checking for AFL++ compilers..."

# TODO: Resolve `alf-clang-lto` errors
#if command -v afl-clang-lto &> /dev/null; then
#    echo "✅ Found afl-clang-lto (recommended LTO mode)"
#    CC=afl-clang-lto
#    CXX=afl-clang-lto++
if command -v afl-clang-fast &> /dev/null; then
    echo "✅ Found afl-clang-fast (LLVM mode)"
    CC=afl-clang-fast
    CXX=afl-clang-fast++
elif command -v afl-gcc-fast &> /dev/null; then
    echo "✅ Found afl-gcc-fast (GCC plugin mode)"
    CC=afl-gcc-fast
    CXX=afl-g++-fast
elif command -v afl-gcc &> /dev/null; then
    echo "✅ Found afl-gcc (basic AFL instrumentation)"
    CC=afl-gcc
    CXX=afl-g++
else
    echo "❌ ERROR: No AFL++ compilers found. Please install AFL++ first:"
    echo "    git clone https://github.com/AFLplusplus/AFLplusplus"
    echo "    cd AFLplusplus && make && sudo make install"
    echo "See: https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md"
    exit 1
fi

# Export the selected compiler
export CC=$CC
export CXX=$CXX

# Number of CPU cores for parallel compilation
CORES=$(nproc)

# Set optimization flags based on configuration
if [ $ENABLE_OPTIMIZATIONS -eq 1 ]; then
    echo "⚠️  Using aggressive optimizations (requires CPU with AVX2/FMA support)"
    OPT_FLAGS="-O3 -march=native -mtune=native -flto -funroll-loops -ffast-math -mavx2 -mfma"
else
    echo "ℹ️  Using standard optimization level (compatible with most CPUs)"
    OPT_FLAGS="-O2"
fi

# === Compile without ASan ===
echo "🔨 Compiling CryptoLib without ASan..."
rm -rf build
mkdir -p build/fuzz && cd build/fuzz
cmake $PROJECT_ROOT -B $PROJECT_ROOT/build/fuzz \
  -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$OPT_FLAGS" \
  -DCMAKE_CXX_FLAGS="$OPT_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="-flto" \
  -DCRYPTO_LIBGCRYPT=ON \
  -DENABLE_FUZZING=ON \
  -DDEBUG=ON \
  -DKEY_INTERNAL=ON \
  -DMC_INTERNAL=ON \
  -DSA_INTERNAL=ON
make -j$CORES
cd ..

# === Compile with ASan ===
echo "🔨 Compiling CryptoLib with ASan..."
rm -rf fuzz-asan
mkdir fuzz-asan && cd fuzz-asan
cmake $PROJECT_ROOT -B $PROJECT_ROOT/build/fuzz-asan \
  -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="-fsanitize=address $OPT_FLAGS" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address $OPT_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address -flto" \
  -DCRYPTO_LIBGCRYPT=ON \
  -DENABLE_FUZZING=ON \
  -DDEBUG=ON \
  -DKEY_INTERNAL=ON \
  -DMC_INTERNAL=ON \
  -DSA_INTERNAL=ON
make -j$CORES
cd ..

# === Compile with CmpLog ===
echo "🔨 Compiling CryptoLib with CmpLog instrumentation..."
rm -rf fuzz-cmplog
mkdir fuzz-cmplog && cd fuzz-cmplog
export AFL_LLVM_CMPLOG=1 # Enable CmpLog instrumentation
cmake $PROJECT_ROOT -B $PROJECT_ROOT/build/fuzz-cmplog \
  -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$OPT_FLAGS" \
  -DCMAKE_CXX_FLAGS="$OPT_FLAGS" \
  -DCRYPTO_LIBGCRYPT=ON \
  -DENABLE_FUZZING=ON \
  -DDEBUG=ON \
  -DKEY_INTERNAL=ON \
  -DMC_INTERNAL=ON \
  -DSA_INTERNAL=ON
make -j$CORES
unset AFL_LLVM_CMPLOG # Unset to avoid affecting other builds
cd ..

# === Compile with CompCov (laf-intel) ===
echo "🔨 Compiling CryptoLib with CompCov (laf-intel) instrumentation..."
rm -rf fuzz-compcov
mkdir fuzz-compcov && cd fuzz-compcov
export AFL_LLVM_LAF_ALL=1 # Enable CompCov instrumentation
cmake $PROJECT_ROOT -B $PROJECT_ROOT/build/fuzz-compcov \
  -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$OPT_FLAGS" \
  -DCMAKE_CXX_FLAGS="$OPT_FLAGS" \
  -DCRYPTO_LIBGCRYPT=ON \
  -DENABLE_FUZZING=ON \
  -DDEBUG=ON \
  -DKEY_INTERNAL=ON \
  -DMC_INTERNAL=ON \
  -DSA_INTERNAL=ON
make -j$CORES
unset AFL_LLVM_LAF_ALL # Unset to avoid affecting other builds
cd ..

# === Verify Build Output ===
# make can succeed without producing the harness (e.g. if the target was skipped),
# so check for the binaries explicitly before reporting success.
MISSING_BINARIES=0
for BUILD_DIR in fuzz fuzz-asan fuzz-cmplog fuzz-compcov; do
  if [ ! -x "$PROJECT_ROOT/build/$BUILD_DIR/bin/fuzz_harness" ]; then
    echo "❌ ERROR: build/$BUILD_DIR/bin/fuzz_harness was not produced"
    MISSING_BINARIES=1
  fi
done
if [ "$MISSING_BINARIES" -ne 0 ]; then
  echo "❌ Fuzz harness build FAILED - see the compiler output above."
  exit 1
fi

# === Final Status ===
echo "✅ Build complete!"
echo "📂 Non-ASan build:     'build/fuzz/'"
echo "📂 ASan build:         'build/fuzz-asan/'"
echo "📂 CmpLog build:       'build/fuzz-cmplog/'"
echo "📂 CompCov (laf-intel) build: 'build/fuzz-compcov/'"
echo ""
echo "To run fuzzing with AFL++:"
echo "$(dirname "$0")/run-fuzz-multithreaded.sh"
echo ""
echo "⚠️  AFL++ SYSTEM CONFIGURATION REMINDERS ⚠️"
echo "For optimal fuzzing performance, consider running these commands:"
echo ""
echo "1️⃣  Disable CPU frequency scaling:"
echo "   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
echo ""
echo "2️⃣  Configure core pattern for crash analysis:"
echo "   echo core | sudo tee /proc/sys/kernel/core_pattern"
echo ""
echo "📋 TROUBLESHOOTING FUZZING SESSIONS 📋"
echo "If the fuzzer does not start or you encounter issues:"
echo ""
echo "1. List all screen sessions:"
echo "   screen -ls"
echo ""
echo "2. Reattach to a specific session to see errors:"
echo "   screen -r session_name"
echo ""
echo "3. To detach from a screen session: Press Ctrl+A, then D"
