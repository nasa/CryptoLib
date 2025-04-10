#!/bin/bash

# === CONFIGURABLE VARIABLES ===
# MEM_LIMIT=128                                       # Memory limit for AFL++
SEEDS_DIR="../corpus"                                 # Directory containing grammar mutator seed files
OUT_DIR="../output"                                   # AFL++ output directory
TARGET_BINARY="../../build/bin/fuzz_harness"          # Default build target
ASAN_BINARY="../../build-asan/bin/fuzz_harness"       # ASan build target
CMPLOG_BINARY="../../build-cmplog/bin/fuzz_harness"   # CMPLOG build target
COMPCOV_BINARY="../../build-compcov/bin/fuzz_harness" # CompCov (laf-intel) build target
NUM_CORES=$(($(nproc) - 2))                           # Use all cores except 2 for OS

# === CHECK IF AFL++ AND SCREEN ARE INSTALLED ===
if ! command -v afl-fuzz &>/dev/null; then
  echo "❌ AFL++ is not installed. Install it before running this script."
  exit 1
fi

if ! command -v screen &>/dev/null; then
  echo "❌ 'screen' is not installed. Install it with 'sudo apt-get install screen' or 'sudo dnf install screen'."
  exit 1
fi

# === CHECK IF USING VIRTUALBOX SHARED FOLDERS ===
TARGET_GROUP="vboxsf"
SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_GROUP=$(stat -c "%G" "$SCRIPT_PATH")
if [ "$SCRIPT_GROUP" = "$TARGET_GROUP" ]; then
  echo "ERROR - This script belongs to the group: $TARGET_GROUP - fuzzer not compatible with shared folders!"
  exit 0
fi

# === EXPORT GLOBAL ENVIRONMENT VARIABLES ===
export AFL_TESTCACHE_SIZE=100     # Enable caching of test cases
export AFL_IMPORT_FIRST=1         # Prioritize loading test cases from other fuzzers
export AFL_IGNORE_SEED_PROBLEMS=1 # Ignore problematic seeds

# === PRINT CONFIGURATION ===
echo "🚀 Starting AFL++ Multi-core Fuzzing in 'screen' sessions"
echo "📂 Output Directory: $OUT_DIR"
echo "💾 Memory Limit: $MEM_LIMIT MB"
echo "🖥️  Using $NUM_CORES cores for fuzzing."

# === START AFL++ FUZZING INSTANCES IN SCREEN SESSIONS ===

# Master Fuzzer: Using explore strategy
screen -dmS afl_main bash -c "AFL_FINAL_SYNC=1 AFL_AUTORESUME=1 afl-fuzz -M main0 -i '$SEEDS_DIR' -o '$OUT_DIR' -p explore -- '$TARGET_BINARY' @@; exec bash"

# Secondary Fuzzers Configuration Counters
ASAN_COUNT=0
CMPLOG_COUNT=0
COMPCOV_COUNT=0
MOPT_COUNT=0
OLD_QUEUE_COUNT=0
DISABLE_TRIM_COUNT=0

# Recommended Limits
CMPLOG_MAX=2
COMPCOV_MAX=3
MOPT_MAX=$(($NUM_CORES / 10))        # 10% for MOpt
OLD_QUEUE_MAX=$(($NUM_CORES / 10))   # 10% for old queue
DISABLE_TRIM_MIN=$(($NUM_CORES / 2)) # At least 50% for AFL_DISABLE_TRIM

# Power Schedules
POWER_SCHEDULES=("fast" "explore" "coe" "lin" "quad" "exploit" "rare")

# Start Secondary Fuzzers
for i in $(seq 1 $NUM_CORES); do
  FUZZER_NAME="main$i"
  SCREEN_SESSION="afl_$FUZZER_NAME"
  CMD="AFL_AUTORESUME=1 afl-fuzz -S '$FUZZER_NAME' -i '$SEEDS_DIR' -o '$OUT_DIR'"

  # Apply configurations based on counters and recommendations
  if [ $ASAN_COUNT -lt 1 ]; then
    CMD="AFL_USE_ASAN=1 $CMD -p fast -- '$ASAN_BINARY' @@"
    ASAN_COUNT=$((ASAN_COUNT + 1))
  elif [ $CMPLOG_COUNT -lt $CMPLOG_MAX ]; then
    if [ $CMPLOG_COUNT -eq 0 ]; then
      CMD="$CMD -p coe -l 2 -- '$CMPLOG_BINARY' @@"
    else
      CMD="$CMD -p lin -l 2AT -- '$CMPLOG_BINARY' @@"
    fi
    CMPLOG_COUNT=$((CMPLOG_COUNT + 1))
  elif [ $COMPCOV_COUNT -lt $COMPCOV_MAX ]; then
    CMD="$CMD -p explore -- '$COMPCOV_BINARY' @@"
    COMPCOV_COUNT=$((COMPCOV_COUNT + 1))
  elif [ $MOPT_COUNT -lt $MOPT_MAX ]; then
    CMD="$CMD -p quad -L 0 -- '$TARGET_BINARY' @@"
    MOPT_COUNT=$((MOPT_COUNT + 1))
  elif [ $OLD_QUEUE_COUNT -lt $OLD_QUEUE_MAX ]; then
    CMD="$CMD -p rare -Z -- '$TARGET_BINARY' @@"
    OLD_QUEUE_COUNT=$((OLD_QUEUE_COUNT + 1))
  elif [ $DISABLE_TRIM_COUNT -lt $DISABLE_TRIM_MIN ]; then
    CMD="AFL_DISABLE_TRIM=1 $CMD -p exploit -- '$TARGET_BINARY' @@"
    DISABLE_TRIM_COUNT=$((DISABLE_TRIM_COUNT + 1))
  else
    # Default configuration if all quotas are met
    RANDOM_POWER_SCHEDULE=${POWER_SCHEDULES[$((RANDOM % ${#POWER_SCHEDULES[@]}))]}
    CMD="$CMD -p $RANDOM_POWER_SCHEDULE -- '$TARGET_BINARY' @@"
  fi

  # Launch in screen session
  screen -dmS "$SCREEN_SESSION" bash -c "$CMD; exec bash"
  echo "🖥️  Started fuzzer in screen session '$SCREEN_SESSION'"
done

# === PERIODIC AFL++ STATUS UPDATES ===
sleep 10
echo "📊 Starting AFL++ status updates every 10 seconds (Press Ctrl+C to stop monitoring)..."
while true; do
  clear
  echo "📈 AFL++ Fuzzing Status (Updated every 10 seconds)"
  afl-whatsup -s "$OUT_DIR"
  sleep 10
done
