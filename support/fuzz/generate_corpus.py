#!/usr/bin/env python3

import os
import random
import argparse
from pathlib import Path


def ensure_dir(directory):
    """Create directory if it doesn't exist"""
    Path(directory).mkdir(parents=True, exist_ok=True)


def generate_random_bytes(min_size, max_size):
    """Generate random bytes of size between min_size and max_size"""
    size = random.randint(min_size, max_size)
    return bytes(random.randint(0, 255) for _ in range(size))


def generate_tc_frame():
    """Generate a TC frame with valid-looking header"""
    frame_size = random.randint(6, 1024)
    frame = bytearray(generate_random_bytes(frame_size, frame_size))

    # Set basic TC frame header fields
    frame[0] = 0x20  # Version 1, Type TC
    frame[1] = 0x03  # SCID
    frame[2] = 0x00 | ((frame_size - 1) >> 8); # VCID
    frame[3] = (frame_size - 1) & 0xFF; # Frame length
    frame[4] = 0x00; # Frame Sequence Number

    return frame


def generate_tm_frame():
    """Generate a TM frame with valid-looking header"""
    frame_size = 1786
    frame = bytearray(generate_random_bytes(frame_size, frame_size))

    # Set basic TM frame header fields
    frame[0] = 0x02  # Version 1, TM
    frame[1] = 0xC0  # SCID
    frame[2] = 0x00  # VCID

    return frame


def generate_aos_frame():
    """Generate an AOS frame with valid-looking header"""
    frame_size = 1786
    frame = bytearray(generate_random_bytes(frame_size, frame_size))

    # Set basic AOS frame header fields
    frame[0] = 0x40  # Version 1, AOS
    frame[1] = 0xC0  # SCID
    frame[2] = 0x00  # VCID

    return frame


def generate_corpus(output_dir, num_samples_per_selector=5):
    """Generate corpus files for each selector value"""
    ensure_dir(output_dir)

    # Generate samples for each selector (0-6)
    for selector in range(7):
        for i in range(num_samples_per_selector):
            # File naming: selector_type_variant.bin
            if selector in [0, 1]:  # TC frame operations
                frame = generate_tc_frame()
                file_name = f"{selector:02d}_tc_{i:02d}.bin"
            elif selector in [2, 5]:  # TM frame operations
                frame = generate_tm_frame()
                file_name = f"{selector:02d}_tm_{i:02d}.bin"
            elif selector in [3, 4]:  # AOS frame operations
                frame = generate_aos_frame()
                file_name = f"{selector:02d}_aos_{i:02d}.bin"
            else:  # selector == 6, TC frame for FECF check
                frame = generate_tc_frame()
                file_name = f"{selector:02d}_tc_fecf_{i:02d}.bin"

            # Add the selector byte at the beginning
            output = bytearray([selector]) + frame

            # Write to file
            with open(os.path.join(output_dir, file_name), "wb") as f:
                f.write(output)

    # Generate some edge cases
    edge_cases = [
        # Minimal valid input (just selector)
        (0, bytearray([0])),
        (1, bytearray([1])),
        (2, bytearray([2])),
        (3, bytearray([3])),
        (4, bytearray([4])),
        (5, bytearray([5])),
        (6, bytearray([6])),

        # Very large inputs
        (0, bytearray([0]) + generate_random_bytes(2000, 2000)),
        (3, bytearray([3]) + generate_random_bytes(2000, 2000)),

        # Interesting byte patterns
        (0, bytearray([0]) + bytes([0xFF] * 50)),
        (1, bytearray([1]) + bytes([0x00] * 50)),
        (2, bytearray([2]) + bytes([i % 256 for i in range(100)])),
        (5, bytearray([5]) + bytes([0xAA, 0x55] * 25))  # Alternating bits
    ]

    for idx, (selector, data) in enumerate(edge_cases):
        file_name = f"edge_{idx:02d}_sel{selector}.bin"
        with open(os.path.join(output_dir, file_name), "wb") as f:
            f.write(data)


def main():
    parser = argparse.ArgumentParser(
        description='Generate corpus for CryptoLib fuzzer')
    parser.add_argument('--output', '-o', default='corpus',
                        help='Output directory for corpus files')
    parser.add_argument('--samples', '-n', type=int, default=5,
                        help='Number of samples per selector')
    args = parser.parse_args()

    print(f"Generating corpus in directory: {args.output}")
    generate_corpus(args.output, args.samples)
    print(f"Generated {7 * args.samples + 11} corpus files")


if __name__ == "__main__":
    main()
