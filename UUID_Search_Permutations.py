# This script is used to print out a UUID128 in different formats,
# which may appear in source code when searching sites like GitHub.
# Usage:
#   python3 UUID_Format_Permutation.py <UUID128 with or without dashes>
# Example:
#   python3 UUID_Format_Permutation.py 5052494D-2DAB-0341-6972-6F6861424C45
# Output:
#   Without dashes: 5052494D2DAB034169726F6861424C45
#   With dashes:    5052494D-2DAB-0341-6972-6F6861424C45
#   Little-endian C byte array: {0x45, 0x4C, 0x42, 0x61, 0x68, 0x6F, 0x72, 0x69, 0x41, 0x03, 0xAB, 0x2D, 0x4D, 0x49, 0x52, 0x50}
#   Little-endian C byte array (no spaces): 0x45,0x4C,0x42,0x61,0x68,0x6F,0x72,0x69,0x41,0x03,0xAB,0x2D,0x4D,0x49,0x52,0x50

import sys
import re

def normalize_uuid(uuid_str):
    # Remove dashes and convert to uppercase
    return re.sub(r'[^0-9A-Fa-f]', '', uuid_str).upper()

def with_dashes(uuid_str):
    # Insert dashes at standard UUID positions
    return f"{uuid_str[0:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:32]}"

def little_endian_bytes(uuid_str):
    # Convert hex string to bytes, reverse for little-endian
    b = bytes.fromhex(uuid_str)
    b_le = b[::-1]
    return b_le

def format_c_array(b_le, with_spaces=True):
    arr = [f"0x{byte:02X}" for byte in b_le]
    sep = ', ' if with_spaces else ','
    return sep.join(arr)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python UUID_Format_Permutation.py <UUID128>")
        sys.exit(1)

    input_uuid = sys.argv[1]
    uuid_nodash = normalize_uuid(input_uuid)
    if len(uuid_nodash) != 32:
        print("Error: UUID must be 128 bits (32 hex digits).")
        sys.exit(1)

    uuid_dash = with_dashes(uuid_nodash)
    b_le = little_endian_bytes(uuid_nodash)

    print("Without dashes: " + uuid_nodash)
    print("Without dashes, endian-swapped: " + b_le.hex().upper()) # This is for if someone got their endianness wrong
    print("With dashes:    " + uuid_dash)
    print("Little-endian C byte array: {" + format_c_array(b_le, with_spaces=True) + "}")
    print("Little-endian C byte array (no spaces): " + format_c_array(b_le, with_spaces=False))