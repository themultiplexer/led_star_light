import zlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def aes_decrypt_cbc(ciphertext_hex, key_hex, iv_hex):
    # Convert hex to bytes
    ciphertext = bytes.fromhex(ciphertext_hex)
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)

    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and unpad (PKCS7)
    decrypted = cipher.decrypt(ciphertext)
    try:
        decrypted = unpad(decrypted, AES.block_size)
    except ValueError:
        print("[!] Warning: Unpadding failed. Data may not be properly padded.")
    
    return decrypted


def xor_brute_force(hex_string):
    data = bytes.fromhex(hex_string)

    for key in range(256):
        xored = bytes(b ^ key for b in data)
        printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in xored)
        print(f"Key {key:02X}: {printable}")


# Hexadecimal payload without the 'aa' start and 'aa55' end
payload = "00000055aa000006b50000000d00000037332e33000000000000002100065a4ee294d4ce0d3852e421e0aed7313f5c0656b333f24acbd27900551d55b51c96a4"
#payload = "aa000006a10000000d00000037332e33000000000000000d00065a4ee294d4ce0d3852e421e0aed7313f5c0656b333f24acbd27900551d55b51c96a4"

# Convert the hex string to a byte array
byte_array = bytes.fromhex(payload)

# Perform XOR on all bytes
checksum = 0
for byte in byte_array:
    checksum ^= byte

# Print the result
print(f"XOR checksum: {checksum:08x}")

sum_checksum = sum(byte_array) & 0xFFFFFFFF
print(f"Sum checksum: {sum_checksum:08x}")

# Calculate the CRC32 checksum
crc_checksum = zlib.crc32(byte_array)

# Print the result in hexadecimal format
print(f"CRC32 checksum: {crc_checksum:08x}")


def rot_hex_string(hex_string, rot=13):
    data = bytes.fromhex(hex_string)
    # Apply ROT-N to each byte (Caesar cipher on byte level)
    rotated = bytes((b + rot) % 256 for b in data)
    # Convert to ASCII (non-printable chars will be shown as dots)
    ascii_output = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in rotated)

    return ascii_output

for i in range(255):
    print(rot_hex_string("c6b61a9c39bdb22840c691fda50172cb3ef06b9f70481fc739ff37298b04d081", i))

xor_brute_force("c6b61a9c39bdb22840c691fda50172cb3ef06b9f70481fc739ff37298b04d081")

