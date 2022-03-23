from Crypto.Cipher import AES
from Crypto.Hash import CMAC, HMAC, SHA256, SHA512
import codecs
import sys

"""
Function: crc16
Calculates the CRC16 for a set of byte data
@param data: byte array
@param offset: int
@param length: int
"""
def crc16(data : bytearray, offset , length):
    if data is None or offset < 0 or offset > len(data)- 1 and offset+length > len(data):
        return 0
    crc = 0xFFFF
    for i in range(0, length):
        crc ^= data[offset + i] << 8
        for j in range(0,8):
            if (crc & 0x8000) > 0:
                crc =(crc << 1) ^ 0x1021
            else:
                crc = crc << 1
    return crc & 0xFFFF


"""
Class: Encryption
This class is used to perform AES, GCM encryption in order to provide a truth baseline.
The baseline is compared against output created by gcrypt within TC_ApplySecurity
"""
class Encryption:
    def __init__(self):
        self.results = 0x00
        self.length = 0.0

    # Function: Encrypt
    # Encrypts data - given a key, iv, header, and bitmask
    def encrypt(self, data, key, iv, header, bitmask):
        hex_header = header + iv             # Combines Header and IV (AAD)
        bitmask_b = bytes.fromhex(bitmask)      
        header_b = bytes.fromhex(hex_header)
        key_b = bytes.fromhex(key)
        iv_b = bytes.fromhex(iv)
        data_b = bytes.fromhex(data)

        # Create Cipher
        cipher = AES.new(key_b, AES.MODE_GCM, nonce=iv_b)

        # Performs some bitmasking if necessary -  This will need work if we get more advanced in testing
        if len(bitmask) > 1:
            zeroed_header = ''
            zeroed_header_b = bytes.fromhex(zeroed_header)            
            # Right now we're only zeroing out the header based on the bitmask existing
            L = [header_b[i:i+1] for i in range (len(header_b))]

            for pieces in L:
                value_i = int.from_bytes(pieces, byteorder="big") & int.from_bytes(bitmask_b, byteorder="big")
                value_b = value_i.to_bytes(max(len(pieces), len(bitmask_b)), byteorder="big")
                zeroed_header_b += value_b
            print("ZEROED AAD:", zeroed_header_b.hex())
            print("DATA:", data_b.hex())
            cipher.update(zeroed_header_b)
            #cipher.update(header_b)
        # Get Cipher and tag
        ciphertext, tag = cipher.encrypt_and_digest(data_b)
        print("Cipher: ", ciphertext.hex())
        print("Tag: ", tag.hex())
        
        # Create final_val with non-zeroed header, cipher, and tag
        final_val = header_b + ciphertext + tag

        # Calculate check_sum
        check_sum = crc16(bytearray(final_val), 0, len(final_val))
        # Apply CRC to final_val
        final_val += check_sum.to_bytes(2, byteorder = "big")

        print(final_val.hex())
        # Padding for Later
        # while (len(final_val.hex()) %8) != 0:
        #     final_val += bytes.fromhex("00")

        final_val_len = (len(final_val.hex()) / 2)
        self.results = final_val
        self.length = final_val_len
        #print(self.results, self.length)

    def get_len(self):
        #print(self.length)
        return self.length
    
    def get_results(self):
        #print(self.results.hex())
        return self.results

class Authentication:
    def __init__(self):
        self.results = 0x00
        self.length = 0.0

    def encrypt_cmac(self, data, key):
        data_b = bytes.fromhex(data)
        key_b = bytes.fromhex(key)

        cmac_obj = CMAC.new(key_b, ciphermod=AES)
        cmac_obj.update(data_b)

        self.results = cmac_obj.hexdigest()
        print(self.results)
        self.length = len(self.results)

    def encrypt_hmac_sha256(self, data, key):
        data_b = bytes.fromhex(data)
        key_b = bytes.fromhex(key)

        hmac_obj = HMAC.new(key_b, digestmod=SHA256)
        hmac_obj.update(data_b)

        self.results = hmac_obj.hexdigest()
        print(self.results)
        self.length = len(self.results)

    def encrypt_hmac_sha512(self, data, key):
        data_b = bytes.fromhex(data)
        key_b = bytes.fromhex(key)

        hmac_obj = HMAC.new(key_b, digestmod=SHA512)
        hmac_obj.update(data_b)

        self.results = hmac_obj.hexdigest()
        print(self.results)
        self.length = len(self.results)    

    def get_len(self):
        #print(self.length)
        return self.length
    
    def get_results(self):
        #print(self.results.hex())
        return self.results

if __name__ == '__main__':
    something=Authentication()
    something.encrypt_hmac_sha512("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445")
    something.get_len()
    something.get_results()