from Crypto.Cipher import AES
import codecs
import sys


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

class Encryption:
    def __init__(self):
        self.results = 0x00
        self.length = 0.0
    def encrypt(self, data, key, iv):
        hex_header = '2003043400ff0004' #This might need to be passed in as well
        hex_header += iv
        header_b = bytes.fromhex(hex_header)
        key_b = bytes.fromhex(key)
        iv_b = bytes.fromhex(iv)
        data_b = bytes.fromhex(data)

        cipher = AES.new(key_b, AES.MODE_GCM, nonce=iv_b)
        ciphertext, tag = cipher.encrypt_and_digest(data_b)

        final_val = header_b + ciphertext + tag

        check_sum = crc16(bytearray(final_val), 0, len(final_val))
        final_val += check_sum.to_bytes(2, byteorder = "big")

        while (len(final_val.hex()) %8) != 0:
            final_val += bytes.fromhex("00")

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

#if __name__ == '__main__':
#    something=Encryption()
#    something.encrypt("1880d2ca0008197f0b0031000039c5", "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210", "000000000000000000000001")
#    something.get_len()
#    something.get_results()


