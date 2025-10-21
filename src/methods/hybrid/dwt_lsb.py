from src.helpers.binary_massage import binary_to_message, message_to_binary

from src.methods.frequency.dwt import DWTSteganography
from src.methods.spatial.lsb import LSBSteganography

class DWTLSBHybrid:

    def __init__(self, dwt_lsb_ratio=(0.5, 0.5), dwt_params=None, lsb_params=None):
        if sum(dwt_lsb_ratio) != 1.0:
            raise ValueError("Jumlah dwt_lsb_ratio harus 1.0")

        self.dwt_ratio = dwt_lsb_ratio[0]
        self.lsb_ratio = dwt_lsb_ratio[1]

        self.dwt_steganography = DWTSteganography(**(dwt_params or {}))
        self.lsb_steganography = LSBSteganography(**(lsb_params or {}))

    def embed(self, cover_image, secret_message):

        full_binary_message = message_to_binary(secret_message)
        split_point = int(len(full_binary_message) * self.dwt_ratio)

        dwt_message_part = binary_to_message(full_binary_message[:split_point])
        lsb_message_part = binary_to_message(full_binary_message[split_point:])

        intermediate_stego, dwt_bit_length = self.dwt_steganography.embed(
            cover_image.copy(), dwt_message_part
        )

        final_stego, lsb_bit_length = self.lsb_steganography.embed(
            intermediate_stego, lsb_message_part
        )

        return final_stego, (dwt_bit_length, lsb_bit_length)

    def extract(self, stego_image, bit_lengths):
        dwt_bit_length, lsb_bit_length = bit_lengths

        lsb_message_part = self.lsb_steganography.extract(
            stego_image, lsb_bit_length)

        dwt_message_part = self.dwt_steganography.extract(
            stego_image, dwt_bit_length)

        return dwt_message_part + lsb_message_part
