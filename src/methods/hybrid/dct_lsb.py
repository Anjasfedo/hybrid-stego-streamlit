from src.helpers.binary_massage import message_to_binary, binary_to_message
from src.methods.frequency.dct import DCTSteganography
from src.methods.spatial.lsb import LSBSteganography


class DCTLSBHybrid:

    def __init__(self, dct_lsb_ratio=(0.5, 0.5), dct_params=None, lsb_params=None):
        if sum(dct_lsb_ratio) != 1.0:
            raise ValueError("Jumlah dct_lsb_ratio harus 1.0")

        self.dct_ratio = dct_lsb_ratio[0]
        self.lsb_ratio = dct_lsb_ratio[1]

        self.dct_steganography = DCTSteganography(**(dct_params or {}))
        self.lsb_steganography = LSBSteganography(**(lsb_params or {}))

    def embed(self, cover_image, secret_message):

        full_binary_message = message_to_binary(secret_message)
        total_bits = len(full_binary_message)
        split_point = int(total_bits * self.dct_ratio)

        dct_binary_part = full_binary_message[:split_point]
        lsb_binary_part = full_binary_message[split_point:]

        dct_message_part = binary_to_message(dct_binary_part)
        lsb_message_part = binary_to_message(lsb_binary_part)

        intermediate_stego, dct_bit_length = self.dct_steganography.embed(
            cover_image.copy(), dct_message_part
        )

        final_stego, lsb_bit_length = self.lsb_steganography.embed(
            intermediate_stego, lsb_message_part
        )

        return final_stego, (dct_bit_length, lsb_bit_length)

    def extract(self, stego_image, bit_lengths):
        dct_bit_length, lsb_bit_length = bit_lengths

        lsb_message_part = self.lsb_steganography.extract(
            stego_image, lsb_bit_length)

        dct_message_part = self.dct_steganography.extract(
            stego_image, dct_bit_length)

        return dct_message_part + lsb_message_part
