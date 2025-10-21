from src.helpers.binary_massage import binary_to_message, message_to_binary

from src.methods.frequency.dct import DCTSteganography
from src.methods.spatial.pvd import PVDSteganography


class DCTPVDHybrid:

    def __init__(self, dct_pvd_ratio=(0.5, 0.5), dct_params=None, pvd_params=None):
        if sum(dct_pvd_ratio) != 1.0:
            raise ValueError("Jumlah dct_pvd_ratio harus 1.0")

        self.dct_ratio = dct_pvd_ratio[0]
        self.pvd_ratio = dct_pvd_ratio[1]

        self.dct_steganography = DCTSteganography(**(dct_params or {}))
        self.pvd_steganography = PVDSteganography(**(pvd_params or {}))

    def embed(self, cover_image, secret_message):

        full_binary_message = message_to_binary(secret_message)
        total_bits = len(full_binary_message)
        split_point = int(total_bits * self.dct_ratio)

        dct_binary_part = full_binary_message[:split_point]
        pvd_binary_part = full_binary_message[split_point:]

        dct_message_part = binary_to_message(dct_binary_part)
        pvd_message_part = binary_to_message(pvd_binary_part)

        intermediate_stego, dct_bit_length = self.dct_steganography.embed(
            cover_image.copy(), dct_message_part
        )

        final_stego, pvd_bit_length = self.pvd_steganography.embed(
            intermediate_stego, pvd_message_part
        )

        return final_stego, (dct_bit_length, pvd_bit_length)

    def extract(self, stego_image, bit_lengths):
        dct_bit_length, pvd_bit_length = bit_lengths

        pvd_message_part = self.pvd_steganography.extract(
            stego_image, pvd_bit_length)

        dct_message_part = self.dct_steganography.extract(
            stego_image, dct_bit_length)

        return dct_message_part + pvd_message_part
