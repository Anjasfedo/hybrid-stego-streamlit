from src.helpers.binary_massage import binary_to_message, message_to_binary

from src.methods.frequency.dct import DCTSteganography
from src.methods.spatial.emd import EMDSteganography

class DCTEMDHybrid:

    def __init__(self, dct_emd_ratio=(0.5, 0.5), dct_params=None, emd_params=None):
        if sum(dct_emd_ratio) != 1.0:
            raise ValueError("Jumlah dct_emd_ratio harus 1.0")

        self.dct_ratio = dct_emd_ratio[0]
        self.emd_ratio = dct_emd_ratio[1]

        self.dct_steganography = DCTSteganography(**(dct_params or {}))
        self.emd_steganography = EMDSteganography(**(emd_params or {}))

    def embed(self, cover_image, secret_message):

        full_binary_message = message_to_binary(secret_message)
        split_point = int(len(full_binary_message) * self.dct_ratio)

        dct_message_part = binary_to_message(full_binary_message[:split_point])
        emd_message_part = binary_to_message(full_binary_message[split_point:])

        intermediate_stego, dct_bit_length = self.dct_steganography.embed(
            cover_image.copy(), dct_message_part
        )

        final_stego, emd_bit_length = self.emd_steganography.embed(
            intermediate_stego, emd_message_part
        )

        return final_stego, (dct_bit_length, emd_bit_length)

    def extract(self, stego_image, bit_lengths):
        dct_bit_length, emd_bit_length = bit_lengths

        emd_message_part = self.emd_steganography.extract(
            stego_image, emd_bit_length)

        dct_message_part = self.dct_steganography.extract(
            stego_image, dct_bit_length)

        return dct_message_part + emd_message_part
