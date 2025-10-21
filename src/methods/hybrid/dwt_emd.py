from src.helpers.binary_massage import binary_to_message, message_to_binary

from src.methods.frequency.dwt import DWTSteganography
from src.methods.spatial.emd import EMDSteganography

class DWTEmdHybrid:
    def __init__(self, dwt_emd_ratio=(0.5, 0.5), dwt_params=None, emd_params=None):
        if sum(dwt_emd_ratio) != 1.0:
            raise ValueError("Jumlah dwt_emd_ratio harus 1.0")

        self.dwt_ratio = dwt_emd_ratio[0]
        self.emd_ratio = dwt_emd_ratio[1]

        self.dwt_steganography = DWTSteganography(**(dwt_params or {}))
        self.emd_steganography = EMDSteganography(**(emd_params or {}))

    def embed(self, cover_image, secret_message):

        full_binary_message = message_to_binary(secret_message)
        split_point = int(len(full_binary_message) * self.dwt_ratio)

        dwt_message_part = binary_to_message(full_binary_message[:split_point])
        emd_message_part = binary_to_message(full_binary_message[split_point:])

        intermediate_stego, dwt_bit_length = self.dwt_steganography.embed(
            cover_image.copy(), dwt_message_part
        )

        final_stego, emd_bit_length = self.emd_steganography.embed(
            intermediate_stego, emd_message_part
        )

        return final_stego, (dwt_bit_length, emd_bit_length)

    def extract(self, stego_image, bit_lengths):
        dwt_bit_length, emd_bit_length = bit_lengths

        emd_message_part = self.emd_steganography.extract(stego_image, emd_bit_length)

        dwt_message_part = self.dwt_steganography.extract(stego_image, dwt_bit_length)

        return dwt_message_part + emd_message_part