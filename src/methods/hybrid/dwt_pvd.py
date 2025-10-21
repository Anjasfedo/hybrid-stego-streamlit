from src.helpers.binary_massage import binary_to_message, message_to_binary

from src.methods.frequency.dwt import DWTSteganography
from src.methods.spatial.pvd import PVDSteganography


class DWTPVDHybrid:

    def __init__(self, dwt_pvd_ratio=(0.5, 0.5), dwt_params=None, pvd_params=None):
        if sum(dwt_pvd_ratio) != 1.0:
            raise ValueError("Jumlah dwt_pvd_ratio harus 1.0")

        self.dwt_ratio = dwt_pvd_ratio[0]
        self.pvd_ratio = dwt_pvd_ratio[1]

        self.dwt_steganography = DWTSteganography(**(dwt_params or {}))
        self.pvd_steganography = PVDSteganography(**(pvd_params or {}))

    def embed(self, cover_image, secret_message):

        full_binary_message = message_to_binary(secret_message)
        split_point = int(len(full_binary_message) * self.dwt_ratio)

        dwt_message_part = binary_to_message(full_binary_message[:split_point])
        pvd_message_part = binary_to_message(full_binary_message[split_point:])

        intermediate_stego, dwt_bit_length = self.dwt_steganography.embed(
            cover_image.copy(), dwt_message_part
        )

        final_stego, pvd_bit_length = self.pvd_steganography.embed(
            intermediate_stego, pvd_message_part
        )

        return final_stego, (dwt_bit_length, pvd_bit_length)

    def extract(self, stego_image, bit_lengths):
        dwt_bit_length, pvd_bit_length = bit_lengths

        pvd_message_part = self.pvd_steganography.extract(
            stego_image, pvd_bit_length)

        dwt_message_part = self.dwt_steganography.extract(
            stego_image, dwt_bit_length)

        return dwt_message_part + pvd_message_part
