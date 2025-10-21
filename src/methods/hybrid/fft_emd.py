from src.helpers.binary_massage import binary_to_message, message_to_binary

from src.methods.frequency.fft import FFTSteganography
from src.methods.spatial.emd import EMDSteganography


class FFTEMDHybrid:

    def __init__(self, fft_emd_ratio=(0.5, 0.5), fft_params=None, emd_params=None):
        if sum(fft_emd_ratio) != 1.0:
            raise ValueError("Jumlah fft_emd_ratio harus 1.0")

        self.fft_ratio = fft_emd_ratio[0]
        self.emd_ratio = fft_emd_ratio[1]

        self.fft_steganography = FFTSteganography(**(fft_params or {}))
        self.emd_steganography = EMDSteganography(**(emd_params or {}))

    def embed(self, cover_image, secret_message):

        full_binary_message = message_to_binary(secret_message)
        split_point = int(len(full_binary_message) * self.fft_ratio)

        fft_message_part = binary_to_message(full_binary_message[:split_point])
        emd_message_part = binary_to_message(full_binary_message[split_point:])

        intermediate_stego, fft_bit_length = self.fft_steganography.embed(
            cover_image.copy(), fft_message_part
        )

        final_stego, emd_bit_length = self.emd_steganography.embed(
            intermediate_stego, emd_message_part
        )

        return final_stego, (fft_bit_length, emd_bit_length)

    def extract(self, stego_image, bit_lengths):
        fft_bit_length, emd_bit_length = bit_lengths

        emd_message_part = self.emd_steganography.extract(
            stego_image, emd_bit_length)

        fft_message_part = self.fft_steganography.extract(
            stego_image, fft_bit_length)

        if fft_message_part is None:
            fft_message_part = ""

        return fft_message_part + emd_message_part
