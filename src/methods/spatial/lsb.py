import cv2
import numpy as np

from src.helpers.binary_massage import binary_to_message, message_to_binary


class LSBSteganography:
    def __init__(self, bits_per_channel=1):
        self.bits_per_channel = max(1, min(bits_per_channel, 4))

    def embed(self, cover_image: np.ndarray, secret_message: str) -> tuple:
        if len(cover_image.shape) == 2:
            cover_image = cv2.cvtColor(cover_image, cv2.COLOR_GRAY2RGB)

        stego_image = cover_image.copy()

        binary_message = message_to_binary(secret_message)
        bit_length = len(binary_message)

        height, width, channels = stego_image.shape
        max_capacity = height * width * channels * self.bits_per_channel

        if bit_length > max_capacity:
            raise ValueError(
                f"Message too long! Needs {bit_length} bits, but capacity is {max_capacity}."
            )

        binary_index = 0
        clear_mask = 255 - (2**self.bits_per_channel - 1)

        for row in range(height):
            for col in range(width):
                for channel in range(channels):
                    if binary_index >= bit_length:
                        return stego_image, bit_length

                    pixel_value = int(stego_image[row, col, channel])

                    pixel_value &= clear_mask

                    bits_to_embed_str = binary_message[binary_index:
                                                       binary_index + self.bits_per_channel]
                    embed_value = int(bits_to_embed_str, 2)

                    stego_image[row, col, channel] = pixel_value | embed_value

                    binary_index += len(bits_to_embed_str)

        return stego_image, bit_length

    def extract(self, stego_image: np.ndarray, bit_length: int) -> str:
        if len(stego_image.shape) == 2:
            stego_image = cv2.cvtColor(stego_image, cv2.COLOR_GRAY2RGB)

        height, width, channels = stego_image.shape
        extract_mask = (2**self.bits_per_channel - 1)

        extracted_bits = ""
        bits_to_extract = bit_length

        for row in range(height):
            for col in range(width):
                for channel in range(channels):
                    if len(extracted_bits) >= bits_to_extract:
                        final_binary_string = extracted_bits[:bits_to_extract]
                        return binary_to_message(final_binary_string)

                    pixel_value = int(stego_image[row, col, channel])
                    extracted_chunk = format(
                        pixel_value & extract_mask, f'0{self.bits_per_channel}b')
                    extracted_bits += extracted_chunk

        final_binary_string = extracted_bits[:bits_to_extract]
        return binary_to_message(final_binary_string)
