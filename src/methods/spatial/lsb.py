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

    def extract(self, stego_image: np.ndarray, bit_length: int) -> tuple:
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
                        message = binary_to_message(final_binary_string)
                        return message, bit_length

                    pixel_value = int(stego_image[row, col, channel])
                    extracted_chunk = format(
                        pixel_value & extract_mask, f'0{self.bits_per_channel}b')
                    extracted_bits += extracted_chunk

        final_binary_string = extracted_bits[:bits_to_extract]
        message = binary_to_message(final_binary_string)
        return message, bit_length

    def extract_auto(self, stego_image: np.ndarray) -> tuple:
        """
        Extract message automatically by detecting message boundaries.
        Looks for end-of-message markers or reasonable message termination.
        Returns (extracted_message, detected_bit_length)
        """
        if len(stego_image.shape) == 2:
            stego_image = cv2.cvtColor(stego_image, cv2.COLOR_GRAY2RGB)

        height, width, channels = stego_image.shape
        extract_mask = (2**self.bits_per_channel - 1)
        max_possible_bits = height * width * channels * self.bits_per_channel

        extracted_bits = ""

        for row in range(height):
            for col in range(width):
                for channel in range(channels):
                    pixel_value = int(stego_image[row, col, channel])
                    extracted_chunk = format(
                        pixel_value & extract_mask, f'0{self.bits_per_channel}b')
                    extracted_bits += extracted_chunk

                    # Try to decode message at various lengths to find valid UTF-8
                    if len(extracted_bits) >= 8:  # At least 1 byte
                        for possible_length in range(8, min(len(extracted_bits), 1000), 8):
                            try:
                                test_binary = extracted_bits[:possible_length]
                                test_message = binary_to_message(test_binary)

                                # Check if it looks like a complete message
                                # (ends with typical sentence terminators or reasonable length)
                                if (len(test_message) > 5 and
                                    (test_message.endswith(('.', '!', '?', '\n')) or
                                     len(test_message) > 50)):  # Reasonable message length

                                    return test_message, possible_length
                            except UnicodeDecodeError:
                                continue
                            except:
                                continue

        # If no automatic detection works, return what we can decode
        try:
            # Try to decode as much as possible as UTF-8
            best_length = len(extracted_bits) - (len(extracted_bits) % 8)
            if best_length > 0:
                final_binary = extracted_bits[:best_length]
                message = binary_to_message(final_binary)
                return message, best_length
        except:
            pass

        # Last resort: return empty string with detected capacity
        return "", 0
