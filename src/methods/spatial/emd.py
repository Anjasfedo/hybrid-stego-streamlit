import cv2
import numpy as np

from src.helpers.binary_massage import binary_to_message, message_to_binary


class EMDSteganography:

    def __init__(self, n=2):
        self.n = n
        self.base = 2 * self.n + 1

    def _calculate_capacity(self, image):
        if len(image.shape) == 2:
            height, width = image.shape
            channels = 1
        else:
            height, width, channels = image.shape

        groups_per_channel = height * (width // self.n)
        return groups_per_channel * channels

    def _extraction_function(self, pixels):
        return sum((i + 1) * int(pixels[i]) for i in range(self.n)) % self.base

    def _embed_digit(self, pixels, digit):
        current_digit = self._extraction_function(pixels)
        if current_digit == digit:
            return pixels.copy()

        for i in range(self.n):
            for delta in [1, -1]:
                modified_pixels = pixels.copy()
                new_value = modified_pixels[i] + delta
                if 0 <= new_value <= 255:
                    modified_pixels[i] = new_value
                    if self._extraction_function(modified_pixels) == digit:
                        return modified_pixels

        for i in range(self.n):
            for delta in range(-255, 256):
                if delta == 0:
                    continue
                modified_pixels = pixels.copy()
                new_value = modified_pixels[i] + delta
                if 0 <= new_value <= 255:
                    modified_pixels[i] = new_value
                    if self._extraction_function(modified_pixels) == digit:
                        return modified_pixels

        return pixels

    def embed(self, cover_image, secret_message):
        if len(cover_image.shape) == 2:
            cover_image = cv2.cvtColor(cover_image, cv2.COLOR_GRAY2RGB)

        stego_image = cover_image.copy().astype(np.int16)
        binary_message = message_to_binary(secret_message)
        bit_length = len(binary_message)

        num_bits_per_digit = 2
        digits = []
        for i in range(0, len(binary_message), num_bits_per_digit):
            bits = binary_message[i:i + num_bits_per_digit]
            if len(bits) < num_bits_per_digit:
                bits = bits.ljust(num_bits_per_digit, '0')
            digits.append(int(bits, 2))

        max_capacity_digits = self._calculate_capacity(stego_image)
        if len(digits) > max_capacity_digits:
            raise ValueError(
                f"Message too long! Needs {len(digits)} groups, but capacity is {max_capacity_digits}.")

        height, width, channels = stego_image.shape
        digit_index = 0
        for channel in range(channels):
            for row in range(height):
                for col in range(0, width - self.n + 1, self.n):
                    if digit_index >= len(digits):
                        break

                    pixel_group = [stego_image[row, col + i, channel]
                                   for i in range(self.n)]
                    new_pixel_group = self._embed_digit(
                        pixel_group, digits[digit_index])

                    for i in range(self.n):
                        stego_image[row, col + i,
                                    channel] = np.clip(new_pixel_group[i], 0, 255)
                    digit_index += 1
                if digit_index >= len(digits):
                    break
            if digit_index >= len(digits):
                break

        final_stego_image = np.clip(stego_image, 0, 255).astype(np.uint8)

        return final_stego_image, bit_length

    def extract(self, stego_image, bit_length):
        if len(stego_image.shape) == 2:
            stego_image = cv2.cvtColor(stego_image, cv2.COLOR_GRAY2RGB)

        height, width, channels = stego_image.shape
        num_bits_per_digit = 2
        extracted_bits = ""

        digits_needed = (bit_length + num_bits_per_digit -
                         1) // num_bits_per_digit

        digit_count = 0
        for channel in range(channels):
            for row in range(height):
                for col in range(0, width - self.n + 1, self.n):
                    if digit_count >= digits_needed:
                        break

                    pixel_group = [stego_image[row, col + i, channel]
                                   for i in range(self.n)]
                    extracted_digit = self._extraction_function(pixel_group)

                    if extracted_digit < 4:
                        extracted_bits += format(extracted_digit,
                                                 f'0{num_bits_per_digit}b')
                        digit_count += 1
                if digit_count >= digits_needed:
                    break
            if digit_count >= digits_needed:
                break

        final_binary_string = extracted_bits[:bit_length]

        return binary_to_message(final_binary_string)
