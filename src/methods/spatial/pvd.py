import math

import cv2
import numpy as np

from src.helpers.binary_massage import binary_to_message, message_to_binary

class PVDSteganography:
    def __init__(self):
        self.ranges = [
            [0, 7, 3],
            [8, 15, 3],
            [16, 31, 4],
            [32, 63, 5],
            [64, 127, 6],
            [128, 255, 7]
        ]

    def _calculate_capacity(self, image):
        height, width, channels = image.shape
        total_capacity = 0
        for row in range(height):
            for col in range(0, width-1, 2):
                for channel in range(channels):
                    p1, p2 = int(image[row, col, channel]), int(image[row, col+1, channel])
                    diff = p2 - p1
                    _, capacity, _, _ = self.get_range_and_capacity(diff)
                    total_capacity += capacity
        return total_capacity

    def get_range_and_capacity(self, diff):
        abs_diff = abs(diff)
        for i, (lower, upper, capacity) in enumerate(self.ranges):
            if lower <= abs_diff <= upper:
                return i, capacity, lower, upper
        return 0, 0, 0, 0

    def embed(self, cover_image, secret_message):
        if len(cover_image.shape) == 2:
            cover_image = cv2.cvtColor(cover_image, cv2.COLOR_GRAY2RGB)

        binary_message = message_to_binary(secret_message)
        message_length = len(binary_message)

        max_capacity = self._calculate_capacity(cover_image)
        if message_length > max_capacity:
            raise ValueError(f"Message too long for PVD! Needed {message_length} bits, but the image only has a capacity of {max_capacity} bits.")

        height, width, channels = cover_image.shape
        stego_image = cover_image.copy().astype(np.float64)
        binary_index = 0

        for row in range(height):
            for col in range(0, width-1, 2):
                if binary_index >= message_length: break
                for channel in range(channels):
                    if binary_index >= message_length: break

                    p1, p2 = int(stego_image[row, col, channel]), int(stego_image[row, col+1, channel])
                    diff = p2 - p1
                    range_idx, capacity, lower, upper = self.get_range_and_capacity(diff)

                    if capacity == 0: continue

                    bits_to_embed = min(capacity, message_length - binary_index)
                    if bits_to_embed == 0: break

                    message_segment = binary_message[binary_index:binary_index + bits_to_embed]
                    message_segment = message_segment.ljust(capacity, '0')
                    embed_value = int(message_segment, 2)

                    new_diff = lower + embed_value if diff >= 0 else -(lower + embed_value)
                    adjustment = new_diff - diff

                    adj1 = adjustment // 2
                    adj2 = adjustment - adj1

                    p1_new = p1 - adj1
                    p2_new = p2 + adj2

                    if p1_new < 0:
                        p2_new += p1_new; p1_new = 0
                    elif p1_new > 255:
                        p2_new -= (p1_new - 255); p1_new = 255
                    if p2_new < 0:
                        p1_new += p2_new; p2_new = 0
                    elif p2_new > 255:
                        p1_new -= (p2_new - 255); p2_new = 255

                    stego_image[row, col, channel] = p1_new
                    stego_image[row, col+1, channel] = p2_new
                    binary_index += bits_to_embed

        return np.clip(stego_image, 0, 255).astype(np.uint8), message_length

    def extract(self, stego_image, bit_length):
        if len(stego_image.shape) == 2:
            stego_image = cv2.cvtColor(stego_image, cv2.COLOR_GRAY2RGB)

        height, width, channels = stego_image.shape
        bit_buffer = ""
        bits_extracted = 0

        for row in range(height):
            for col in range(0, width-1, 2):
                for channel in range(channels):
                    if bits_extracted >= bit_length:
                        if len(bit_buffer) > 0:
                            if len(bit_buffer) % 8 != 0:
                                bit_buffer = bit_buffer[:-(len(bit_buffer) % 8)]
                            return binary_to_message(bit_buffer)
                        return ""

                    p1, p2 = int(stego_image[row, col, channel]), int(stego_image[row, col+1, channel])
                    diff = p2 - p1
                    _, capacity, lower, _ = self.get_range_and_capacity(diff)

                    if capacity == 0: continue

                    embed_value = abs(diff) - lower
                    embed_value = max(0, min(embed_value, (2**capacity) - 1))

                    bits_to_take = min(capacity, bit_length - bits_extracted)
                    bit_buffer += format(embed_value, f'0{capacity}b')[:bits_to_take]
                    bits_extracted += bits_to_take

        if len(bit_buffer) > 0:
            if len(bit_buffer) % 8 != 0:
                bit_buffer = bit_buffer[:-(len(bit_buffer) % 8)]
            return binary_to_message(bit_buffer)
        return ""