import cv2
import numpy as np

from scipy.fftpack import dct, idct

from src.helpers.binary_massage import binary_to_message, message_to_binary


class DCTSteganography:

    def __init__(self, block_size=8, quant_factor=15, embed_positions=None):
        self.block_size = block_size
        self.quant_factor = quant_factor

        if embed_positions is None:
            self.embed_positions = [(2, 1), (1, 2), (3, 0), (0, 3), (2, 2)]
        else:
            self.embed_positions = embed_positions

        self.jpeg_quant_table = np.array([
            [16, 11, 10, 16, 24, 40, 51, 61],
            [12, 12, 14, 19, 26, 58, 60, 55],
            [14, 13, 16, 24, 40, 57, 69, 56],
            [14, 17, 22, 29, 51, 87, 80, 62],
            [18, 22, 37, 56, 68, 109, 103, 77],
            [24, 35, 55, 64, 81, 104, 113, 92],
            [49, 64, 78, 87, 103, 121, 120, 101],
            [72, 92, 95, 98, 112, 100, 103, 99]
        ])

    def _dct2d(self, block):
        return dct(dct(block.T, type=2, norm='ortho').T, type=2, norm='ortho')

    def _idct2d(self, block):
        return idct(idct(block.T, type=2, norm='ortho').T, type=2, norm='ortho')

    def _calculate_capacity(self, image_shape):
        height, width = image_shape[:2]
        blocks_y = height // self.block_size
        blocks_x = width // self.block_size
        return (blocks_y * blocks_x) * len(self.embed_positions)

    def embed(self, cover_image, secret_message):
        if len(cover_image.shape) == 2:
            cover_image = cv2.cvtColor(cover_image, cv2.COLOR_GRAY2RGB)

        max_bits = self._calculate_capacity(cover_image.shape)
        binary_message = message_to_binary(secret_message)
        bit_length = len(binary_message)

        if bit_length > max_bits:
            raise ValueError(
                f"Pesan terlalu panjang! Kapasitas: {max_bits} bit, Dibutuhkan: {bit_length} bit.")

        ycrcb = cv2.cvtColor(cover_image, cv2.COLOR_RGB2YCrCb)
        y_channel = ycrcb[:, :, 0].astype(np.float32)
        stego_y = y_channel.copy()
        height, width = y_channel.shape
        binary_index = 0

        for i in range(height // self.block_size):
            for j in range(width // self.block_size):
                if binary_index >= bit_length:
                    break

                row_start, col_start = i * self.block_size, j * self.block_size
                block = stego_y[row_start:row_start+self.block_size,
                                col_start:col_start+self.block_size]

                dct_block = self._dct2d(block - 128.0)

                for u, v in self.embed_positions:
                    if binary_index >= bit_length:
                        break

                    quant_step = self.quant_factor * \
                        self.jpeg_quant_table[u, v] / 50.0
                    quant_coef = np.round(dct_block[u, v] / quant_step)
                    bit = int(binary_message[binary_index])

                    if (quant_coef % 2) != bit:
                        quant_coef += 1 if quant_coef >= 0 else -1

                    dct_block[u, v] = quant_coef * quant_step
                    binary_index += 1

                idct_block = self._idct2d(dct_block) + 128.0
                stego_y[row_start:row_start+self.block_size, col_start:col_start +
                        self.block_size] = np.clip(idct_block, 0, 255)

        ycrcb[:, :, 0] = stego_y.astype(np.uint8)
        return cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2RGB), bit_length

    def extract(self, stego_image, bit_length):
        if len(stego_image.shape) == 2:
            stego_image = cv2.cvtColor(stego_image, cv2.COLOR_GRAY2RGB)

        ycrcb = cv2.cvtColor(stego_image, cv2.COLOR_RGB2YCrCb)
        y_channel = ycrcb[:, :, 0].astype(np.float32)
        height, width = y_channel.shape
        bit_buffer = ""
        bits_extracted = 0

        for i in range(height // self.block_size):
            for j in range(width // self.block_size):
                if bits_extracted >= bit_length:
                    break

                row_start, col_start = i * self.block_size, j * self.block_size
                block = y_channel[row_start:row_start +
                                  self.block_size, col_start:col_start+self.block_size]
                dct_block = self._dct2d(block - 128.0)

                for u, v in self.embed_positions:
                    if bits_extracted >= bit_length:
                        break

                    quant_step = self.quant_factor * \
                        self.jpeg_quant_table[u, v] / 50.0
                    quant_coef = np.round(dct_block[u, v] / quant_step)
                    bit_buffer += str(int(quant_coef) % 2)
                    bits_extracted += 1

        final_binary_string = bit_buffer[:bit_length]

        return binary_to_message(final_binary_string)
