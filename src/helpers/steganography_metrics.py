import numpy as np

from skimage.metrics import structural_similarity as ssim

class SteganographyMetrics:
    def __init__(self, original_image: np.ndarray, stego_image: np.ndarray):
        self.original_image = original_image.astype(np.float64)
        self.stego_image = stego_image.astype(np.float64)

    def calculate_mse(self) -> float:
        return np.mean((self.original_image - self.stego_image) ** 2)

    def calculate_psnr(self) -> float:
        mse = self.calculate_mse()
        if mse == 0:
            return float('inf')

        max_pixel_value = 255.0
        psnr_value = 20 * np.log10(max_pixel_value / np.sqrt(mse))
        return psnr_value

    def calculate_ssim(self) -> float:
        data_range = 255.0

        if self.original_image.ndim == 3:
            return ssim(self.original_image, self.stego_image, multichannel=True, data_range=data_range, channel_axis=2)
        else:
            return ssim(self.original_image, self.stego_image, data_range=data_range)

    def get_all_metrics(self) -> dict:
        mse = self.calculate_mse()
        psnr = self.calculate_psnr()
        ssim_val = self.calculate_ssim()

        return {
            'mse': mse,
            'psnr': psnr,
            'ssim': ssim_val
        }