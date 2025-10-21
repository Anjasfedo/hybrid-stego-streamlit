from pydantic import BaseModel, Field
from typing import Optional, Dict


class RobustnessTestResult(BaseModel):
    ber: float = Field(..., description="Bit Error Rate for this attack")
    robust_image_url: str = Field(...,
                                  description="URL of the attacked stego image")


class SteganographyMetrics(BaseModel):
    mse: float = Field(..., description="Mean Squared Error")
    psnr: float = Field(..., description="Peak Signal-to-Noise Ratio (dB)")
    ssim: float = Field(..., description="Structural Similarity Index")


class LSBEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    bit_length: int = Field(..., description="Number of bits embedded")
    lsb_instance_id: str = Field(
        ..., description="LSB instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class LSBExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class PVDEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    bit_length: int = Field(..., description="Number of bits embedded")
    pvd_instance_id: str = Field(
        ..., description="PVD instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class PVDExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class EMDEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    bit_length: int = Field(..., description="Number of bits embedded")
    emd_instance_id: str = Field(
        ..., description="EMD instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class EMDExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class DCTEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    bit_length: int = Field(..., description="Number of bits embedded")
    dct_instance_id: str = Field(
        ..., description="DCT instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class DCTExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class DWTEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    bit_length: int = Field(..., description="Number of bits embedded")
    dwt_instance_id: str = Field(
        ..., description="DWT instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class DWTExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class FFTEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    bit_length: int = Field(..., description="Number of bits embedded")
    fft_instance_id: str = Field(
        ..., description="FFT instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class FFTExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDCTLSBEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    dct_bit_length: int = Field(...,
                                description="Number of bits embedded using DCT")
    lsb_bit_length: int = Field(...,
                                description="Number of bits embedded using LSB")
    hybrid_instance_id: str = Field(
        ..., description="Hybrid instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDCTLSBExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDCTPVDEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    dct_bit_length: int = Field(...,
                                description="Number of bits embedded using DCT")
    pvd_bit_length: int = Field(...,
                                description="Number of bits embedded using PVD")
    hybrid_instance_id: str = Field(
        ..., description="Hybrid instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDCTPVDExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDCTEMDEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    dct_bit_length: int = Field(...,
                                description="Number of bits embedded using DCT")
    emd_bit_length: int = Field(...,
                                description="Number of bits embedded using EMD")
    hybrid_instance_id: str = Field(
        ..., description="Hybrid instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDCTEMDExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDWTLSBEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    dwt_bit_length: int = Field(...,
                                description="Number of bits embedded using DWT")
    lsb_bit_length: int = Field(...,
                                description="Number of bits embedded using LSB")
    hybrid_instance_id: str = Field(
        ..., description="Hybrid instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDWTLSBExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDWTPVDEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    dwt_bit_length: int = Field(...,
                                description="Number of bits embedded using DWT")
    pvd_bit_length: int = Field(...,
                                description="Number of bits embedded using PVD")
    hybrid_instance_id: str = Field(
        ..., description="Hybrid instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDWTPVDExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDWTEMDEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    dwt_bit_length: int = Field(...,
                                description="Number of bits embedded using DWT")
    emd_bit_length: int = Field(...,
                                description="Number of bits embedded using EMD")
    hybrid_instance_id: str = Field(
        ..., description="Hybrid instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridDWTEMDExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridFFTLSBEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    fft_bit_length: int = Field(...,
                                description="Number of bits embedded using FFT")
    lsb_bit_length: int = Field(...,
                                description="Number of bits embedded using LSB")
    hybrid_instance_id: str = Field(
        ..., description="Hybrid instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridFFTLSBExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridFFTPVDEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    fft_bit_length: int = Field(...,
                                description="Number of bits embedded using FFT")
    pvd_bit_length: int = Field(...,
                                description="Number of bits embedded using PVD")
    hybrid_instance_id: str = Field(
        ..., description="Hybrid instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridFFTPVDExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridFFTEMDEmbedResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    stego_image_url: str = Field(..., description="URL of the stego image")
    original_image_url: str = Field(...,
                                    description="URL of the original cover image")
    fft_bit_length: int = Field(...,
                                description="Number of bits embedded using FFT")
    emd_bit_length: int = Field(...,
                                description="Number of bits embedded using EMD")
    hybrid_instance_id: str = Field(
        ..., description="Hybrid instance ID for pairing with extract operation")
    message: Optional[str] = Field(
        None, description="Success or error message")


class HybridFFTEMDExtractResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    extracted_message: str = Field(..., description="Extracted secret message")
    stego_metrics: Optional[SteganographyMetrics] = Field(
        None, description="Steganography quality metrics (if original image provided)")
    robust_metrics: Optional[Dict] = Field(
        None, description="Robustness test results containing detail_attacks and avg_ber")
    message: Optional[str] = Field(
        None, description="Success or error message")


class LSBRobustTestResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    robustness_results: Dict[str, RobustnessTestResult] = Field(
        ..., description="Robustness test results with attack images and BER values")
    average_ber: float = Field(...,
                               description="Average BER across all attacks")
    message: Optional[str] = Field(
        None, description="Success or error message")


class PVDRobustTestResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    robustness_results: Dict[str, RobustnessTestResult] = Field(
        ..., description="Robustness test results with attack images and BER values")
    average_ber: float = Field(...,
                               description="Average BER across all attacks")
    message: Optional[str] = Field(
        None, description="Success or error message")


class EMDRobustTestResponse(BaseModel):
    success: bool = Field(...,
                          description="Whether the operation was successful")
    robustness_results: Dict[str, RobustnessTestResult] = Field(
        ..., description="Robustness test results with attack images and BER values")
    average_ber: float = Field(...,
                               description="Average BER across all attacks")
    message: Optional[str] = Field(
        None, description="Success or error message")
