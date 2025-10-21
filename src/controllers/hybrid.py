from fastapi import APIRouter, HTTPException, UploadFile, File, Form

from src.helpers.steganography_metrics import SteganographyMetrics
from src.helpers.image_utils import download_image_from_url, encode_image_to_bytes, validate_image, read_uploaded_file
from src.helpers.hybrid_instance_manager import HybridInstanceManager
from src.helpers.robustness_tester import RobustnessTester, attack_configurations
from src.s3.utils import upload_image_and_get_url
from src.models.steganography import (
    HybridDCTLSBEmbedResponse, HybridDCTLSBExtractResponse,
    HybridDCTPVDEmbedResponse, HybridDCTPVDExtractResponse,
    HybridDCTEMDEmbedResponse, HybridDCTEMDExtractResponse,
    HybridDWTLSBEmbedResponse, HybridDWTLSBExtractResponse,
    HybridDWTPVDEmbedResponse, HybridDWTPVDExtractResponse,
    HybridDWTEMDEmbedResponse, HybridDWTEMDExtractResponse,
    HybridFFTLSBEmbedResponse, HybridFFTLSBExtractResponse,
    HybridFFTPVDEmbedResponse, HybridFFTPVDExtractResponse,
    HybridFFTEMDEmbedResponse, HybridFFTEMDExtractResponse,
    RobustnessTestResult, SteganographyMetrics as MetricsModel
)

router = APIRouter(prefix="/hybrid", tags=["hybrid"])


@router.post("/embed/dct-lsb", response_model=HybridDCTLSBEmbedResponse, summary="Embed message using DCT-LSB hybrid steganography with file upload")
async def embed_dct_lsb(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    dct_ratio: float = Form(0.5, ge=0.0, le=1.0, description="DCT ratio (0.0-1.0, default 0.5)"),
    lsb_ratio: float = Form(0.5, ge=0.0, le=1.0, description="LSB ratio (0.0-1.0, default 0.5)"),
    # DCT parameters
    block_size: int = Form(8, ge=4, le=16, description="Block size for DCT (4-16, default 8)"),
    quant_factor: int = Form(70, ge=5, le=100, description="Quantization factor (5-100, default 70)"),
    embed_positions: str = Form("mid", description="Embed positions: 'mid_low', 'mid', 'high', or 'default' (default: mid)"),
    # LSB parameters
    bits_per_channel: int = Form(1, ge=1, le=4, description="Number of bits per channel for LSB (1-4, default 1)")
) -> HybridDCTLSBEmbedResponse:
    """
    Embed a secret message into an uploaded image using DCT-LSB hybrid steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **dct_ratio**: Ratio of message bits to embed using DCT (0.0-1.0, default 0.5)
    - **lsb_ratio**: Ratio of message bits to embed using LSB (0.0-1.0, default 0.5)
    - **block_size**: Block size for DCT (4-16, default 8)
    - **quant_factor**: Quantization factor (5-100, default 70, higher for robustness but lower quality)
    - **embed_positions**: Embed positions preset ('mid_low', 'mid', 'high', or 'default', default 'mid')
    - **bits_per_channel**: Number of bits per channel for LSB (1-4, default 1)

    Returns the stego image URL and embedding details with hybrid instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return HybridDCTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dct_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Validate ratio sum
        if abs(dct_ratio + lsb_ratio - 1.0) > 0.001:
            return HybridDCTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dct_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="DCT ratio and LSB ratio must sum to 1.0"
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return HybridDCTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dct_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Parse embed positions for DCT
        from src.helpers.dct_instance_manager import POSITION_MID_LOW, POSITION_MID, POSITION_HIGH

        embed_positions_map = {
            "mid_low": POSITION_MID_LOW,
            "mid": POSITION_MID,
            "high": POSITION_HIGH,
            "default": POSITION_MID
        }

        selected_positions = embed_positions_map.get(embed_positions.lower(), POSITION_MID)

        # Prepare DCT and LSB parameters
        dct_params = {
            "block_size": block_size,
            "quant_factor": quant_factor,
            "embed_positions": selected_positions
        }

        lsb_params = {
            "bits_per_channel": bits_per_channel
        }

        # Create and store hybrid instance for pairing
        hybrid_instance_id = HybridInstanceManager.create_instance(
            dct_lsb_ratio=(dct_ratio, lsb_ratio),
            dct_params=dct_params,
            lsb_params=lsb_params
        )
        hybrid = HybridInstanceManager.get_instance(hybrid_instance_id)

        if not hybrid:
            return HybridDCTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dct_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="Failed to create hybrid instance"
            )

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{hybrid_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("hybrid/dct-lsb/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, (dct_bit_length, lsb_bit_length) = hybrid.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{hybrid_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("hybrid/dct-lsb/embed", filename, stego_image_bytes)

        return HybridDCTLSBEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            dct_bit_length=dct_bit_length,
            lsb_bit_length=lsb_bit_length,
            hybrid_instance_id=hybrid_instance_id,
            message=f"Successfully embedded {dct_bit_length + lsb_bit_length} bits using DCT-LSB hybrid steganography"
        )

    except ValueError as e:
        return HybridDCTLSBEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            dct_bit_length=0,
            lsb_bit_length=0,
            hybrid_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/dct-pvd", response_model=HybridDCTPVDEmbedResponse, summary="Embed message using DCT-PVD hybrid steganography with file upload")
async def embed_dct_pvd(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    dct_ratio: float = Form(0.5, ge=0.0, le=1.0, description="DCT ratio (0.0-1.0, default 0.5)"),
    pvd_ratio: float = Form(0.5, ge=0.0, le=1.0, description="PVD ratio (0.0-1.0, default 0.5)"),
    # DCT parameters
    block_size: int = Form(8, ge=4, le=16, description="Block size for DCT (4-16, default 8)"),
    quant_factor: int = Form(70, ge=5, le=100, description="Quantization factor (5-100, default 70)"),
    embed_positions: str = Form("mid", description="Embed positions: 'mid_low', 'mid', 'high', or 'default' (default: mid)")
) -> HybridDCTPVDEmbedResponse:
    """
    Embed a secret message into an uploaded image using DCT-PVD hybrid steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **dct_ratio**: Ratio of message bits to embed using DCT (0.0-1.0, default 0.5)
    - **pvd_ratio**: Ratio of message bits to embed using PVD (0.0-1.0, default 0.5)
    - **block_size**: Block size for DCT (4-16, default 8)
    - **quant_factor**: Quantization factor (5-100, default 70, higher for robustness but lower quality)
    - **embed_positions**: Embed positions preset ('mid_low', 'mid', 'high', or 'default', default 'mid')

    Returns the stego image URL and embedding details with hybrid instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return HybridDCTPVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dct_bit_length=0,
                pvd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Validate ratio sum
        if abs(dct_ratio + pvd_ratio - 1.0) > 0.001:
            return HybridDCTPVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dct_bit_length=0,
                pvd_bit_length=0,
                hybrid_instance_id="",
                message="DCT ratio and PVD ratio must sum to 1.0"
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return HybridDCTPVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dct_bit_length=0,
                pvd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Parse embed positions for DCT
        from src.helpers.dct_instance_manager import POSITION_MID_LOW, POSITION_MID, POSITION_HIGH

        embed_positions_map = {
            "mid_low": POSITION_MID_LOW,
            "mid": POSITION_MID,
            "high": POSITION_HIGH,
            "default": POSITION_MID
        }

        selected_positions = embed_positions_map.get(embed_positions.lower(), POSITION_MID)

        # Prepare DCT parameters (PVD doesn't need additional parameters)
        dct_params = {
            "block_size": block_size,
            "quant_factor": quant_factor,
            "embed_positions": selected_positions
        }

        pvd_params = {}  # PVD uses default parameters

        # Import DCT-PVD hybrid class
        from src.methods.hybrid.dct_pvd import DCTPVDHybrid

        # Create hybrid instance
        hybrid_instance_id = str(__import__('uuid').uuid4())
        hybrid = DCTPVDHybrid(
            dct_pvd_ratio=(dct_ratio, pvd_ratio),
            dct_params=dct_params,
            pvd_params=pvd_params
        )

        # Store hybrid instance using the existing manager (adapting for DCT-PVD)
        # For now, we'll use the existing HybridInstanceManager but create DCT-PVD instance
        HybridInstanceManager._instances[hybrid_instance_id] = hybrid
        HybridInstanceManager._instance_timestamps[hybrid_instance_id] = __import__('time').time()

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{hybrid_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("hybrid/dct-pvd/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, (dct_bit_length, pvd_bit_length) = hybrid.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{hybrid_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("hybrid/dct-pvd/embed", filename, stego_image_bytes)

        return HybridDCTPVDEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            dct_bit_length=dct_bit_length,
            pvd_bit_length=pvd_bit_length,
            hybrid_instance_id=hybrid_instance_id,
            message=f"Successfully embedded {dct_bit_length + pvd_bit_length} bits using DCT-PVD hybrid steganography"
        )

    except ValueError as e:
        return HybridDCTPVDEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            dct_bit_length=0,
            pvd_bit_length=0,
            hybrid_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/dct-emd", response_model=HybridDCTEMDEmbedResponse, summary="Embed message using DCT-EMD hybrid steganography with file upload")
async def embed_dct_emd(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    dct_ratio: float = Form(0.5, ge=0.0, le=1.0, description="DCT ratio (0.0-1.0, default 0.5)"),
    emd_ratio: float = Form(0.5, ge=0.0, le=1.0, description="EMD ratio (0.0-1.0, default 0.5)"),
    # DCT parameters
    block_size: int = Form(8, ge=4, le=16, description="Block size for DCT (4-16, default 8)"),
    quant_factor: int = Form(70, ge=5, le=100, description="Quantization factor (5-100, default 70)"),
    embed_positions: str = Form("mid", description="Embed positions: 'mid_low', 'mid', 'high', or 'default' (default: mid)"),
    # EMD parameters
    n: int = Form(2, ge=1, le=10, description="EMD parameter n (number of pixels per group)")
) -> HybridDCTEMDEmbedResponse:
    """
    Embed a secret message into an uploaded image using DCT-EMD hybrid steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **dct_ratio**: Ratio of message bits to embed using DCT (0.0-1.0, default 0.5)
    - **emd_ratio**: Ratio of message bits to embed using EMD (0.0-1.0, default 0.5)
    - **block_size**: Block size for DCT (4-16, default 8)
    - **quant_factor**: Quantization factor (5-100, default 70, higher for robustness but lower quality)
    - **embed_positions**: Embed positions preset ('mid_low', 'mid', 'high', or 'default', default 'mid')
    - **n**: EMD parameter n (1-10, default 2)

    Returns the stego image URL and embedding details with hybrid instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return HybridDCTEMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dct_bit_length=0,
                emd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Validate ratio sum
        if abs(dct_ratio + emd_ratio - 1.0) > 0.001:
            return HybridDCTEMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dct_bit_length=0,
                emd_bit_length=0,
                hybrid_instance_id="",
                message="DCT ratio and EMD ratio must sum to 1.0"
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return HybridDCTEMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dct_bit_length=0,
                emd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Parse embed positions for DCT
        from src.helpers.dct_instance_manager import POSITION_MID_LOW, POSITION_MID, POSITION_HIGH

        embed_positions_map = {
            "mid_low": POSITION_MID_LOW,
            "mid": POSITION_MID,
            "high": POSITION_HIGH,
            "default": POSITION_MID
        }

        selected_positions = embed_positions_map.get(embed_positions.lower(), POSITION_MID)

        # Prepare DCT and EMD parameters
        dct_params = {
            "block_size": block_size,
            "quant_factor": quant_factor,
            "embed_positions": selected_positions
        }

        emd_params = {
            "n": n
        }

        # Import DCT-EMD hybrid class
        from src.methods.hybrid.dct_emd import DCTEMDHybrid

        # Create hybrid instance
        hybrid_instance_id = str(__import__('uuid').uuid4())
        hybrid = DCTEMDHybrid(
            dct_emd_ratio=(dct_ratio, emd_ratio),
            dct_params=dct_params,
            emd_params=emd_params
        )

        # Store hybrid instance using the existing manager (adapting for DCT-EMD)
        HybridInstanceManager._instances[hybrid_instance_id] = hybrid
        HybridInstanceManager._instance_timestamps[hybrid_instance_id] = __import__('time').time()

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{hybrid_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("hybrid/dct-emd/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, (dct_bit_length, emd_bit_length) = hybrid.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{hybrid_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("hybrid/dct-emd/embed", filename, stego_image_bytes)

        return HybridDCTEMDEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            dct_bit_length=dct_bit_length,
            emd_bit_length=emd_bit_length,
            hybrid_instance_id=hybrid_instance_id,
            message=f"Successfully embedded {dct_bit_length + emd_bit_length} bits using DCT-EMD hybrid steganography"
        )

    except ValueError as e:
        return HybridDCTEMDEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            dct_bit_length=0,
            emd_bit_length=0,
            hybrid_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/dwt-lsb", response_model=HybridDWTLSBEmbedResponse, summary="Embed message using DWT-LSB hybrid steganography with file upload")
async def embed_dwt_lsb(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    dwt_ratio: float = Form(0.5, ge=0.0, le=1.0, description="DWT ratio (0.0-1.0, default 0.5)"),
    lsb_ratio: float = Form(0.5, ge=0.0, le=1.0, description="LSB ratio (0.0-1.0, default 0.5)"),
    # DWT parameters
    wavelet: str = Form("haar", description="Wavelet type (default: haar)"),
    level: int = Form(3, ge=1, le=3, description="Decomposition level (1-3, default 3)"),
    band: str = Form("HH", description="Frequency band (LL, LH, HL, HH, default HH)"),
    delta: float = Form(25.0, description="Delta value (default 25.0)"),
    embed_level: int = Form(3, ge=1, le=3, description="Embedding level (1-3, must be <= decomposition level, default 3)"),
    robust_mode: bool = Form(True, description="Enable robust mode (default True)"),
    # LSB parameters
    bits_per_channel: int = Form(1, ge=1, le=4, description="Number of bits per channel for LSB (1-4, default 1)")
) -> HybridDWTLSBEmbedResponse:
    """
    Embed a secret message into an uploaded image using DWT-LSB hybrid steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **dwt_ratio**: Ratio of message bits to embed using DWT (0.0-1.0, default 0.5)
    - **lsb_ratio**: Ratio of message bits to embed using LSB (0.0-1.0, default 0.5)
    - **wavelet**: Wavelet type (default: haar)
    - **level**: Decomposition level (1-3, default 3)
    - **band**: Frequency band (LL, LH, HL, HH, default HH)
    - **delta**: Delta value (default 25.0)
    - **embed_level**: Embedding level (1-3, must be <= decomposition level, default 3)
    - **robust_mode**: Enable robust mode (default True)
    - **bits_per_channel**: Number of bits per channel for LSB (1-4, default 1)

    Returns the stego image URL and embedding details with hybrid instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return HybridDWTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Validate ratio sum
        if abs(dwt_ratio + lsb_ratio - 1.0) > 0.001:
            return HybridDWTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="DWT ratio and LSB ratio must sum to 1.0"
            )

        # Validate embed_level vs level
        if embed_level > level:
            return HybridDWTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="Embedding level must be less than or equal to decomposition level"
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return HybridDWTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Prepare DWT and LSB parameters
        dwt_params = {
            "wavelet": wavelet,
            "level": level,
            "band": band,
            "delta": delta,
            "embed_level": embed_level,
            "robust_mode": robust_mode
        }

        lsb_params = {
            "bits_per_channel": bits_per_channel
        }

        # Import DWT-LSB hybrid class
        from src.methods.hybrid.dwt_lsb import DWTLSBHybrid

        # Create hybrid instance
        hybrid_instance_id = str(__import__('uuid').uuid4())
        hybrid = DWTLSBHybrid(
            dwt_lsb_ratio=(dwt_ratio, lsb_ratio),
            dwt_params=dwt_params,
            lsb_params=lsb_params
        )

        # Store hybrid instance using the existing manager (adapting for DWT-LSB)
        HybridInstanceManager._instances[hybrid_instance_id] = hybrid
        HybridInstanceManager._instance_timestamps[hybrid_instance_id] = __import__('time').time()

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{hybrid_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("hybrid/dwt-lsb/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, (dwt_bit_length, lsb_bit_length) = hybrid.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{hybrid_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("hybrid/dwt-lsb/embed", filename, stego_image_bytes)

        return HybridDWTLSBEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            dwt_bit_length=dwt_bit_length,
            lsb_bit_length=lsb_bit_length,
            hybrid_instance_id=hybrid_instance_id,
            message=f"Successfully embedded {dwt_bit_length + lsb_bit_length} bits using DWT-LSB hybrid steganography"
        )

    except ValueError as e:
        return HybridDWTLSBEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            dwt_bit_length=0,
            lsb_bit_length=0,
            hybrid_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/dwt-pvd", response_model=HybridDWTPVDEmbedResponse, summary="Embed message using DWT-PVD hybrid steganography with file upload")
async def embed_dwt_pvd(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    dwt_ratio: float = Form(0.5, ge=0.0, le=1.0, description="DWT ratio (0.0-1.0, default 0.5)"),
    pvd_ratio: float = Form(0.5, ge=0.0, le=1.0, description="PVD ratio (0.0-1.0, default 0.5)"),
    # DWT parameters
    wavelet: str = Form("haar", description="Wavelet type (default: haar)"),
    level: int = Form(3, ge=1, le=3, description="Decomposition level (1-3, default 3)"),
    band: str = Form("HH", description="Frequency band (LL, LH, HL, HH, default HH)"),
    delta: float = Form(25.0, description="Delta value (default 25.0)"),
    embed_level: int = Form(3, ge=1, le=3, description="Embedding level (1-3, must be <= decomposition level, default 3)"),
    robust_mode: bool = Form(True, description="Enable robust mode (default True)")
) -> HybridDWTPVDEmbedResponse:
    """
    Embed a secret message into an uploaded image using DWT-PVD hybrid steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **dwt_ratio**: Ratio of message bits to embed using DWT (0.0-1.0, default 0.5)
    - **pvd_ratio**: Ratio of message bits to embed using PVD (0.0-1.0, default 0.5)
    - **wavelet**: Wavelet type (default: haar)
    - **level**: Decomposition level (1-3, default 3)
    - **band**: Frequency band (LL, LH, HL, HH, default HH)
    - **delta**: Delta value (default 25.0)
    - **embed_level**: Embedding level (1-3, must be <= decomposition level, default 3)
    - **robust_mode**: Enable robust mode (default True)

    Returns the stego image URL and embedding details with hybrid instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return HybridDWTPVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                pvd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Validate ratio sum
        if abs(dwt_ratio + pvd_ratio - 1.0) > 0.001:
            return HybridDWTPVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                pvd_bit_length=0,
                hybrid_instance_id="",
                message="DWT ratio and PVD ratio must sum to 1.0"
            )

        # Validate embed_level vs level
        if embed_level > level:
            return HybridDWTPVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                pvd_bit_length=0,
                hybrid_instance_id="",
                message="Embedding level must be less than or equal to decomposition level"
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return HybridDWTPVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                pvd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Prepare DWT parameters (PVD doesn't need additional parameters)
        dwt_params = {
            "wavelet": wavelet,
            "level": level,
            "band": band,
            "delta": delta,
            "embed_level": embed_level,
            "robust_mode": robust_mode
        }

        pvd_params = {}  # PVD uses default parameters

        # Import DWT-PVD hybrid class
        from src.methods.hybrid.dwt_pvd import DWTPVDHybrid

        # Create hybrid instance
        hybrid_instance_id = str(__import__('uuid').uuid4())
        hybrid = DWTPVDHybrid(
            dwt_pvd_ratio=(dwt_ratio, pvd_ratio),
            dwt_params=dwt_params,
            pvd_params=pvd_params
        )

        # Store hybrid instance using the existing manager (adapting for DWT-PVD)
        HybridInstanceManager._instances[hybrid_instance_id] = hybrid
        HybridInstanceManager._instance_timestamps[hybrid_instance_id] = __import__('time').time()

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{hybrid_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("hybrid/dwt-pvd/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, (dwt_bit_length, pvd_bit_length) = hybrid.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{hybrid_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("hybrid/dwt-pvd/embed", filename, stego_image_bytes)

        return HybridDWTPVDEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            dwt_bit_length=dwt_bit_length,
            pvd_bit_length=pvd_bit_length,
            hybrid_instance_id=hybrid_instance_id,
            message=f"Successfully embedded {dwt_bit_length + pvd_bit_length} bits using DWT-PVD hybrid steganography"
        )

    except ValueError as e:
        return HybridDWTPVDEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            dwt_bit_length=0,
            pvd_bit_length=0,
            hybrid_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/dwt-emd", response_model=HybridDWTEMDEmbedResponse, summary="Embed message using DWT-EMD hybrid steganography with file upload")
async def embed_dwt_emd(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    dwt_ratio: float = Form(0.5, ge=0.0, le=1.0, description="DWT ratio (0.0-1.0, default 0.5)"),
    emd_ratio: float = Form(0.5, ge=0.0, le=1.0, description="EMD ratio (0.0-1.0, default 0.5)"),
    # DWT parameters
    wavelet: str = Form("haar", description="Wavelet type (default: haar)"),
    level: int = Form(3, ge=1, le=3, description="Decomposition level (1-3, default 3)"),
    band: str = Form("HH", description="Frequency band (LL, LH, HL, HH, default HH)"),
    delta: float = Form(25.0, description="Delta value (default 25.0)"),
    embed_level: int = Form(3, ge=1, le=3, description="Embedding level (1-3, must be <= decomposition level, default 3)"),
    robust_mode: bool = Form(True, description="Enable robust mode (default True)"),
    # EMD parameters
    n: int = Form(2, ge=1, le=10, description="EMD parameter n (number of pixels per group)")
) -> HybridDWTEMDEmbedResponse:
    """
    Embed a secret message into an uploaded image using DWT-EMD hybrid steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **dwt_ratio**: Ratio of message bits to embed using DWT (0.0-1.0, default 0.5)
    - **emd_ratio**: Ratio of message bits to embed using EMD (0.0-1.0, default 0.5)
    - **wavelet**: Wavelet type (default: haar)
    - **level**: Decomposition level (1-3, default 3)
    - **band**: Frequency band (LL, LH, HL, HH, default HH)
    - **delta**: Delta value (default 25.0)
    - **embed_level**: Embedding level (1-3, must be <= decomposition level, default 3)
    - **robust_mode**: Enable robust mode (default True)
    - **n**: EMD parameter n (1-10, default 2)

    Returns the stego image URL and embedding details with hybrid instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return HybridDWTEMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                emd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Validate ratio sum
        if abs(dwt_ratio + emd_ratio - 1.0) > 0.001:
            return HybridDWTEMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                emd_bit_length=0,
                hybrid_instance_id="",
                message="DWT ratio and EMD ratio must sum to 1.0"
            )

        # Validate embed_level vs level
        if embed_level > level:
            return HybridDWTEMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                emd_bit_length=0,
                hybrid_instance_id="",
                message="Embedding level must be less than or equal to decomposition level"
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return HybridDWTEMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                dwt_bit_length=0,
                emd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Prepare DWT and EMD parameters
        dwt_params = {
            "wavelet": wavelet,
            "level": level,
            "band": band,
            "delta": delta,
            "embed_level": embed_level,
            "robust_mode": robust_mode
        }

        emd_params = {
            "n": n
        }

        # Import DWT-EMD hybrid class
        from src.methods.hybrid.dwt_emd import DWTEmdHybrid

        # Create hybrid instance
        hybrid_instance_id = str(__import__('uuid').uuid4())
        hybrid = DWTEmdHybrid(
            dwt_emd_ratio=(dwt_ratio, emd_ratio),
            dwt_params=dwt_params,
            emd_params=emd_params
        )

        # Store hybrid instance using the existing manager (adapting for DWT-EMD)
        HybridInstanceManager._instances[hybrid_instance_id] = hybrid
        HybridInstanceManager._instance_timestamps[hybrid_instance_id] = __import__('time').time()

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{hybrid_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("hybrid/dwt-emd/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, (dwt_bit_length, emd_bit_length) = hybrid.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{hybrid_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("hybrid/dwt-emd/embed", filename, stego_image_bytes)

        return HybridDWTEMDEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            dwt_bit_length=dwt_bit_length,
            emd_bit_length=emd_bit_length,
            hybrid_instance_id=hybrid_instance_id,
            message=f"Successfully embedded {dwt_bit_length + emd_bit_length} bits using DWT-EMD hybrid steganography"
        )

    except ValueError as e:
        return HybridDWTEMDEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            dwt_bit_length=0,
            emd_bit_length=0,
            hybrid_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/fft-lsb", response_model=HybridFFTLSBEmbedResponse, summary="Embed message using FFT-LSB hybrid steganography with file upload")
async def embed_fft_lsb(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    fft_ratio: float = Form(0.5, ge=0.0, le=1.0, description="FFT ratio (0.0-1.0, default 0.5)"),
    lsb_ratio: float = Form(0.5, ge=0.0, le=1.0, description="LSB ratio (0.0-1.0, default 0.5)"),
    # FFT parameters
    r_in: float = Form(0.1, ge=0.05, le=0.3, description="Inner radius ratio (0.05-0.3, default 0.1)"),
    r_out: float = Form(0.4, ge=0.3, le=0.6, description="Outer radius ratio (0.3-0.6, default 0.4)"),
    phase_levels: int = Form(4, description="Phase levels (locked to 4)"),
    header_repeat: int = Form(3, ge=1, le=10, description="Header repeat count (1-10, default 3)"),
    payload_repeat: int = Form(3, ge=1, le=5, description="Payload repeat count (1-5, default 3)"),
    color_order: str = Form("RGB", description="Color order (RGB or BGR, default RGB)"),
    header_channel: str = Form("Cr", description="Header channel (Y, Cr, Cb, default Cr)"),
    payload_channel: str = Form("Cb", description="Payload channel (Y, Cr, Cb, default Cb)"),
    mag_min_boost: float = Form(3.0, ge=1.0, le=10.0, description="Minimum magnitude boost (1.0-10.0, default 3.0)"),
    # LSB parameters
    bits_per_channel: int = Form(1, ge=1, le=4, description="Number of bits per channel for LSB (1-4, default 1)")
) -> HybridFFTLSBEmbedResponse:
    """
    Embed a secret message into an uploaded image using FFT-LSB hybrid steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **fft_ratio**: Ratio of message bits to embed using FFT (0.0-1.0, default 0.5)
    - **lsb_ratio**: Ratio of message bits to embed using LSB (0.0-1.0, default 0.5)
    - **r_in**: Inner radius ratio (0.05-0.3, default 0.1)
    - **r_out**: Outer radius ratio (0.3-0.6, default 0.4)
    - **phase_levels**: Phase levels (locked to 4)
    - **header_repeat**: Header repeat count (1-10, default 3)
    - **payload_repeat**: Payload repeat count (1-5, default 3)
    - **color_order**: Color order (RGB or BGR, default RGB)
    - **header_channel**: Header channel (Y, Cr, Cb, default Cr)
    - **payload_channel**: Payload channel (Y, Cr, Cb, default Cb)
    - **mag_min_boost**: Minimum magnitude boost (1.0-10.0, default 3.0)
    - **bits_per_channel**: Number of bits per channel for LSB (1-4, default 1)

    Returns the stego image URL and embedding details with hybrid instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return HybridFFTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                fft_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Validate ratio sum
        if abs(fft_ratio + lsb_ratio - 1.0) > 0.001:
            return HybridFFTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                fft_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="FFT ratio and LSB ratio must sum to 1.0"
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return HybridFFTLSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                fft_bit_length=0,
                lsb_bit_length=0,
                hybrid_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Prepare FFT and LSB parameters
        fft_params = {
            "r_in": r_in,
            "r_out": r_out,
            "phase_levels": phase_levels,
            "header_repeat": header_repeat,
            "payload_repeat": payload_repeat,
            "color_order": color_order,
            "header_channel": header_channel,
            "payload_channel": payload_channel,
            "mag_min_boost": mag_min_boost
        }

        lsb_params = {
            "bits_per_channel": bits_per_channel
        }

        # Import FFT-LSB hybrid class
        from src.methods.hybrid.fft_lsb import FFTLSBHybrid

        # Create hybrid instance
        hybrid_instance_id = str(__import__('uuid').uuid4())
        hybrid = FFTLSBHybrid(
            fft_lsb_ratio=(fft_ratio, lsb_ratio),
            fft_params=fft_params,
            lsb_params=lsb_params
        )

        # Store hybrid instance using the existing manager (adapting for FFT-LSB)
        HybridInstanceManager._instances[hybrid_instance_id] = hybrid
        HybridInstanceManager._instance_timestamps[hybrid_instance_id] = __import__('time').time()

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{hybrid_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("hybrid/fft-lsb/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, (fft_bit_length, lsb_bit_length) = hybrid.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{hybrid_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("hybrid/fft-lsb/embed", filename, stego_image_bytes)

        return HybridFFTLSBEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            fft_bit_length=fft_bit_length,
            lsb_bit_length=lsb_bit_length,
            hybrid_instance_id=hybrid_instance_id,
            message=f"Successfully embedded {fft_bit_length + lsb_bit_length} bits using FFT-LSB hybrid steganography"
        )

    except ValueError as e:
        return HybridFFTLSBEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            fft_bit_length=0,
            lsb_bit_length=0,
            hybrid_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/fft-pvd", response_model=HybridFFTPVDEmbedResponse, summary="Embed message using FFT-PVD hybrid steganography with file upload")
async def embed_fft_pvd(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    fft_ratio: float = Form(0.5, ge=0.0, le=1.0, description="FFT ratio (0.0-1.0, default 0.5)"),
    pvd_ratio: float = Form(0.5, ge=0.0, le=1.0, description="PVD ratio (0.0-1.0, default 0.5)"),
    # FFT parameters
    r_in: float = Form(0.1, ge=0.05, le=0.3, description="Inner radius ratio (0.05-0.3, default 0.1)"),
    r_out: float = Form(0.4, ge=0.3, le=0.6, description="Outer radius ratio (0.3-0.6, default 0.4)"),
    phase_levels: int = Form(4, description="Phase levels (locked to 4)"),
    header_repeat: int = Form(3, ge=1, le=10, description="Header repeat count (1-10, default 3)"),
    payload_repeat: int = Form(3, ge=1, le=5, description="Payload repeat count (1-5, default 3)"),
    color_order: str = Form("RGB", description="Color order (RGB or BGR, default RGB)"),
    header_channel: str = Form("Cr", description="Header channel (Y, Cr, Cb, default Cr)"),
    payload_channel: str = Form("Cb", description="Payload channel (Y, Cr, Cb, default Cb)"),
    mag_min_boost: float = Form(3.0, ge=1.0, le=10.0, description="Minimum magnitude boost (1.0-10.0, default 3.0)")
) -> HybridFFTPVDEmbedResponse:
    """
    Embed a secret message into an uploaded image using FFT-PVD hybrid steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **fft_ratio**: Ratio of message bits to embed using FFT (0.0-1.0, default 0.5)
    - **pvd_ratio**: Ratio of message bits to embed using PVD (0.0-1.0, default 0.5)
    - **r_in**: Inner radius ratio (0.05-0.3, default 0.1)
    - **r_out**: Outer radius ratio (0.3-0.6, default 0.4)
    - **phase_levels**: Phase levels (locked to 4)
    - **header_repeat**: Header repeat count (1-10, default 3)
    - **payload_repeat**: Payload repeat count (1-5, default 3)
    - **color_order**: Color order (RGB or BGR, default RGB)
    - **header_channel**: Header channel (Y, Cr, Cb, default Cr)
    - **payload_channel**: Payload channel (Y, Cr, Cb, default Cb)
    - **mag_min_boost**: Minimum magnitude boost (1.0-10.0, default 3.0)

    Returns the stego image URL and embedding details with hybrid instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return HybridFFTPVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                fft_bit_length=0,
                pvd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Validate ratio sum
        if abs(fft_ratio + pvd_ratio - 1.0) > 0.001:
            return HybridFFTPVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                fft_bit_length=0,
                pvd_bit_length=0,
                hybrid_instance_id="",
                message="FFT ratio and PVD ratio must sum to 1.0"
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return HybridFFTPVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                fft_bit_length=0,
                pvd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Prepare FFT parameters (PVD doesn't need additional parameters)
        fft_params = {
            "r_in": r_in,
            "r_out": r_out,
            "phase_levels": phase_levels,
            "header_repeat": header_repeat,
            "payload_repeat": payload_repeat,
            "color_order": color_order,
            "header_channel": header_channel,
            "payload_channel": payload_channel,
            "mag_min_boost": mag_min_boost
        }

        pvd_params = {}  # PVD uses default parameters

        # Import FFT-PVD hybrid class
        from src.methods.hybrid.fft_pvd import FFTPVDHybrid

        # Create hybrid instance
        hybrid_instance_id = str(__import__('uuid').uuid4())
        hybrid = FFTPVDHybrid(
            fft_pvd_ratio=(fft_ratio, pvd_ratio),
            fft_params=fft_params,
            pvd_params=pvd_params
        )

        # Store hybrid instance using the existing manager (adapting for FFT-PVD)
        HybridInstanceManager._instances[hybrid_instance_id] = hybrid
        HybridInstanceManager._instance_timestamps[hybrid_instance_id] = __import__('time').time()

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{hybrid_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("hybrid/fft-pvd/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, (fft_bit_length, pvd_bit_length) = hybrid.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{hybrid_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("hybrid/fft-pvd/embed", filename, stego_image_bytes)

        return HybridFFTPVDEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            fft_bit_length=fft_bit_length,
            pvd_bit_length=pvd_bit_length,
            hybrid_instance_id=hybrid_instance_id,
            message=f"Successfully embedded {fft_bit_length + pvd_bit_length} bits using FFT-PVD hybrid steganography"
        )

    except ValueError as e:
        return HybridFFTPVDEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            fft_bit_length=0,
            pvd_bit_length=0,
            hybrid_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/fft-emd", response_model=HybridFFTEMDEmbedResponse, summary="Embed message using FFT-EMD hybrid steganography with file upload")
async def embed_fft_emd(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    fft_ratio: float = Form(0.5, ge=0.0, le=1.0, description="FFT ratio (0.0-1.0, default 0.5)"),
    emd_ratio: float = Form(0.5, ge=0.0, le=1.0, description="EMD ratio (0.0-1.0, default 0.5)"),
    # FFT parameters
    r_in: float = Form(0.1, ge=0.05, le=0.3, description="Inner radius ratio (0.05-0.3, default 0.1)"),
    r_out: float = Form(0.4, ge=0.3, le=0.6, description="Outer radius ratio (0.3-0.6, default 0.4)"),
    phase_levels: int = Form(4, description="Phase levels (locked to 4)"),
    header_repeat: int = Form(3, ge=1, le=10, description="Header repeat count (1-10, default 3)"),
    payload_repeat: int = Form(3, ge=1, le=5, description="Payload repeat count (1-5, default 3)"),
    color_order: str = Form("RGB", description="Color order (RGB or BGR, default RGB)"),
    header_channel: str = Form("Cr", description="Header channel (Y, Cr, Cb, default Cr)"),
    payload_channel: str = Form("Cb", description="Payload channel (Y, Cr, Cb, default Cb)"),
    mag_min_boost: float = Form(3.0, ge=1.0, le=10.0, description="Minimum magnitude boost (1.0-10.0, default 3.0)"),
    # EMD parameters
    n: int = Form(2, ge=1, le=10, description="EMD parameter n (number of pixels per group)")
) -> HybridFFTEMDEmbedResponse:
    """
    Embed a secret message into an uploaded image using FFT-EMD hybrid steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **fft_ratio**: Ratio of message bits to embed using FFT (0.0-1.0, default 0.5)
    - **emd_ratio**: Ratio of message bits to embed using EMD (0.0-1.0, default 0.5)
    - **r_in**: Inner radius ratio (0.05-0.3, default 0.1)
    - **r_out**: Outer radius ratio (0.3-0.6, default 0.4)
    - **phase_levels**: Phase levels (locked to 4)
    - **header_repeat**: Header repeat count (1-10, default 3)
    - **payload_repeat**: Payload repeat count (1-5, default 3)
    - **color_order**: Color order (RGB or BGR, default RGB)
    - **header_channel**: Header channel (Y, Cr, Cb, default Cr)
    - **payload_channel**: Payload channel (Y, Cr, Cb, default Cb)
    - **mag_min_boost**: Minimum magnitude boost (1.0-10.0, default 3.0)
    - **n**: EMD parameter n (1-10, default 2)

    Returns the stego image URL and embedding details with hybrid instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return HybridFFTEMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                fft_bit_length=0,
                emd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Validate ratio sum
        if abs(fft_ratio + emd_ratio - 1.0) > 0.001:
            return HybridFFTEMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                fft_bit_length=0,
                emd_bit_length=0,
                hybrid_instance_id="",
                message="FFT ratio and EMD ratio must sum to 1.0"
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return HybridFFTEMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                fft_bit_length=0,
                emd_bit_length=0,
                hybrid_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Prepare FFT and EMD parameters
        fft_params = {
            "r_in": r_in,
            "r_out": r_out,
            "phase_levels": phase_levels,
            "header_repeat": header_repeat,
            "payload_repeat": payload_repeat,
            "color_order": color_order,
            "header_channel": header_channel,
            "payload_channel": payload_channel,
            "mag_min_boost": mag_min_boost
        }

        emd_params = {
            "n": n
        }

        # Import FFT-EMD hybrid class
        from src.methods.hybrid.fft_emd import FFTEMDHybrid

        # Create hybrid instance
        hybrid_instance_id = str(__import__('uuid').uuid4())
        hybrid = FFTEMDHybrid(
            fft_emd_ratio=(fft_ratio, emd_ratio),
            fft_params=fft_params,
            emd_params=emd_params
        )

        # Store hybrid instance using the existing manager (adapting for FFT-EMD)
        HybridInstanceManager._instances[hybrid_instance_id] = hybrid
        HybridInstanceManager._instance_timestamps[hybrid_instance_id] = __import__('time').time()

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{hybrid_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("hybrid/fft-emd/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, (fft_bit_length, emd_bit_length) = hybrid.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{hybrid_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("hybrid/fft-emd/embed", filename, stego_image_bytes)

        return HybridFFTEMDEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            fft_bit_length=fft_bit_length,
            emd_bit_length=emd_bit_length,
            hybrid_instance_id=hybrid_instance_id,
            message=f"Successfully embedded {fft_bit_length + emd_bit_length} bits using FFT-EMD hybrid steganography"
        )

    except ValueError as e:
        return HybridFFTEMDEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            fft_bit_length=0,
            emd_bit_length=0,
            hybrid_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/dct-lsb/{hybrid_instance_id}", response_model=HybridDCTLSBExtractResponse, summary="Extract message using DCT-LSB hybrid steganography")
async def extract_dct_lsb(
    hybrid_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    dct_bit_length: int = Form(..., gt=0, description="Number of bits to extract using DCT"),
    lsb_bit_length: int = Form(..., gt=0, description="Number of bits to extract using LSB"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> HybridDCTLSBExtractResponse:
    """
    Extract a secret message from a stego image using DCT-LSB hybrid steganography.

    - **hybrid_instance_id**: Hybrid instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **dct_bit_length**: Number of bits to extract using DCT
    - **lsb_bit_length**: Number of bits to extract using LSB
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return HybridDCTLSBExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared hybrid instance using the instance ID from path parameter
        hybrid = HybridInstanceManager.get_instance(hybrid_instance_id)
        if not hybrid:
            return HybridDCTLSBExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid hybrid instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = hybrid.extract(stego_image_array, (dct_bit_length, lsb_bit_length))

        # Calculate metrics if original image is provided
        stego_metrics = None
        if original_image:
            try:
                original_image_array = await read_uploaded_file(original_image)
                if validate_image(original_image_array):
                    metrics_calculator = SteganographyMetrics(original_image_array, stego_image_array)
                    metrics_dict = metrics_calculator.get_all_metrics()
                    stego_metrics = MetricsModel(**metrics_dict)
            except Exception as e:
                # Log error but don't fail the extraction
                pass

        # Run robustness testing if original message is provided
        robust_metrics = None
        if original_message:
            try:
                from src.helpers.binary_massage import message_to_binary
                original_binary_message = message_to_binary(original_message)

                # Create robustness tester with the hybrid instance
                tester = RobustnessTester(hybrid, original_binary_message)

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations, bit_lengths=(dct_bit_length, lsb_bit_length))

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_dct_lsb_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder (in real implementation, this would be the actual attacked image)
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "hybrid/dct-lsb/robust",
                        attack_image_name,
                        attack_image_bytes
                    )

                    # Add to detail attacks
                    detail_attacks.append({
                        attack_label: {
                            "ber": ber,
                            "robust_image_url": attack_image_url
                        }
                    })

                # Calculate average BER
                avg_ber = None
                if robustness_results:
                    avg_ber = sum(robustness_results.values()) / len(robustness_results)

                # Build robust metrics object
                robust_metrics = {
                    "detail_attacks": detail_attacks,
                    "avg_ber": avg_ber
                }

            except Exception as e:
                # Log error but don't fail the extraction if robustness testing fails
                pass

        total_bits = dct_bit_length + lsb_bit_length
        return HybridDCTLSBExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {total_bits} bits using DCT-LSB hybrid steganography"
        )

    except ValueError as e:
        return HybridDCTLSBExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/dct-pvd/{hybrid_instance_id}", response_model=HybridDCTPVDExtractResponse, summary="Extract message using DCT-PVD hybrid steganography")
async def extract_dct_pvd(
    hybrid_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    dct_bit_length: int = Form(..., gt=0, description="Number of bits to extract using DCT"),
    pvd_bit_length: int = Form(..., gt=0, description="Number of bits to extract using PVD"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> HybridDCTPVDExtractResponse:
    """
    Extract a secret message from a stego image using DCT-PVD hybrid steganography.

    - **hybrid_instance_id**: Hybrid instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **dct_bit_length**: Number of bits to extract using DCT
    - **pvd_bit_length**: Number of bits to extract using PVD
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return HybridDCTPVDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared hybrid instance using the instance ID from path parameter
        hybrid = HybridInstanceManager.get_instance(hybrid_instance_id)
        if not hybrid:
            return HybridDCTPVDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid hybrid instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = hybrid.extract(stego_image_array, (dct_bit_length, pvd_bit_length))

        # Calculate metrics if original image is provided
        stego_metrics = None
        if original_image:
            try:
                original_image_array = await read_uploaded_file(original_image)
                if validate_image(original_image_array):
                    metrics_calculator = SteganographyMetrics(original_image_array, stego_image_array)
                    metrics_dict = metrics_calculator.get_all_metrics()
                    stego_metrics = MetricsModel(**metrics_dict)
            except Exception as e:
                # Log error but don't fail the extraction
                pass

        # Run robustness testing if original message is provided
        robust_metrics = None
        if original_message:
            try:
                from src.helpers.binary_massage import message_to_binary
                original_binary_message = message_to_binary(original_message)

                # Create robustness tester with the hybrid instance
                tester = RobustnessTester(hybrid, original_binary_message)

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations, bit_lengths=(dct_bit_length, pvd_bit_length))

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_dct_pvd_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "hybrid/dct-pvd/robust",
                        attack_image_name,
                        attack_image_bytes
                    )

                    # Add to detail attacks
                    detail_attacks.append({
                        attack_label: {
                            "ber": ber,
                            "robust_image_url": attack_image_url
                        }
                    })

                # Calculate average BER
                avg_ber = None
                if robustness_results:
                    avg_ber = sum(robustness_results.values()) / len(robustness_results)

                # Build robust metrics object
                robust_metrics = {
                    "detail_attacks": detail_attacks,
                    "avg_ber": avg_ber
                }

            except Exception as e:
                # Log error but don't fail the extraction if robustness testing fails
                pass

        total_bits = dct_bit_length + pvd_bit_length
        return HybridDCTPVDExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {total_bits} bits using DCT-PVD hybrid steganography"
        )

    except ValueError as e:
        return HybridDCTPVDExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/dct-emd/{hybrid_instance_id}", response_model=HybridDCTEMDExtractResponse, summary="Extract message using DCT-EMD hybrid steganography")
async def extract_dct_emd(
    hybrid_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    dct_bit_length: int = Form(..., gt=0, description="Number of bits to extract using DCT"),
    emd_bit_length: int = Form(..., gt=0, description="Number of bits to extract using EMD"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> HybridDCTEMDExtractResponse:
    """
    Extract a secret message from a stego image using DCT-EMD hybrid steganography.

    - **hybrid_instance_id**: Hybrid instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **dct_bit_length**: Number of bits to extract using DCT
    - **emd_bit_length**: Number of bits to extract using EMD
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return HybridDCTEMDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared hybrid instance using the instance ID from path parameter
        hybrid = HybridInstanceManager.get_instance(hybrid_instance_id)
        if not hybrid:
            return HybridDCTEMDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid hybrid instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = hybrid.extract(stego_image_array, (dct_bit_length, emd_bit_length))

        # Calculate metrics if original image is provided
        stego_metrics = None
        if original_image:
            try:
                original_image_array = await read_uploaded_file(original_image)
                if validate_image(original_image_array):
                    metrics_calculator = SteganographyMetrics(original_image_array, stego_image_array)
                    metrics_dict = metrics_calculator.get_all_metrics()
                    stego_metrics = MetricsModel(**metrics_dict)
            except Exception as e:
                # Log error but don't fail the extraction
                pass

        # Run robustness testing if original message is provided
        robust_metrics = None
        if original_message:
            try:
                from src.helpers.binary_massage import message_to_binary
                original_binary_message = message_to_binary(original_message)

                # Create robustness tester with the hybrid instance
                tester = RobustnessTester(hybrid, original_binary_message)

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations, bit_lengths=(dct_bit_length, emd_bit_length))

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_dct_emd_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "hybrid/dct-emd/robust",
                        attack_image_name,
                        attack_image_bytes
                    )

                    # Add to detail attacks
                    detail_attacks.append({
                        attack_label: {
                            "ber": ber,
                            "robust_image_url": attack_image_url
                        }
                    })

                # Calculate average BER
                avg_ber = None
                if robustness_results:
                    avg_ber = sum(robustness_results.values()) / len(robustness_results)

                # Build robust metrics object
                robust_metrics = {
                    "detail_attacks": detail_attacks,
                    "avg_ber": avg_ber
                }

            except Exception as e:
                # Log error but don't fail the extraction if robustness testing fails
                pass

        total_bits = dct_bit_length + emd_bit_length
        return HybridDCTEMDExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {total_bits} bits using DCT-EMD hybrid steganography"
        )

    except ValueError as e:
        return HybridDCTEMDExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/dwt-lsb/{hybrid_instance_id}", response_model=HybridDWTLSBExtractResponse, summary="Extract message using DWT-LSB hybrid steganography")
async def extract_dwt_lsb(
    hybrid_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    dwt_bit_length: int = Form(..., gt=0, description="Number of bits to extract using DWT"),
    lsb_bit_length: int = Form(..., gt=0, description="Number of bits to extract using LSB"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> HybridDWTLSBExtractResponse:
    """
    Extract a secret message from a stego image using DWT-LSB hybrid steganography.

    - **hybrid_instance_id**: Hybrid instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **dwt_bit_length**: Number of bits to extract using DWT
    - **lsb_bit_length**: Number of bits to extract using LSB
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return HybridDWTLSBExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared hybrid instance using the instance ID from path parameter
        hybrid = HybridInstanceManager.get_instance(hybrid_instance_id)
        if not hybrid:
            return HybridDWTLSBExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid hybrid instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = hybrid.extract(stego_image_array, (dwt_bit_length, lsb_bit_length))

        # Calculate metrics if original image is provided
        stego_metrics = None
        if original_image:
            try:
                original_image_array = await read_uploaded_file(original_image)
                if validate_image(original_image_array):
                    metrics_calculator = SteganographyMetrics(original_image_array, stego_image_array)
                    metrics_dict = metrics_calculator.get_all_metrics()
                    stego_metrics = MetricsModel(**metrics_dict)
            except Exception as e:
                # Log error but don't fail the extraction
                pass

        # Run robustness testing if original message is provided
        robust_metrics = None
        if original_message:
            try:
                from src.helpers.binary_massage import message_to_binary
                original_binary_message = message_to_binary(original_message)

                # Create robustness tester with the hybrid instance
                tester = RobustnessTester(hybrid, original_binary_message)

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations, bit_lengths=(dwt_bit_length, lsb_bit_length))

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_dwt_lsb_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "hybrid/dwt-lsb/robust",
                        attack_image_name,
                        attack_image_bytes
                    )

                    # Add to detail attacks
                    detail_attacks.append({
                        attack_label: {
                            "ber": ber,
                            "robust_image_url": attack_image_url
                        }
                    })

                # Calculate average BER
                avg_ber = None
                if robustness_results:
                    avg_ber = sum(robustness_results.values()) / len(robustness_results)

                # Build robust metrics object
                robust_metrics = {
                    "detail_attacks": detail_attacks,
                    "avg_ber": avg_ber
                }

            except Exception as e:
                # Log error but don't fail the extraction if robustness testing fails
                pass

        total_bits = dwt_bit_length + lsb_bit_length
        return HybridDWTLSBExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {total_bits} bits using DWT-LSB hybrid steganography"
        )

    except ValueError as e:
        return HybridDWTLSBExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/dwt-pvd/{hybrid_instance_id}", response_model=HybridDWTPVDExtractResponse, summary="Extract message using DWT-PVD hybrid steganography")
async def extract_dwt_pvd(
    hybrid_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    dwt_bit_length: int = Form(..., gt=0, description="Number of bits to extract using DWT"),
    pvd_bit_length: int = Form(..., gt=0, description="Number of bits to extract using PVD"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> HybridDWTPVDExtractResponse:
    """
    Extract a secret message from a stego image using DWT-PVD hybrid steganography.

    - **hybrid_instance_id**: Hybrid instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **dwt_bit_length**: Number of bits to extract using DWT
    - **pvd_bit_length**: Number of bits to extract using PVD
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return HybridDWTPVDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared hybrid instance using the instance ID from path parameter
        hybrid = HybridInstanceManager.get_instance(hybrid_instance_id)
        if not hybrid:
            return HybridDWTPVDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid hybrid instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = hybrid.extract(stego_image_array, (dwt_bit_length, pvd_bit_length))

        # Calculate metrics if original image is provided
        stego_metrics = None
        if original_image:
            try:
                original_image_array = await read_uploaded_file(original_image)
                if validate_image(original_image_array):
                    metrics_calculator = SteganographyMetrics(original_image_array, stego_image_array)
                    metrics_dict = metrics_calculator.get_all_metrics()
                    stego_metrics = MetricsModel(**metrics_dict)
            except Exception as e:
                # Log error but don't fail the extraction
                pass

        # Run robustness testing if original message is provided
        robust_metrics = None
        if original_message:
            try:
                from src.helpers.binary_massage import message_to_binary
                original_binary_message = message_to_binary(original_message)

                # Create robustness tester with the hybrid instance
                tester = RobustnessTester(hybrid, original_binary_message)

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations, bit_lengths=(dwt_bit_length, pvd_bit_length))

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_dwt_pvd_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "hybrid/dwt-pvd/robust",
                        attack_image_name,
                        attack_image_bytes
                    )

                    # Add to detail attacks
                    detail_attacks.append({
                        attack_label: {
                            "ber": ber,
                            "robust_image_url": attack_image_url
                        }
                    })

                # Calculate average BER
                avg_ber = None
                if robustness_results:
                    avg_ber = sum(robustness_results.values()) / len(robustness_results)

                # Build robust metrics object
                robust_metrics = {
                    "detail_attacks": detail_attacks,
                    "avg_ber": avg_ber
                }

            except Exception as e:
                # Log error but don't fail the extraction if robustness testing fails
                pass

        total_bits = dwt_bit_length + pvd_bit_length
        return HybridDWTPVDExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {total_bits} bits using DWT-PVD hybrid steganography"
        )

    except ValueError as e:
        return HybridDWTPVDExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/dwt-emd/{hybrid_instance_id}", response_model=HybridDWTEMDExtractResponse, summary="Extract message using DWT-EMD hybrid steganography")
async def extract_dwt_emd(
    hybrid_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    dwt_bit_length: int = Form(..., gt=0, description="Number of bits to extract using DWT"),
    emd_bit_length: int = Form(..., gt=0, description="Number of bits to extract using EMD"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> HybridDWTEMDExtractResponse:
    """
    Extract a secret message from a stego image using DWT-EMD hybrid steganography.

    - **hybrid_instance_id**: Hybrid instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **dwt_bit_length**: Number of bits to extract using DWT
    - **emd_bit_length**: Number of bits to extract using EMD
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return HybridDWTEMDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared hybrid instance using the instance ID from path parameter
        hybrid = HybridInstanceManager.get_instance(hybrid_instance_id)
        if not hybrid:
            return HybridDWTEMDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid hybrid instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = hybrid.extract(stego_image_array, (dwt_bit_length, emd_bit_length))

        # Calculate metrics if original image is provided
        stego_metrics = None
        if original_image:
            try:
                original_image_array = await read_uploaded_file(original_image)
                if validate_image(original_image_array):
                    metrics_calculator = SteganographyMetrics(original_image_array, stego_image_array)
                    metrics_dict = metrics_calculator.get_all_metrics()
                    stego_metrics = MetricsModel(**metrics_dict)
            except Exception as e:
                # Log error but don't fail the extraction
                pass

        # Run robustness testing if original message is provided
        robust_metrics = None
        if original_message:
            try:
                from src.helpers.binary_massage import message_to_binary
                original_binary_message = message_to_binary(original_message)

                # Create robustness tester with the hybrid instance
                tester = RobustnessTester(hybrid, original_binary_message)

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations, bit_lengths=(dwt_bit_length, emd_bit_length))

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_dwt_emd_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "hybrid/dwt-emd/robust",
                        attack_image_name,
                        attack_image_bytes
                    )

                    # Add to detail attacks
                    detail_attacks.append({
                        attack_label: {
                            "ber": ber,
                            "robust_image_url": attack_image_url
                        }
                    })

                # Calculate average BER
                avg_ber = None
                if robustness_results:
                    avg_ber = sum(robustness_results.values()) / len(robustness_results)

                # Build robust metrics object
                robust_metrics = {
                    "detail_attacks": detail_attacks,
                    "avg_ber": avg_ber
                }

            except Exception as e:
                # Log error but don't fail the extraction if robustness testing fails
                pass

        total_bits = dwt_bit_length + emd_bit_length
        return HybridDWTEMDExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {total_bits} bits using DWT-EMD hybrid steganography"
        )

    except ValueError as e:
        return HybridDWTEMDExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/fft-lsb/{hybrid_instance_id}", response_model=HybridFFTLSBExtractResponse, summary="Extract message using FFT-LSB hybrid steganography")
async def extract_fft_lsb(
    hybrid_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    fft_bit_length: int = Form(..., gt=0, description="Number of bits to extract using FFT"),
    lsb_bit_length: int = Form(..., gt=0, description="Number of bits to extract using LSB"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> HybridFFTLSBExtractResponse:
    """
    Extract a secret message from a stego image using FFT-LSB hybrid steganography.

    - **hybrid_instance_id**: Hybrid instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **fft_bit_length**: Number of bits to extract using FFT
    - **lsb_bit_length**: Number of bits to extract using LSB
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return HybridFFTLSBExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared hybrid instance using the instance ID from path parameter
        hybrid = HybridInstanceManager.get_instance(hybrid_instance_id)
        if not hybrid:
            return HybridFFTLSBExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid hybrid instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = hybrid.extract(stego_image_array, (fft_bit_length, lsb_bit_length))

        # Calculate metrics if original image is provided
        stego_metrics = None
        if original_image:
            try:
                original_image_array = await read_uploaded_file(original_image)
                if validate_image(original_image_array):
                    metrics_calculator = SteganographyMetrics(original_image_array, stego_image_array)
                    metrics_dict = metrics_calculator.get_all_metrics()
                    stego_metrics = MetricsModel(**metrics_dict)
            except Exception as e:
                # Log error but don't fail the extraction
                pass

        # Run robustness testing if original message is provided
        robust_metrics = None
        if original_message:
            try:
                from src.helpers.binary_massage import message_to_binary
                original_binary_message = message_to_binary(original_message)

                # Create robustness tester with the hybrid instance
                tester = RobustnessTester(hybrid, original_binary_message)

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations, bit_lengths=(fft_bit_length, lsb_bit_length))

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_fft_lsb_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "hybrid/fft-lsb/robust",
                        attack_image_name,
                        attack_image_bytes
                    )

                    # Add to detail attacks
                    detail_attacks.append({
                        attack_label: {
                            "ber": ber,
                            "robust_image_url": attack_image_url
                        }
                    })

                # Calculate average BER
                avg_ber = None
                if robustness_results:
                    avg_ber = sum(robustness_results.values()) / len(robustness_results)

                # Build robust metrics object
                robust_metrics = {
                    "detail_attacks": detail_attacks,
                    "avg_ber": avg_ber
                }

            except Exception as e:
                # Log error but don't fail the extraction if robustness testing fails
                pass

        total_bits = fft_bit_length + lsb_bit_length
        return HybridFFTLSBExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {total_bits} bits using FFT-LSB hybrid steganography"
        )

    except ValueError as e:
        return HybridFFTLSBExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/fft-pvd/{hybrid_instance_id}", response_model=HybridFFTPVDExtractResponse, summary="Extract message using FFT-PVD hybrid steganography")
async def extract_fft_pvd(
    hybrid_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    fft_bit_length: int = Form(..., gt=0, description="Number of bits to extract using FFT"),
    pvd_bit_length: int = Form(..., gt=0, description="Number of bits to extract using PVD"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> HybridFFTPVDExtractResponse:
    """
    Extract a secret message from a stego image using FFT-PVD hybrid steganography.

    - **hybrid_instance_id**: Hybrid instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **fft_bit_length**: Number of bits to extract using FFT
    - **pvd_bit_length**: Number of bits to extract using PVD
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return HybridFFTPVDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared hybrid instance using the instance ID from path parameter
        hybrid = HybridInstanceManager.get_instance(hybrid_instance_id)
        if not hybrid:
            return HybridFFTPVDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid hybrid instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = hybrid.extract(stego_image_array, (fft_bit_length, pvd_bit_length))

        # Calculate metrics if original image is provided
        stego_metrics = None
        if original_image:
            try:
                original_image_array = await read_uploaded_file(original_image)
                if validate_image(original_image_array):
                    metrics_calculator = SteganographyMetrics(original_image_array, stego_image_array)
                    metrics_dict = metrics_calculator.get_all_metrics()
                    stego_metrics = MetricsModel(**metrics_dict)
            except Exception as e:
                # Log error but don't fail the extraction
                pass

        # Run robustness testing if original message is provided
        robust_metrics = None
        if original_message:
            try:
                from src.helpers.binary_massage import message_to_binary
                original_binary_message = message_to_binary(original_message)

                # Create robustness tester with the hybrid instance
                tester = RobustnessTester(hybrid, original_binary_message)

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations, bit_lengths=(fft_bit_length, pvd_bit_length))

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_fft_pvd_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "hybrid/fft-pvd/robust",
                        attack_image_name,
                        attack_image_bytes
                    )

                    # Add to detail attacks
                    detail_attacks.append({
                        attack_label: {
                            "ber": ber,
                            "robust_image_url": attack_image_url
                        }
                    })

                # Calculate average BER
                avg_ber = None
                if robustness_results:
                    avg_ber = sum(robustness_results.values()) / len(robustness_results)

                # Build robust metrics object
                robust_metrics = {
                    "detail_attacks": detail_attacks,
                    "avg_ber": avg_ber
                }

            except Exception as e:
                # Log error but don't fail the extraction if robustness testing fails
                pass

        total_bits = fft_bit_length + pvd_bit_length
        return HybridFFTPVDExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {total_bits} bits using FFT-PVD hybrid steganography"
        )

    except ValueError as e:
        return HybridFFTPVDExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/fft-emd/{hybrid_instance_id}", response_model=HybridFFTEMDExtractResponse, summary="Extract message using FFT-EMD hybrid steganography")
async def extract_fft_emd(
    hybrid_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    fft_bit_length: int = Form(..., gt=0, description="Number of bits to extract using FFT"),
    emd_bit_length: int = Form(..., gt=0, description="Number of bits to extract using EMD"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> HybridFFTEMDExtractResponse:
    """
    Extract a secret message from a stego image using FFT-EMD hybrid steganography.

    - **hybrid_instance_id**: Hybrid instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **fft_bit_length**: Number of bits to extract using FFT
    - **emd_bit_length**: Number of bits to extract using EMD
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return HybridFFTEMDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared hybrid instance using the instance ID from path parameter
        hybrid = HybridInstanceManager.get_instance(hybrid_instance_id)
        if not hybrid:
            return HybridFFTEMDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid hybrid instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = hybrid.extract(stego_image_array, (fft_bit_length, emd_bit_length))

        # Calculate metrics if original image is provided
        stego_metrics = None
        if original_image:
            try:
                original_image_array = await read_uploaded_file(original_image)
                if validate_image(original_image_array):
                    metrics_calculator = SteganographyMetrics(original_image_array, stego_image_array)
                    metrics_dict = metrics_calculator.get_all_metrics()
                    stego_metrics = MetricsModel(**metrics_dict)
            except Exception as e:
                # Log error but don't fail the extraction
                pass

        # Run robustness testing if original message is provided
        robust_metrics = None
        if original_message:
            try:
                from src.helpers.binary_massage import message_to_binary
                original_binary_message = message_to_binary(original_message)

                # Create robustness tester with the hybrid instance
                tester = RobustnessTester(hybrid, original_binary_message)

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations, bit_lengths=(fft_bit_length, emd_bit_length))

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_fft_emd_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "hybrid/fft-emd/robust",
                        attack_image_name,
                        attack_image_bytes
                    )

                    # Add to detail attacks
                    detail_attacks.append({
                        attack_label: {
                            "ber": ber,
                            "robust_image_url": attack_image_url
                        }
                    })

                # Calculate average BER
                avg_ber = None
                if robustness_results:
                    avg_ber = sum(robustness_results.values()) / len(robustness_results)

                # Build robust metrics object
                robust_metrics = {
                    "detail_attacks": detail_attacks,
                    "avg_ber": avg_ber
                }

            except Exception as e:
                # Log error but don't fail the extraction if robustness testing fails
                pass

        total_bits = fft_bit_length + emd_bit_length
        return HybridFFTEMDExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {total_bits} bits using FFT-EMD hybrid steganography"
        )

    except ValueError as e:
        return HybridFFTEMDExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")