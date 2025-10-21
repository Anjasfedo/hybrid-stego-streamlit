from fastapi import APIRouter, HTTPException, UploadFile, File, Form

from src.helpers.steganography_metrics import SteganographyMetrics
from src.helpers.image_utils import encode_image_to_bytes, validate_image, read_uploaded_file
from src.helpers.dct_instance_manager import DCTInstanceManager
from src.helpers.dwt_instance_manager import DWTInstanceManager
from src.helpers.fft_instance_manager import FFTInstanceManager
from src.helpers.robustness_tester import RobustnessTester, attack_configurations
from src.s3.utils import upload_image_and_get_url
from src.models.steganography import (
    DCTEmbedResponse, DCTExtractResponse,
    DWTEmbedResponse, DWTExtractResponse,
    FFTEmbedResponse, FFTExtractResponse,
    RobustnessTestResult, SteganographyMetrics as MetricsModel
)

router = APIRouter(prefix="/frequency", tags=["frequency"])


@router.post("/embed/dct", response_model=DCTEmbedResponse, summary="Embed message using DCT steganography with file upload")
async def embed_dct(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    block_size: int = Form(8, ge=4, le=16, description="Block size for DCT (4-16, default 8)"),
    quant_factor: int = Form(70, ge=5, le=100, description="Quantization factor (5-100, default 70)"),
    embed_positions: str = Form("mid", description="Embed positions: 'mid_low', 'mid', 'high', or 'default' (default: mid)")
) -> DCTEmbedResponse:
    """
    Embed a secret message into an uploaded image using DCT steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **block_size**: Block size for DCT (4-16, default 8)
    - **quant_factor**: Quantization factor (5-100, default 70, higher for robustness but lower quality)
    - **embed_positions**: Embed positions preset ('mid_low', 'mid', 'high', or 'default', default 'mid')

    Returns the stego image URL and embedding details with DCT instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return DCTEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                dct_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return DCTEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                dct_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Parse embed positions
        from src.helpers.dct_instance_manager import POSITION_MID_LOW, POSITION_MID, POSITION_HIGH

        embed_positions_map = {
            "mid_low": POSITION_MID_LOW,
            "mid": POSITION_MID,
            "high": POSITION_HIGH,
            "default": POSITION_MID
        }

        selected_positions = embed_positions_map.get(embed_positions.lower(), POSITION_MID)

        # Create and store DCT instance for pairing
        dct_instance_id = DCTInstanceManager.create_instance(
            block_size=block_size,
            quant_factor=quant_factor,
            embed_positions=selected_positions
        )
        dct = DCTInstanceManager.get_instance(dct_instance_id)

        if not dct:
            return DCTEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                dct_instance_id="",
                message="Failed to create DCT instance"
            )

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{dct_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("frequency/dct/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, bit_length = dct.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{dct_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("frequency/dct/embed", filename, stego_image_bytes)

        return DCTEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            bit_length=bit_length,
            dct_instance_id=dct_instance_id,
            message=f"Successfully embedded {bit_length} bits using DCT steganography"
        )

    except ValueError as e:
        return DCTEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            bit_length=0,
            dct_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/dct/{dct_instance_id}", response_model=DCTExtractResponse, summary="Extract message using DCT steganography")
async def extract_dct(
    dct_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    bit_length: int = Form(..., gt=0, description="Number of bits to extract"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> DCTExtractResponse:
    """
    Extract a secret message from a stego image using DCT steganography.

    - **dct_instance_id**: DCT instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **bit_length**: Number of bits to extract
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return DCTExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared DCT instance using the instance ID from path parameter
        dct = DCTInstanceManager.get_instance(dct_instance_id)
        if not dct:
            return DCTExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid DCT instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = dct.extract(stego_image_array, bit_length)

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

                # Create robustness tester with the steganography instance
                tester = RobustnessTester(dct, original_binary_message[:bit_length])

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations)

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_dct_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "frequency/dct/robust",
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

        return DCTExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {bit_length} bits using DCT steganography"
        )

    except ValueError as e:
        return DCTExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/dwt", response_model=DWTEmbedResponse, summary="Embed message using DWT steganography with file upload")
async def embed_dwt(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    wavelet: str = Form("haar", description="Wavelet type (default: haar)"),
    level: int = Form(3, ge=1, le=3, description="Decomposition level (1-3, default 3)"),
    band: str = Form("HH", description="Frequency band (LL, LH, HL, HH, default HH)"),
    delta: float = Form(25.0, description="Delta value (default 25.0)"),
    embed_level: int = Form(3, ge=1, le=3, description="Embedding level (1-3, must be <= decomposition level, default 3)"),
    robust_mode: bool = Form(True, description="Enable robust mode (default True)")
) -> DWTEmbedResponse:
    """
    Embed a secret message into an uploaded image using DWT steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **wavelet**: Wavelet type (default: haar)
    - **level**: Decomposition level (1-3, default 3)
    - **band**: Frequency band (LL, LH, HL, HH, default HH)
    - **delta**: Delta value (default 25.0)
    - **embed_level**: Embedding level (1-3, must be <= decomposition level, default 3)
    - **robust_mode**: Enable robust mode (default True)

    Returns the stego image URL and embedding details with DWT instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return DWTEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                dwt_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return DWTEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                dwt_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Create and store DWT instance for pairing
        dwt_instance_id = DWTInstanceManager.create_instance(
            wavelet=wavelet,
            level=level,
            band=band,
            delta=delta,
            embed_level=embed_level,
            robust_mode=robust_mode
        )
        dwt = DWTInstanceManager.get_instance(dwt_instance_id)

        if not dwt:
            return DWTEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                dwt_instance_id="",
                message="Failed to create DWT instance"
            )

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{dwt_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("frequency/dwt/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, bit_length = dwt.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{dwt_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("frequency/dwt/embed", filename, stego_image_bytes)

        return DWTEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            bit_length=bit_length,
            dwt_instance_id=dwt_instance_id,
            message=f"Successfully embedded {bit_length} bits using DWT steganography"
        )

    except ValueError as e:
        return DWTEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            bit_length=0,
            dwt_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/dwt/{dwt_instance_id}", response_model=DWTExtractResponse, summary="Extract message using DWT steganography")
async def extract_dwt(
    dwt_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    bit_length: int = Form(..., gt=0, description="Number of bits to extract"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> DWTExtractResponse:
    """
    Extract a secret message from a stego image using DWT steganography.

    - **dwt_instance_id**: DWT instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **bit_length**: Number of bits to extract
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return DWTExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared DWT instance using the instance ID from path parameter
        dwt = DWTInstanceManager.get_instance(dwt_instance_id)
        if not dwt:
            return DWTExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid DWT instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = dwt.extract(stego_image_array, bit_length)

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

                # Create robustness tester with the steganography instance
                tester = RobustnessTester(dwt, original_binary_message[:bit_length])

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations)

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_dwt_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "frequency/dwt/robust",
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

        return DWTExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {bit_length} bits using DWT steganography"
        )

    except ValueError as e:
        return DWTExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/fft", response_model=FFTEmbedResponse, summary="Embed message using FFT steganography with file upload")
async def embed_fft(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    r_in: float = Form(0.1, ge=0.05, le=0.3, description="Inner radius ratio (0.05-0.3, default 0.1)"),
    r_out: float = Form(0.4, ge=0.3, le=0.6, description="Outer radius ratio (0.3-0.6, default 0.4)"),
    phase_levels: int = Form(4, description="Phase levels (locked to 4)"),
    header_repeat: int = Form(3, ge=1, le=10, description="Header repeat count (1-10, default 3)"),
    payload_repeat: int = Form(3, ge=1, le=5, description="Payload repeat count (1-5, default 3)"),
    color_order: str = Form("RGB", description="Color order (RGB or BGR, default RGB)"),
    header_channel: str = Form("Cr", description="Header channel (Y, Cr, Cb, default Cr)"),
    payload_channel: str = Form("Cb", description="Payload channel (Y, Cr, Cb, default Cb)"),
    mag_min_boost: float = Form(3.0, ge=1.0, le=10.0, description="Minimum magnitude boost (1.0-10.0, default 3.0)")
) -> FFTEmbedResponse:
    """
    Embed a secret message into an uploaded image using FFT steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **r_in**: Inner radius ratio (0.05-0.3, default 0.1)
    - **r_out**: Outer radius ratio (0.3-0.6, default 0.4)
    - **phase_levels**: Phase levels (locked to 4)
    - **header_repeat**: Header repeat count (1-10, default 3)
    - **payload_repeat**: Payload repeat count (1-5, default 3)
    - **color_order**: Color order (RGB or BGR, default RGB)
    - **header_channel**: Header channel (Y, Cr, Cb, default Cr)
    - **payload_channel**: Payload channel (Y, Cr, Cb, default Cb)
    - **mag_min_boost**: Minimum magnitude boost (1.0-10.0, default 3.0)

    Returns the stego image URL and embedding details with FFT instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return FFTEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                fft_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return FFTEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                fft_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Create and store FFT instance for pairing
        fft_instance_id = FFTInstanceManager.create_instance(
            r_in=r_in,
            r_out=r_out,
            phase_levels=phase_levels,
            header_repeat=header_repeat,
            payload_repeat=payload_repeat,
            color_order=color_order,
            header_channel=header_channel,
            payload_channel=payload_channel,
            mag_min_boost=mag_min_boost
        )
        fft = FFTInstanceManager.get_instance(fft_instance_id)

        if not fft:
            return FFTEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                fft_instance_id="",
                message="Failed to create FFT instance"
            )

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{fft_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("frequency/fft/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, bit_length = fft.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{fft_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("frequency/fft/embed", filename, stego_image_bytes)

        return FFTEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            bit_length=bit_length,
            fft_instance_id=fft_instance_id,
            message=f"Successfully embedded {bit_length} bits using FFT steganography"
        )

    except ValueError as e:
        return FFTEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            bit_length=0,
            fft_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/fft/{fft_instance_id}", response_model=FFTExtractResponse, summary="Extract message using FFT steganography")
async def extract_fft(
    fft_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    bit_length: int = Form(None, description="Number of bits to extract (optional, can be auto-detected)"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> FFTExtractResponse:
    """
    Extract a secret message from a stego image using FFT steganography.

    - **fft_instance_id**: FFT instance ID from embed operation (path parameter)
    - **stego_image**: Stego image file containing embedded message
    - **bit_length**: Number of bits to extract (optional, can be auto-detected)
    - **original_image**: Original image file for quality metrics (optional)
    - **original_message**: Original message for robustness testing (optional)

    Returns the extracted message, optional quality metrics, and optional robustness test results.
    """
    try:
        # Read and validate stego image
        stego_image_array = await read_uploaded_file(stego_image)
        if not validate_image(stego_image_array):
            return FFTExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared FFT instance using the instance ID from path parameter
        fft = FFTInstanceManager.get_instance(fft_instance_id)
        if not fft:
            return FFTExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid FFT instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance (bit_length can be None for auto-detection)
        extracted_message = fft.extract(stego_image_array, bit_length)

        # If extraction failed, return error response
        if extracted_message is None:
            return FFTExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Failed to extract message. The image may not contain embedded data or the parameters may not match."
            )

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

                # Use actual bit length for robustness testing if bit_length is None
                robust_bit_length = bit_length if bit_length is not None else len(extracted_message.encode('utf-8')) * 8

                # Create robustness tester with the steganography instance
                tester = RobustnessTester(fft, original_binary_message[:robust_bit_length])

                # Run all attack configurations
                robustness_results = tester.run_all_tests(stego_image_array, attack_configurations)

                # Upload attacked images and build robust metrics response
                import uuid
                instance_id = str(uuid.uuid4())[:8]
                detail_attacks = []

                for attack_label, ber in robustness_results.items():
                    # Generate attack image name
                    attack_name = attack_label.split()[0].lower()
                    safe_label = attack_label.replace(" ", "_").replace("(", "").replace(")", "").replace("=", "_")
                    attack_image_name = f"robust_fft_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "frequency/fft/robust",
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

        actual_bit_length = len(extracted_message.encode('utf-8')) * 8
        return FFTExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {actual_bit_length} bits using FFT steganography"
        )

    except ValueError as e:
        return FFTExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")