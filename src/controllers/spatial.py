from fastapi import APIRouter, HTTPException, UploadFile, File, Form

from src.helpers.steganography_metrics import SteganographyMetrics
from src.helpers.image_utils import download_image_from_url, encode_image_to_bytes, validate_image, read_uploaded_file
from src.helpers.lsb_instance_manager import LSBInstanceManager
from src.helpers.pvd_instance_manager import PVDInstanceManager
from src.helpers.emd_instance_manager import EMDInstanceManager
from src.helpers.robustness_tester import RobustnessTester, attack_configurations
from src.s3.utils import upload_image_and_get_url
from src.models.steganography import (
    LSBEmbedResponse, LSBExtractResponse, PVDEmbedResponse,
    PVDExtractResponse, EMDEmbedResponse, EMDExtractResponse,
    RobustnessTestResult, SteganographyMetrics as MetricsModel
)

router = APIRouter(prefix="/spatial", tags=["spatial"])


@router.post("/embed/lsb", response_model=LSBEmbedResponse, summary="Embed message using LSB steganography with file upload")
async def embed_lsb(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    bits_per_channel: int = Form(1, ge=1, le=4, description="Number of bits per channel to use")
) -> LSBEmbedResponse:
    """
    Embed a secret message into an uploaded image using LSB steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **bits_per_channel**: Number of bits per channel (1-4)

    Returns the stego image URL and embedding details with LSB instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return LSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                lsb_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return LSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                lsb_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Create and store LSB instance for pairing
        lsb_instance_id = LSBInstanceManager.create_instance(bits_per_channel=bits_per_channel)
        lsb = LSBInstanceManager.get_instance(lsb_instance_id)

        if not lsb:
            return LSBEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                lsb_instance_id="",
                message="Failed to create LSB instance"
            )

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{lsb_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("spatial/lsb/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, bit_length = lsb.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{lsb_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("spatial/lsb/embed", filename, stego_image_bytes)

        return LSBEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            bit_length=bit_length,
            lsb_instance_id=lsb_instance_id,
            message=f"Successfully embedded {bit_length} bits using LSB steganography"
        )

    except ValueError as e:
        return LSBEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            bit_length=0,
            lsb_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/lsb/{lsb_instance_id}", response_model=LSBExtractResponse, summary="Extract message using LSB steganography")
async def extract_lsb(
    lsb_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    bit_length: int = Form(..., gt=0, description="Number of bits to extract"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> LSBExtractResponse:
    """
    Extract a secret message from a stego image using LSB steganography.

    - **lsb_instance_id**: LSB instance ID from embed operation (path parameter)
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
            return LSBExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared LSB instance using the instance ID from path parameter
        lsb = LSBInstanceManager.get_instance(lsb_instance_id)
        if not lsb:
            return LSBExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid LSB instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = lsb.extract(stego_image_array, bit_length)

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
                tester = RobustnessTester(lsb, original_binary_message[:bit_length])

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
                    attack_image_name = f"robust_lsb_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "spatial/lsb/robust",
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

        return LSBExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {bit_length} bits using LSB steganography"
        )

    except ValueError as e:
        return LSBExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/pvd", response_model=PVDEmbedResponse, summary="Embed message using PVD steganography with file upload")
async def embed_pvd(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed")
) -> PVDEmbedResponse:
    """
    Embed a secret message into an uploaded image using PVD steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed

    Returns the stego image URL and embedding details with PVD instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return PVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                pvd_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return PVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                pvd_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Create and store PVD instance for pairing
        pvd_instance_id = PVDInstanceManager.create_instance()
        pvd = PVDInstanceManager.get_instance(pvd_instance_id)

        if not pvd:
            return PVDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                pvd_instance_id="",
                message="Failed to create PVD instance"
            )

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{pvd_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("spatial/pvd/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, bit_length = pvd.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{pvd_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("spatial/pvd/embed", filename, stego_image_bytes)

        return PVDEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            bit_length=bit_length,
            pvd_instance_id=pvd_instance_id,
            message=f"Successfully embedded {bit_length} bits using PVD steganography"
        )

    except ValueError as e:
        return PVDEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            bit_length=0,
            pvd_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/pvd/{pvd_instance_id}", response_model=PVDExtractResponse, summary="Extract message using PVD steganography")
async def extract_pvd(
    pvd_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    bit_length: int = Form(..., gt=0, description="Number of bits to extract"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> PVDExtractResponse:
    """
    Extract a secret message from a stego image using PVD steganography.

    - **pvd_instance_id**: PVD instance ID from embed operation (path parameter)
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
            return PVDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared PVD instance using the instance ID from path parameter
        pvd = PVDInstanceManager.get_instance(pvd_instance_id)
        if not pvd:
            return PVDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid PVD instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = pvd.extract(stego_image_array, bit_length)

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
                tester = RobustnessTester(pvd, original_binary_message[:bit_length])

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
                    attack_image_name = f"robust_pvd_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "spatial/pvd/robust",
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

        return PVDExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {bit_length} bits using PVD steganography"
        )

    except ValueError as e:
        return PVDExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/embed/emd", response_model=EMDEmbedResponse, summary="Embed message using EMD steganography with file upload")
async def embed_emd(
    original_image: UploadFile = File(..., description="Original cover image file"),
    message: str = Form(..., description="Secret message to embed"),
    n: int = Form(2, ge=1, le=10, description="EMD parameter n (number of pixels per group)")
) -> EMDEmbedResponse:
    """
    Embed a secret message into an uploaded image using EMD steganography.

    - **original_image**: Cover image file to embed message in
    - **message**: Secret message to embed
    - **n**: EMD parameter n (1-10, default 2)

    Returns the stego image URL and embedding details with EMD instance ID for extraction pairing.
    """
    try:
        # Validate file type
        if not original_image.content_type or not original_image.content_type.startswith('image/'):
            return EMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                emd_instance_id="",
                message="Invalid file type. Please upload an image file."
            )

        # Read and validate uploaded image
        original_image_array = await read_uploaded_file(original_image)
        if not validate_image(original_image_array):
            return EMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                emd_instance_id="",
                message="Invalid or corrupted image file"
            )

        # Create and store EMD instance for pairing
        emd_instance_id = EMDInstanceManager.create_instance(n=n)
        emd = EMDInstanceManager.get_instance(emd_instance_id)

        if not emd:
            return EMDEmbedResponse(
                success=False,
                stego_image_url="",
                original_image_url="",
                bit_length=0,
                emd_instance_id="",
                message="Failed to create EMD instance"
            )

        # Upload original image first
        original_image_bytes = encode_image_to_bytes(original_image_array, "PNG")
        original_filename = f"original_image_{emd_instance_id[:8]}.png"
        original_image_url = upload_image_and_get_url("spatial/emd/original", original_filename, original_image_bytes)

        # Embed message
        stego_image, bit_length = emd.embed(original_image_array, message)

        # Encode and upload stego image
        stego_image_bytes = encode_image_to_bytes(stego_image, "PNG")
        filename = f"stego_image_{emd_instance_id[:8]}.png"
        stego_image_url = upload_image_and_get_url("spatial/emd/embed", filename, stego_image_bytes)

        return EMDEmbedResponse(
            success=True,
            stego_image_url=stego_image_url,
            original_image_url=original_image_url,
            bit_length=bit_length,
            emd_instance_id=emd_instance_id,
            message=f"Successfully embedded {bit_length} bits using EMD steganography"
        )

    except ValueError as e:
        return EMDEmbedResponse(
            success=False,
            stego_image_url="",
            original_image_url="",
            bit_length=0,
            emd_instance_id="",
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/extract/emd/{emd_instance_id}", response_model=EMDExtractResponse, summary="Extract message using EMD steganography")
async def extract_emd(
    emd_instance_id: str,
    stego_image: UploadFile = File(..., description="Stego image file"),
    bit_length: int = Form(..., gt=0, description="Number of bits to extract"),
    original_image: UploadFile = File(None, description="Original image file for metrics (optional)"),
    original_message: str = Form(None, description="Original message for robustness testing (optional)")
) -> EMDExtractResponse:
    """
    Extract a secret message from a stego image using EMD steganography.

    - **emd_instance_id**: EMD instance ID from embed operation (path parameter)
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
            return EMDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid or corrupted stego image file"
            )

        # Get the shared EMD instance using the instance ID from path parameter
        emd = EMDInstanceManager.get_instance(emd_instance_id)
        if not emd:
            return EMDExtractResponse(
                success=False,
                extracted_message="",
                stego_metrics=None,
                message="Invalid EMD instance ID. Make sure to use the same instance ID from the embed operation."
            )

        # Extract message using the shared instance
        extracted_message = emd.extract(stego_image_array, bit_length)

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
                tester = RobustnessTester(emd, original_binary_message[:bit_length])

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
                    attack_image_name = f"robust_emd_{attack_name}_{safe_label}_{instance_id}.png"

                    # Create attack image placeholder
                    attack_image_bytes = encode_image_to_bytes(stego_image_array, "PNG")

                    # Upload attacked image to S3
                    attack_image_url = upload_image_and_get_url(
                        "spatial/emd/robust",
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

        return EMDExtractResponse(
            success=True,
            extracted_message=extracted_message,
            stego_metrics=stego_metrics,
            robust_metrics=robust_metrics,
            message=f"Successfully extracted {bit_length} bits using EMD steganography"
        )

    except ValueError as e:
        return EMDExtractResponse(
            success=False,
            extracted_message="",
            stego_metrics=None,
            message=f"Validation error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
