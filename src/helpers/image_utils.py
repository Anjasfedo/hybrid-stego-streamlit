import numpy as np
import cv2
import requests
import io
from typing import Tuple
from fastapi import UploadFile


def download_image_from_url(url: str) -> np.ndarray:
    """Download image from URL and return as numpy array."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        image_array = np.frombuffer(response.content, np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError("Could not decode image")
        return image
    except Exception as e:
        raise ValueError(f"Failed to download image: {str(e)}")


def encode_image_to_bytes(image: np.ndarray, format: str = "PNG") -> bytes:
    """Encode numpy array image to bytes."""
    success, encoded_img = cv2.imencode(f".{format.lower()}", image)
    if not success:
        raise ValueError("Failed to encode image")
    return encoded_img.tobytes()


def validate_image(image: np.ndarray) -> bool:
    """Validate if the image is properly formatted."""
    return image is not None and len(image.shape) in [2, 3] and image.size > 0


async def read_uploaded_file(file: UploadFile) -> np.ndarray:
    """
    Read uploaded image file and return as numpy array.

    Args:
        file: UploadFile object from FastAPI

    Returns:
        Image as numpy array

    Raises:
        ValueError: If file cannot be processed
    """
    try:
        # Read file content
        content = await file.read()

        # Convert to numpy array
        image_array = np.frombuffer(content, np.uint8)

        # Decode image
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

        if image is None:
            raise ValueError("Could not decode uploaded image")

        return image

    except Exception as e:
        raise ValueError(f"Failed to process uploaded file: {str(e)}")