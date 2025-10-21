from fastapi import APIRouter, HTTPException

from src.helpers.create_massage import create_pattern_padded_message, my_message
from src.models.message import MessageRequest, MessageResponse

router = APIRouter(prefix="/message", tags=["message"])

@router.post("/generate", response_model=MessageResponse, summary="Generate padded message")
async def generate_message(request: MessageRequest) -> MessageResponse:
    """
    Generate a message with deterministic padding to reach a specific byte size.

    - **base_message**: The initial message to pad (optional, will use default if not provided)
    - **target_byte_size**: Desired total size in bytes (1-10000)

    Returns the padded message with metadata about the operation.
    """
    try:
        base_message = request.base_message if request.base_message is not None else my_message
        padded_message = create_pattern_padded_message(base_message, request.target_byte_size)

        if not padded_message:
            return MessageResponse(
                success=False,
                message="Failed to generate message - message may be too large or encoding failed",
                actual_byte_size=None,
                target_byte_size=request.target_byte_size
            )

        actual_byte_size = len(padded_message.encode('utf-8'))

        return MessageResponse(
            success=True,
            message=padded_message,
            actual_byte_size=actual_byte_size,
            target_byte_size=request.target_byte_size
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
