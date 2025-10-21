from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from src.helpers.create_massage import create_pattern_padded_message
from src.models.message import MessageRequest, MessageResponse, HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="Health check")
async def health_check() -> HealthResponse:
    """
    Check the health status of the message generation service.
    """
    return HealthResponse(
        status="ok"
    )