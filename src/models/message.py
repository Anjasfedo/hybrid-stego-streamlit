from pydantic import BaseModel, Field
from typing import Optional


class MessageRequest(BaseModel):
    base_message: Optional[str] = Field(None, description="The base message to pad (optional, will use default if not provided)", example="Hello World")
    target_byte_size: int = Field(..., ge=1, le=10000, description="Target size in bytes", example=512)


class MessageResponse(BaseModel):
    success: bool = Field(..., description="Whether the operation was successful")
    message: str = Field(..., description="The generated message or error message")
    actual_byte_size: Optional[int] = Field(None, description="Actual size of the generated message in bytes")
    target_byte_size: int = Field(..., description="Requested target size in bytes")


class HealthResponse(BaseModel):
    status: str = Field(..., description="Health status", example="ok")