#!/usr/bin/env python3
"""
ZKP Visual Authentication FastAPI Server.

This module provides a REST API for the Zero-Knowledge Proof
authentication system with visual pattern verification.
"""

import os
import time
import uuid
import base64
import logging
from typing import Dict, List, Optional, Any, Union

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator

# Import our authentication modules
from .zkp_auth import ZKPAuth, ZKPError
from .visual_pattern import VisualPattern, PatternError


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("zkp_auth_server")

# Initialize security scheme
security = HTTPBearer(auto_error=False)

# Create the FastAPI application
app = FastAPI(
    title="ZKP Visual Authentication API",
    description="A secure authentication API using Zero-Knowledge Proofs and visual pattern verification",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to your frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"]
)

# Global authentication service instance
# In a production environment, you would want to use a dependency injection pattern
# and potentially persist user data in a database
auth_service = ZKPAuth(
    challenge_ttl=300,  # 5 minutes
    key_bits=2048,
    use_visual_patterns=True,
    visual_pattern_config={
        "grid_size": 8,
        "challenge_ttl": 300,
        "color_depth": 8
    }
)


# Pydantic models for request/response validation

class RegisterRequest(BaseModel):
    """Request model for user registration."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    personalization: Optional[str] = None
    
    class Config:
        schema_extra = {
            "example": {
                "username": "testuser",
                "password": "securepassword123",
                "personalization": "optional-device-id"
            }
        }


class RegisterResponse(BaseModel):
    """Response model for user registration."""
    username: str
    public_key: str
    salt: str
    registered_at: int


class ChallengeRequest(BaseModel):
    """Request model for challenge creation."""
    username: str = Field(..., min_length=3, max_length=50)
    
    class Config:
        schema_extra = {
            "example": {
                "username": "testuser"
            }
        }


class VisualChallengeData(BaseModel):
    """Data for a visual challenge."""
    challenge_id: str
    image_data: str
    expires_at: int


class ChallengeResponse(BaseModel):
    """Response model for challenge creation."""
    challenge_id: str
    commitment: str  # Base64 encoded commitment
    challenge: str   # Base64 encoded challenge
    timestamp: int
    expires_at: int
    visual_challenge: Optional[VisualChallengeData] = None


class VerifyRequest(BaseModel):
    """Request model for authentication verification."""
    username: str = Field(..., min_length=3, max_length=50)
    challenge_id: str
    response: str   # Base64 encoded response
    visual_challenge_id: Optional[str] = None
    visual_response: Optional[List[List[int]]] = None
    
    class Config:
        schema_extra = {
            "example": {
                "username": "testuser",
                "challenge_id": "1234567890abcdef",
                "response": "BASE64_ENCODED_RESPONSE",
                "visual_challenge_id": "abcdef1234567890",
                "visual_response": [[0, 1, 2], [3, 4, 5], [6, 7, 8]]
            }
        }


class VerifyResponse(BaseModel):
    """Response model for authentication verification."""
    authenticated: bool
    username: str
    timestamp: int
    session_token: Optional[str] = None


class ErrorResponse(BaseModel):
    """Standard error response model."""
    detail: str
    code: str
    timestamp: int


# Custom exception handler
@app.exception_handler(ZKPError)
async def zkp_exception_handler(request: Request, exc: ZKPError):
    """Handle ZKP authentication errors."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "detail": str(exc),
            "code": "authentication_error",
            "timestamp": int(time.time())
        },
    )


@app.exception_handler(PatternError)
async def pattern_exception_handler(request: Request, exc: PatternError):
    """Handle visual pattern errors."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "detail": str(exc),
            "code": "pattern_error",
            "timestamp": int(time.time())
        },
    )


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Add request ID for tracing
    request_id = str(uuid.uuid4())
    response.headers["X-Request-ID"] = request_id
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    return response


@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint that redirects to documentation."""
    return {"message": "ZKP Visual Authentication API", "docs": "/docs"}


@app.post(
    "/register", 
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
    }
)
async def register_user(request: RegisterRequest):
    """
    Register a new user.
    
    This endpoint creates a new user with the provided username and password.
    The password is never stored, only used to derive cryptographic keys.
    """
    try:
        # Register the user
        registration = auth_service.register_user(
            request.username,
            request.password,
            request.personalization
        )
        
        # Convert public key to string for JSON response
        registration["public_key"] = str(registration["public_key"])
        
        return registration
        
    except ZKPError as e:
        # Re-raise the error to be handled by the exception handler
        raise
    except Exception as e:
        logger.error(f"Unexpected error during registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during registration"
        )


@app.post(
    "/challenge", 
    response_model=ChallengeResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
        404: {"model": ErrorResponse, "description": "User Not Found"},
    }
)
async def create_challenge(request: ChallengeRequest):
    """
    Create an authentication challenge.
    
    This endpoint creates a challenge for the specified user that must be solved
    to authenticate. It may also include a visual pattern challenge.
    """
    try:
        # Create a challenge
        challenge = auth_service.create_challenge(request.username)
        
        # Format values for JSON response
        challenge["commitment"] = str(challenge["commitment"])
        challenge["challenge"] = str(challenge["challenge"])
        
        return challenge
        
    except ZKPError as e:
        if "not registered" in str(e):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{request.username}' not found"
            )
        # Re-raise the error to be handled by the exception handler
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating challenge: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while creating the challenge"
        )


@app.post(
    "/verify", 
    response_model=VerifyResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
        401: {"model": ErrorResponse, "description": "Authentication Failed"},
    }
)
async def verify_authentication(request: VerifyRequest):
    """
    Verify an authentication response.
    
    This endpoint verifies the user's response to an authentication challenge.
    If successful, it returns a session token.
    """
    try:
        # Convert response from base64 string to integer
        try:
            response_int = int(request.response)
        except ValueError:
            raise ZKPError("Invalid response format")
        
        # Verify the response
        is_authenticated = auth_service.verify_response(
            request.username,
            request.challenge_id,
            response_int,
            request.visual_challenge_id,
            request.visual_response
        )
        
        if not is_authenticated:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed"
            )
        
        # Generate a session token (in a real app, use a proper JWT)
        timestamp = int(time.time())
        session_token = base64.b64encode(
            f"{request.username}:{timestamp}:{uuid.uuid4()}".encode()
        ).decode()
        
        return {
            "authenticated": True,
            "username": request.username,
            "timestamp": timestamp,
            "session_token": session_token
        }
        
    except ZKPError as e:
        # If it's an expired or unknown challenge, respond with 401
        if "expired" in str(e) or "Unknown" in str(e):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e)
            )
        # Re-raise the error to be handled by the exception handler
        raise
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Unexpected error during verification: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during authentication verification"
        )


# Customize OpenAPI docs
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
        
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer"
        }
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Run the server
if __name__ == "__main__":
    # In production, use an ASGI server like Gunicorn with Uvicorn workers
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    logger.info(f"Starting ZKP Authentication server on {host}:{port}")
    uvicorn.run(
        "src.server:app",
        host=host,
        port=port,
        reload=False,  # Set to True during development
        log_level="info",
    )

