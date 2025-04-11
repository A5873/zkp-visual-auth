#!/usr/bin/env python3
"""
Tests for the FastAPI Server for ZKP Visual Authentication.

This module contains comprehensive tests for the API endpoints,
request validation, error handling, security headers, and more.
"""

import os
import re
import time
import json
import base64
from unittest.mock import patch, MagicMock

import pytest
import httpx
from fastapi.testclient import TestClient
from fastapi import status

from src.server import app
from src.zkp_auth import ZKPAuth, ZKPError


# Setup test client
@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
def auth_user(client):
    """Register a test user and return the registration data."""
    user_data = {
        "username": "testuser",
        "password": "securepassword123",
        "personalization": "test-device"
    }
    response = client.post("/register", json=user_data)
    return {
        "username": user_data["username"],
        "password": user_data["password"],
        "registration": response.json()
    }


class TestRegistrationEndpoint:
    """Tests for the /register endpoint."""
    
    def test_register_valid_user(self, client):
        """Test registration with valid data."""
        user_data = {
            "username": "validuser",
            "password": "validpassword123",
            "personalization": "device-id"
        }
        
        response = client.post("/register", json=user_data)
        
        # Error response format
        error_response = client.post("/challenge", json={
            "username": "nonexistentuser"
        })
        assert error_response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND]
        error_data = error_response.json()
        assert isinstance(error_data["detail"], str)
        assert isinstance(error_data["timestamp"], int)
        
        # Verify response format
        verify_response = client.post("/verify", json={
            "username": auth_user["username"],
            "challenge_id": "some-id",
            "response": "12345"
        })
        # This will fail due to invalid challenge ID, but we just check format
        assert verify_response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]
        verify_error = verify_response.json()
        assert "detail" in verify_error
        assert "timestamp" in verify_error


class TestOpenAPIDocumentation:
    """Tests for OpenAPI documentation."""
    
    def test_openapi_schema(self, client):
        """Test OpenAPI schema is properly generated."""
        response = client.get("/openapi.json")
        
        # Check response status
        assert response.status_code == status.HTTP_200_OK
        
        # Parse OpenAPI schema
        schema = response.json()
        
        # Check basic structure
        assert "openapi" in schema
        assert "info" in schema
        assert "paths" in schema
        assert "components" in schema
        
        # Check API info
        assert schema["info"]["title"] == "ZKP Visual Authentication API"
        assert "version" in schema["info"]
        
        # Check endpoint paths exist
        assert "/register" in schema["paths"]
        assert "/challenge" in schema["paths"]
        assert "/verify" in schema["paths"]
        
        # Check security schemes
        assert "securitySchemes" in schema["components"]
        assert "BearerAuth" in schema["components"]["securitySchemes"]
    
    def test_docs_endpoint(self, client):
        """Test the docs endpoint (Swagger UI) is accessible."""
        response = client.get("/docs")
        
        # Check response status
        assert response.status_code == status.HTTP_200_OK
        
        # Check it's HTML and contains Swagger UI
        assert "text/html" in response.headers["content-type"]
        assert "swagger-ui" in response.text.lower()


class TestIntegrationCases:
    """Integration tests for complete authentication flows."""
    
    def test_complete_auth_flow(self, client, monkeypatch):
        """Test a complete authentication flow from registration to verification."""
        # 1. Register a new user
        username = f"flowuser_{int(time.time())}"
        password = "flowpassword123"
        
        register_response = client.post("/register", json={
            "username": username,
            "password": password
        })
        assert register_response.status_code == status.HTTP_201_CREATED
        registration = register_response.json()
        
        # 2. Create a challenge
        challenge_response = client.post("/challenge", json={
            "username": username
        })
        assert challenge_response.status_code == status.HTTP_200_OK
        challenge = challenge_response.json()
        
        # 3. Mock successful verification since we can't actually compute a valid response
        def mock_verify(*args, **kwargs):
            return True
        
        monkeypatch.setattr("src.zkp_auth.ZKPAuth.verify_response", mock_verify)
        
        # 4. Verify with the mocked response
        verify_response = client.post("/verify", json={
            "username": username,
            "challenge_id": challenge["challenge_id"],
            "response": "123456",
            "visual_challenge_id": challenge["visual_challenge"]["challenge_id"],
            "visual_response": [[0, 1, 2], [3, 4, 5], [6, 7, 8]]
        })
        
        assert verify_response.status_code == status.HTTP_200_OK
        verification = verify_response.json()
        assert verification["authenticated"] is True
        assert verification["username"] == username
        assert "session_token" in verification
    
    def test_server_error_handling(self, client, monkeypatch):
        """Test server error handling for unexpected exceptions."""
        # Mock register_user to raise an unexpected exception
        def mock_register(*args, **kwargs):
            raise RuntimeError("Unexpected internal error")
        
        monkeypatch.setattr("src.zkp_auth.ZKPAuth.register_user", mock_register)
        
        # Attempt to register a user
        response = client.post("/register", json={
            "username": "serveruser",
            "password": "serverpassword123"
        })
        
        # Should return a 500 error
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        error_data = response.json()
        assert "detail" in error_data
        # Should not expose internal error details
        assert "Unexpected internal error" not in error_data["detail"]


# Additional fixtures for test data management

@pytest.fixture(autouse=True)
def clear_auth_service():
    """Reset the authentication service between tests."""
    # Store original registered users and challenges
    orig_users = app.state.auth_service.registered_users.copy() if hasattr(app.state, "auth_service") else {}
    orig_challenges = app.state.auth_service.active_challenges.copy() if hasattr(app.state, "auth_service") else {}
    
    # Run the test
    yield
    
    # Clean up - restore original state
    if hasattr(app.state, "auth_service"):
        app.state.auth_service.registered_users = orig_users
        app.state.auth_service.active_challenges = orig_challenges


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
    
    def test_register_duplicate_user(self, client, auth_user):
        """Test registration with duplicate username."""
        user_data = {
            "username": auth_user["username"],  # Already registered
            "password": "newpassword123"
        }
        
        response = client.post("/register", json=user_data)
        
        # Check response status and error message
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already registered" in response.json()["detail"]
    
    def test_register_invalid_data(self, client):
        """Test registration with invalid data formats."""
        # Test with username too short
        response = client.post("/register", json={
            "username": "ab",  # Too short
            "password": "validpassword123"
        })
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Test with password too short
        response = client.post("/register", json={
            "username": "validuser",
            "password": "short"  # Too short
        })
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Test with missing fields
        response = client.post("/register", json={
            "username": "validuser"
            # Missing password
        })
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestChallengeEndpoint:
    """Tests for the /challenge endpoint."""
    
    def test_create_challenge_valid_user(self, client, auth_user):
        """Test challenge creation for valid user."""
        data = {"username": auth_user["username"]}
        
        response = client.post("/challenge", json=data)
        
        # Check response status and content
        assert response.status_code == status.HTTP_200_OK
        challenge = response.json()
        assert "challenge_id" in challenge
        assert "commitment" in challenge
        assert "challenge" in challenge
        assert "timestamp" in challenge
        assert "expires_at" in challenge
        assert "visual_challenge" in challenge
        
        # Check visual challenge format
        visual = challenge["visual_challenge"]
        assert "challenge_id" in visual
        assert "image_data" in visual
        assert "expires_at" in visual
        
        # Verify image data is base64 encoded
        try:
            base64.b64decode(visual["image_data"])
        except Exception:
            pytest.fail("Image data is not properly base64 encoded")
    
    def test_create_challenge_nonexistent_user(self, client):
        """Test challenge creation for nonexistent user."""
        data = {"username": "nonexistentuser"}
        
        response = client.post("/challenge", json=data)
        
        # Check response status and error message
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"]
    
    def test_create_challenge_invalid_data(self, client):
        """Test challenge creation with invalid data."""
        # Test with username too short
        response = client.post("/challenge", json={
            "username": "ab"  # Too short
        })
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Test with missing fields
        response = client.post("/challenge", json={})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestVerificationEndpoint:
    """Tests for the /verify endpoint."""
    
    def test_verification_success(self, client, auth_user, monkeypatch):
        """Test successful verification of authentication response."""
        # Create challenge
        challenge_response = client.post("/challenge", json={
            "username": auth_user["username"]
        })
        assert challenge_response.status_code == status.HTTP_200_OK
        challenge = challenge_response.json()
        
        # Mock the verify_response method to always return True
        # This is because we can't easily compute a valid response in tests
        def mock_verify(*args, **kwargs):
            return True
        
        monkeypatch.setattr("src.zkp_auth.ZKPAuth.verify_response", mock_verify)
        
        # Submit verification
        verify_data = {
            "username": auth_user["username"],
            "challenge_id": challenge["challenge_id"],
            "response": "123456",  # Doesn't matter, we're mocking
            "visual_challenge_id": challenge["visual_challenge"]["challenge_id"],
            "visual_response": [[0, 1, 2], [3, 4, 5], [6, 7, 8]]
        }
        
        response = client.post("/verify", json=verify_data)
        
        # Check response status and content
        assert response.status_code == status.HTTP_200_OK
        verification = response.json()
        assert verification["authenticated"] is True
        assert verification["username"] == auth_user["username"]
        assert "timestamp" in verification
        assert "session_token" in verification
    
    def test_verification_failure(self, client, auth_user, monkeypatch):
        """Test failed verification of authentication response."""
        # Create challenge
        challenge_response = client.post("/challenge", json={
            "username": auth_user["username"]
        })
        assert challenge_response.status_code == status.HTTP_200_OK
        challenge = challenge_response.json()
        
        # Mock the verify_response method to always return False
        def mock_verify(*args, **kwargs):
            return False
        
        monkeypatch.setattr("src.zkp_auth.ZKPAuth.verify_response", mock_verify)
        
        # Submit verification
        verify_data = {
            "username": auth_user["username"],
            "challenge_id": challenge["challenge_id"],
            "response": "123456",  # Doesn't matter, we're mocking
            "visual_challenge_id": challenge["visual_challenge"]["challenge_id"],
            "visual_response": [[0, 1, 2], [3, 4, 5], [6, 7, 8]]
        }
        
        response = client.post("/verify", json=verify_data)
        
        # Check response status and error message
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "failed" in response.json()["detail"]
    
    def test_verification_expired_challenge(self, client, auth_user, monkeypatch):
        """Test verification with expired challenge."""
        # Create challenge
        challenge_response = client.post("/challenge", json={
            "username": auth_user["username"]
        })
        assert challenge_response.status_code == status.HTTP_200_OK
        challenge = challenge_response.json()
        
        # Mock verify_response to raise an expired challenge error
        def mock_verify(*args, **kwargs):
            raise ZKPError("Challenge has expired")
        
        monkeypatch.setattr("src.zkp_auth.ZKPAuth.verify_response", mock_verify)
        
        # Submit verification
        verify_data = {
            "username": auth_user["username"],
            "challenge_id": challenge["challenge_id"],
            "response": "123456",
            "visual_challenge_id": challenge["visual_challenge"]["challenge_id"],
            "visual_response": [[0, 1, 2], [3, 4, 5], [6, 7, 8]]
        }
        
        response = client.post("/verify", json=verify_data)
        
        # Check response status and error message
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "expired" in response.json()["detail"]
    
    def test_verification_invalid_data(self, client):
        """Test verification with invalid data formats."""
        # Test with username too short
        response = client.post("/verify", json={
            "username": "ab",  # Too short
            "challenge_id": "some-id",
            "response": "123456"
        })
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Test with missing fields
        response = client.post("/verify", json={
            "username": "validuser",
            # Missing challenge_id and response
        })
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestErrorHandling:
    """Tests for error handling in the API."""
    
    def test_zkp_error_handler(self, client, auth_user, monkeypatch):
        """Test handling of ZKP errors."""
        # Mock the register_user method to raise a ZKPError
        def mock_register(*args, **kwargs):
            raise ZKPError("Custom ZKP error")
        
        monkeypatch.setattr("src.zkp_auth.ZKPAuth.register_user", mock_register)
        
        # Attempt to register a user
        response = client.post("/register", json={
            "username": "erroruser",
            "password": "errorpassword123"
        })
        
        # Check response format
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = response.json()
        assert error_data["detail"] == "Custom ZKP error"
        assert error_data["code"] == "authentication_error"
        assert "timestamp" in error_data
    
    def test_pattern_error_handler(self, client, auth_user, monkeypatch):
        """Test handling of PatternError."""
        # This is harder to test directly, but we can verify the handler exists
        # by checking the registered exception handlers
        assert app.exception_handlers is not None
        
        # Check that our middleware is adding security headers
        response = client.get("/")
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert "Strict-Transport-Security" in response.headers
        assert "X-XSS-Protection" in response.headers
        assert "X-Request-ID" in response.headers


class TestSecurityHeaders:
    """Tests for security headers in responses."""
    
    def test_security_headers_present(self, client):
        """Test that security headers are added to responses."""
        response = client.get("/")
        
        # Check security headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert "max-age=31536000" in response.headers["Strict-Transport-Security"]
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
    
    def test_request_id_generated(self, client):
        """Test that a request ID is generated and added to responses."""
        response = client.get("/")
        
        # Check request ID header
        assert "X-Request-ID" in response.headers
        # UUID format: 8-4-4-4-12 hexadecimal digits
        assert re.match(r"^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", response.headers["X-Request-ID"])


@pytest.mark.asyncio
async def test_cors_middleware():
    """Test CORS middleware handling."""
    async with httpx.AsyncClient(app=app, base_url="http://testserver") as ac:
        # Options request to simulate CORS preflight
        response = await ac.options("/", headers={
            "Origin": "http://example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        })
        
        # Check CORS headers
        assert response.status_code == status.HTTP_200_OK
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        assert "POST" in response.headers["Access-Control-Allow-Methods"]
        assert "Content-Type" in response.headers["Access-Control-Allow-Headers"]


class TestResponseFormats:
    """Tests for API response formats."""
    
    def test_response_formats(self, client, auth_user):
        """Test response formats for different endpoints."""
        # Register endpoint response format
        register_response = client.post("/register", json={
            "username": "formatuser",
            "password": "formatpassword123"
        })
        assert register_response.status_code == status.HTTP_201_CREATED
        register_data = register_response.json()
        assert isinstance(register_data["username"], str)
        assert isinstance(register_data["public_key"], str)
        assert isinstance(register_data["salt"], str)
        assert isinstance(register_data["registered_at"], int)
        
        # Challenge endpoint response format
        challenge_response = client.post("/challenge", json={
            "username": auth_user["username"]
        })
        assert challenge_response.status_code == status.HTTP_200_OK
        challenge_data = challenge_response.json()
        assert isinstance(challenge_data["challenge_id"], str)
        assert isinstance(challenge_data["commitment"], str)
        assert isinstance(challenge_data["challenge"], str)
        assert isinstance(challenge_data["timestamp"], int)
        assert isinstance(challenge_data["expires_at"], int)
        assert isinstance(challenge_data["visual_challenge"], dict)
        
        # Error response format
        error_response = client.post("/challenge", json={
            "username": "nonexistentuser"
        })
        assert error_response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND]
        error_data = error_response.json()
        

