#!/usr/bin/env python3
"""
Shared test fixtures and utilities for the ZKP Visual Authentication tests.

This module provides common fixtures and utilities that can be reused
across all test files, helping to maintain consistency and reduce duplication.
"""

import os
import time
import base64
from typing import Dict, Any, List, Optional
from unittest.mock import patch, MagicMock

import pytest
import numpy as np
from fastapi.testclient import TestClient
from Crypto.Random import get_random_bytes

from src.server import app
from src.zkp_auth import ZKPAuth, ZKPError, ZKPParameters, ZKPKeyPair
from src.visual_pattern import VisualPattern, PatternError


# Environment setup
@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up the test environment variables and configurations."""
    # Store original environment variables
    orig_env = {}
    for key in ["PORT", "HOST", "LOG_LEVEL"]:
        if key in os.environ:
            orig_env[key] = os.environ[key]
    
    # Set test environment variables
    os.environ["PORT"] = "8001"  # Use a different port for tests
    os.environ["HOST"] = "127.0.0.1"
    os.environ["LOG_LEVEL"] = "error"  # Reduce log noise during tests
    
    yield
    
    # Restore original environment variables
    for key in ["PORT", "HOST", "LOG_LEVEL"]:
        if key in orig_env:
            os.environ[key] = orig_env[key]
        elif key in os.environ:
            del os.environ[key]


# API test client
@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    with TestClient(app) as test_client:
        yield test_client


# Authentication objects
@pytest.fixture
def visual_pattern():
    """Create a VisualPattern instance for testing."""
    return VisualPattern(
        grid_size=8,
        challenge_ttl=30,
        color_depth=8
    )


@pytest.fixture
def auth_service():
    """Create a ZKPAuth instance for testing with smaller keys for speed."""
    return ZKPAuth(
        challenge_ttl=30,
        key_bits=1024,  # Smaller keys for faster tests
        use_visual_patterns=True,
        visual_pattern_config={
            "grid_size": 8,
            "challenge_ttl": 30,
            "color_depth": 8
        }
    )


@pytest.fixture
def auth_service_no_patterns():
    """Create a ZKPAuth instance without visual patterns."""
    return ZKPAuth(
        challenge_ttl=30,
        key_bits=1024,
        use_visual_patterns=False
    )


# Test data
@pytest.fixture
def random_username():
    """Generate a random username for testing."""
    return f"user_{int(time.time())}_{os.urandom(4).hex()}"


@pytest.fixture
def sample_password():
    """Provide a sample password for testing."""
    return "Secure_Password_123!"


@pytest.fixture
def sample_pattern(visual_pattern):
    """Generate a sample pattern for testing."""
    public_key = "test_user_123"
    timestamp = int(time.time())
    seed = os.urandom(16)
    pattern = visual_pattern.generate_pattern(public_key, timestamp, seed)
    return pattern, public_key, timestamp, seed


@pytest.fixture
def test_user_data(random_username, sample_password):
    """Generate test user data."""
    return {
        "username": random_username,
        "password": sample_password,
        "personalization": "test-device"
    }


@pytest.fixture
def registered_user(auth_service, test_user_data):
    """Register a test user and return the registration data."""
    registration = auth_service.register_user(
        test_user_data["username"],
        test_user_data["password"],
        test_user_data["personalization"]
    )
    
    # Return complete user info
    return {
        "username": test_user_data["username"],
        "password": test_user_data["password"],
        "personalization": test_user_data["personalization"],
        "registration": registration,
        "salt": base64.b64decode(registration["salt"])
    }


@pytest.fixture
def registered_user_with_challenge(auth_service, registered_user):
    """Register a user and create a challenge for them."""
    challenge = auth_service.create_challenge(registered_user["username"])
    
    return {
        **registered_user,
        "challenge": challenge
    }


# Mock utilities
@pytest.fixture
def mock_time():
    """Provide a patch for the time.time function."""
    with patch('time.time') as mock:
        mock.return_value = 1617211234  # Fixed timestamp for deterministic tests
        yield mock


@pytest.fixture
def mock_random():
    """Provide a patch for random functions to make tests deterministic."""
    with patch('os.urandom') as mock_urandom, \
         patch('secrets.token_hex') as mock_token_hex, \
         patch('uuid.uuid4') as mock_uuid4:
        
        # Use fixed values for deterministic tests
        mock_urandom.return_value = b'deterministic_random_bytes'
        mock_token_hex.return_value = 'deterministic_token'
        mock_uuid4.return_value = 'deterministic-uuid-value'
        
        yield (mock_urandom, mock_token_hex, mock_uuid4)


@pytest.fixture
def mock_verify_success():
    """Mock successful verification."""
    with patch('src.zkp_auth.ZKPAuth.verify_response') as mock:
        mock.return_value = True
        yield mock


@pytest.fixture
def mock_verify_failure():
    """Mock failed verification."""
    with patch('src.zkp_auth.ZKPAuth.verify_response') as mock:
        mock.return_value = False
        yield mock


# Cleanup utilities
@pytest.fixture(autouse=True)
def cleanup_auth_service(auth_service):
    """Reset the authentication service state between tests."""
    # Store original state
    orig_users = auth_service.registered_users.copy()
    orig_challenges = auth_service.active_challenges.copy()
    
    yield
    
    # Restore original state
    auth_service.registered_users = orig_users
    auth_service.active_challenges = orig_challenges


@pytest.fixture(autouse=True)
def cleanup_pattern_generator(visual_pattern):
    """Reset the pattern generator state between tests."""
    # Store original state
    orig_challenges = visual_pattern.active_challenges.copy()
    
    yield
    
    # Restore original state
    visual_pattern.active_challenges = orig_challenges


# Helper functions
def create_test_challenge(auth_service, username: str) -> Dict[str, Any]:
    """Create a test challenge for the specified user."""
    return auth_service.create_challenge(username)


def compute_test_response(auth_service, username: str, challenge_id: str, challenge: int, 
                          password: str, salt: bytes) -> int:
    """Compute a test response for the given challenge."""
    return auth_service.compute_auth_response(
        username, challenge_id, challenge, password, salt
    )

