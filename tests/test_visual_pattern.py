#!/usr/bin/env python3
"""
Tests for the Visual Pattern Authentication Module.

This module contains comprehensive tests for the VisualPattern class,
covering normal operation, error handling, edge cases, and security aspects.
"""

import os
import time
import uuid
import base64
from io import BytesIO
import unittest
from unittest.mock import patch, MagicMock

import pytest
import numpy as np
from PIL import Image

from src.visual_pattern import VisualPattern, PatternError


class TestVisualPattern:
    """Test suite for the VisualPattern class."""
    
    @pytest.fixture
    def pattern_gen(self):
        """Create a VisualPattern instance for testing."""
        return VisualPattern(
            grid_size=8,
            challenge_ttl=30,
            color_depth=8
        )
    
    @pytest.fixture
    def sample_pattern(self, pattern_gen):
        """Generate a sample pattern for testing."""
        public_key = "test_user_123"
        timestamp = int(time.time())
        seed = os.urandom(16)
        pattern = pattern_gen.generate_pattern(public_key, timestamp, seed)
        return pattern, public_key, timestamp, seed
    
    def test_init_with_valid_params(self):
        """Test initialization with valid parameters."""
        pattern_gen = VisualPattern(grid_size=10, challenge_ttl=60, color_depth=16)
        assert pattern_gen.grid_size == 10
        assert pattern_gen.challenge_ttl == 60
        assert pattern_gen.color_depth == 16
        assert len(pattern_gen.color_palette) == 16 + 2  # +2 for black and white
    
    def test_init_with_invalid_params(self):
        """Test initialization with invalid parameters."""
        # Test with invalid grid size
        with pytest.raises(PatternError, match="Grid size must be at least 4"):
            VisualPattern(grid_size=3)
        
        # Test with invalid challenge TTL
        with pytest.raises(PatternError, match="Challenge TTL must be at least 5 seconds"):
            VisualPattern(challenge_ttl=3)
        
        # Test with invalid color depth
        with pytest.raises(PatternError, match="Color depth must be between 2 and 64"):
            VisualPattern(color_depth=65)
    
    def test_generate_pattern(self, pattern_gen):
        """Test pattern generation produces expected output."""
        public_key = "test_user_456"
        pattern = pattern_gen.generate_pattern(public_key)
        
        # Check pattern dimensions and type
        assert isinstance(pattern, np.ndarray)
        assert pattern.shape == (pattern_gen.grid_size, pattern_gen.grid_size)
        assert pattern.dtype == np.uint8
        
        # Check pattern values are within expected range
        assert np.all(pattern >= 0)
        assert np.all(pattern < pattern_gen.color_depth)
    
    def test_generate_pattern_deterministic(self, pattern_gen):
        """Test that pattern generation is deterministic with same inputs."""
        public_key = "test_user_789"
        timestamp = 1617211234
        seed = b'deterministic_seed'
        
        # Generate two patterns with same inputs
        pattern1 = pattern_gen.generate_pattern(public_key, timestamp, seed)
        pattern2 = pattern_gen.generate_pattern(public_key, timestamp, seed)
        
        # Patterns should be identical
        assert np.array_equal(pattern1, pattern2)
        
        # Change one input and pattern should be different
        pattern3 = pattern_gen.generate_pattern(public_key, timestamp + 1, seed)
        assert not np.array_equal(pattern1, pattern3)
    
    def test_generate_pattern_with_invalid_input(self, pattern_gen):
        """Test pattern generation with invalid inputs."""
        # Test with too short public key
        with pytest.raises(PatternError, match="Public key must be at least 8 characters"):
            pattern_gen.generate_pattern("short")
        
        # Test with empty public key
        with pytest.raises(PatternError, match="Public key must be at least 8 characters"):
            pattern_gen.generate_pattern("")
    
    def test_pattern_to_image(self, pattern_gen, sample_pattern):
        """Test conversion of pattern to image."""
        pattern, _, _, _ = sample_pattern
        
        # Convert pattern to image
        img = pattern_gen.pattern_to_image(pattern)
        
        # Check image properties
        assert isinstance(img, Image.Image)
        assert img.mode == "RGB"
        assert img.size == (400, 400)  # Default size
        
        # Test with custom size
        img_custom = pattern_gen.pattern_to_image(pattern, size=200)
        assert img_custom.size == (200, 200)
    
    def test_pattern_to_image_with_invalid_input(self, pattern_gen):
        """Test pattern to image conversion with invalid inputs."""
        # Test with non-numpy array
        with pytest.raises(PatternError, match="Pattern must be a numpy array"):
            pattern_gen.pattern_to_image([[1, 2], [3, 4]])
        
        # Test with wrong shape
        wrong_shape = np.ones((10, 10), dtype=np.uint8)
        with pytest.raises(PatternError, match="Pattern must be 8x8"):
            pattern_gen.pattern_to_image(wrong_shape)
    
    def test_get_challenge(self, pattern_gen):
        """Test challenge generation."""
        public_key = "test_user_challenge"
        challenge = pattern_gen.get_challenge(public_key)
        
        # Check challenge structure
        assert "challenge_id" in challenge
        assert "image_data" in challenge
        assert "timestamp" in challenge
        assert "expires_at" in challenge
        
        # Verify timestamp and expiration
        assert challenge["expires_at"] == challenge["timestamp"] + pattern_gen.challenge_ttl
        
        # Verify image data is base64 encoded
        try:
            image_bytes = base64.b64decode(challenge["image_data"])
            img = Image.open(BytesIO(image_bytes))
            assert img.mode == "RGB"
        except Exception:
            pytest.fail("Image data is not properly base64 encoded")
        
        # Check that challenge is stored
        assert challenge["challenge_id"] in pattern_gen.active_challenges
    
    def test_verify_pattern_success(self, pattern_gen):
        """Test successful pattern verification."""
        public_key = "test_user_verify"
        challenge = pattern_gen.get_challenge(public_key)
        
        # Get the original pattern from stored challenge
        original_pattern = pattern_gen.active_challenges[challenge["challenge_id"]]["pattern"]
        
        # Verify with the correct pattern
        result = pattern_gen.verify_pattern(challenge["challenge_id"], original_pattern)
        assert result is True
        
        # Challenge should be removed after verification
        assert challenge["challenge_id"] not in pattern_gen.active_challenges
    
    def test_verify_pattern_failure(self, pattern_gen):
        """Test failed pattern verification."""
        public_key = "test_user_verify_fail"
        challenge = pattern_gen.get_challenge(public_key)
        
        # Create a wrong pattern response
        wrong_pattern = np.zeros((pattern_gen.grid_size, pattern_gen.grid_size), dtype=np.uint8)
        
        # Verify with the wrong pattern
        result = pattern_gen.verify_pattern(challenge["challenge_id"], wrong_pattern.tolist())
        assert result is False
        
        # Challenge should be removed even after failed verification
        assert challenge["challenge_id"] not in pattern_gen.active_challenges
    
    def test_verify_pattern_unknown_challenge(self, pattern_gen):
        """Test verification with unknown challenge ID."""
        unknown_id = str(uuid.uuid4())
        pattern = np.zeros((pattern_gen.grid_size, pattern_gen.grid_size), dtype=np.uint8)
        
        with pytest.raises(PatternError, match="Unknown or expired challenge"):
            pattern_gen.verify_pattern(unknown_id, pattern.tolist())
    
    def test_verify_pattern_expired_challenge(self, pattern_gen):
        """Test verification with expired challenge."""
        public_key = "test_user_expired"
        challenge = pattern_gen.get_challenge(public_key)
        
        # Manually expire the challenge
        pattern_gen.active_challenges[challenge["challenge_id"]]["expires_at"] = int(time.time()) - 10
        
        # Get the original pattern
        original_pattern = pattern_gen.active_challenges[challenge["challenge_id"]]["pattern"]
        
        with pytest.raises(PatternError, match="Challenge has expired"):
            pattern_gen.verify_pattern(challenge["challenge_id"], original_pattern)
    
    def test_cleanup_expired_challenges(self, pattern_gen):
        """Test cleanup of expired challenges."""
        # Create some challenges
        for i in range(5):
            public_key = f"test_user_cleanup_{i}"
            pattern_gen.get_challenge(public_key)
        
        # Get all challenge IDs
        challenge_ids = list(pattern_gen.active_challenges.keys())
        
        # Manually expire half of them
        for i, cid in enumerate(challenge_ids):
            if i % 2 == 0:
                pattern_gen.active_challenges[cid]["expires_at"] = int(time.time()) - 10
        
        # Run cleanup
        pattern_gen.active_challenges  # count before
        pattern_gen._cleanup_expired_challenges()
        
        # Check that expired challenges are removed
        for i, cid in enumerate(challenge_ids):
            if i % 2 == 0:
                assert cid not in pattern_gen.active_challenges
            else:
                assert cid in pattern_gen.active_challenges
    
    @patch('time.time')
    def test_challenge_ttl(self, mock_time, pattern_gen):
        """Test that challenges respect their TTL."""
        mock_time.return_value = 1617211234
        
        public_key = "test_user_ttl"
        challenge = pattern_gen.get_challenge(public_key)
        assert challenge["expires_at"] == 1617211234 + pattern_gen.challenge_ttl
        
        # Advance time to just before expiration
        mock_time.return_value = 1617211234 + pattern_gen.challenge_ttl - 1
        
        # Verify should still work
        original_pattern = pattern_gen.active_challenges[challenge["challenge_id"]]["pattern"]
        assert pattern_gen.verify_pattern(challenge["challenge_id"], original_pattern)
        
        # New challenge
        challenge = pattern_gen.get_challenge(public_key)
        
        # Advance time past expiration
        mock_time.return_value = 1617211234 + pattern_gen.challenge_ttl + 1
        
        # Verify should fail with expired error
        original_pattern = pattern_gen.active_challenges[challenge["challenge_id"]]["pattern"]
        with pytest.raises(PatternError, match="Challenge has expired"):
            pattern_gen.verify_pattern(challenge["challenge_id"], original_pattern)
    
    def test_multiple_challenges(self, pattern_gen):
        """Test handling multiple challenges simultaneously."""
        challenges = []
        
        # Create multiple challenges
        for i in range(5):
            public_key = f"test_user_multi_{i}"
            challenge = pattern_gen.get_challenge(public_key)
            challenges.append(challenge)
        
        # Verify they're all stored
        for challenge in challenges:
            assert challenge["challenge_id"] in pattern_gen.active_challenges
        
        # Verify one challenge
        challenge = challenges[2]
        original_pattern = pattern_gen.active_challenges[challenge["challenge_id"]]["pattern"]
        assert pattern_gen.verify_pattern(challenge["challenge_id"], original_pattern)
        
        # That challenge should be removed, others should remain
        assert challenge["challenge_id"] not in pattern_gen.active_challenges
        for i, c in enumerate(challenges):
            if i != 2:
                assert c["challenge_id"] in pattern_gen.active_challenges


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])

