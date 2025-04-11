#!/usr/bin/env python3
"""
Tests for the Zero-Knowledge Proof Authentication Module.

This module contains comprehensive tests for the ZKPAuth class,
covering cryptographic operations, challenge-response verification,
integration with visual patterns, and security aspects.
"""

import os
import time
import base64
from unittest.mock import patch, MagicMock

import pytest
from Crypto.Random import get_random_bytes

from src.zkp_auth import ZKPAuth, ZKPError, ZKPParameters, ZKPKeyPair, ZKPChallenge
from src.visual_pattern import VisualPattern, PatternError


class TestZKPAuth:
    """Test suite for the ZKPAuth class."""
    
    @pytest.fixture
    def auth_service(self):
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
    def auth_service_no_patterns(self):
        """Create a ZKPAuth instance without visual patterns."""
        return ZKPAuth(
            challenge_ttl=30,
            key_bits=1024,
            use_visual_patterns=False
        )
    
    @pytest.fixture
    def test_visual_pattern_verification_failure(self, auth_service, test_user):
        """Test failed visual pattern verification."""
        username = test_user["username"]
        password = test_user["password"]
        salt = base64.b64decode(test_user["registration"]["salt"])
        
        # Create challenge
        challenge = auth_service.create_challenge(username)
        challenge_id = challenge["challenge_id"]
        challenge_value = challenge["challenge"]
        visual_challenge_id = challenge["visual_challenge"]["challenge_id"]
        
        # Compute correct ZKP response
        zkp_response = auth_service.compute_auth_response(
            username,
            challenge_id,
            challenge_value,
            password,
            salt
        )
        
        # Create an incorrect visual pattern response
        wrong_pattern = [[0 for _ in range(8)] for _ in range(8)]
        
        # Verify should fail because visual pattern is wrong
        is_verified = auth_service.verify_response(
            username,
            challenge_id,
            zkp_response,
            visual_challenge_id,
            wrong_pattern
        )
        
        assert is_verified is False
        
        # Challenges should be removed after verification
        assert challenge_id not in auth_service.active_challenges
    
    def test_concurrent_authentication_attempts(self, auth_service, test_user):
        """Test handling of concurrent authentication attempts."""
        username = test_user["username"]
        password = test_user["password"]
        salt = base64.b64decode(test_user["registration"]["salt"])
        
        # Create multiple challenges for the same user
        challenges = []
        for _ in range(3):
            challenge = auth_service.create_challenge(username)
            challenges.append(challenge)
        
        # Verify each challenge ID is unique
        challenge_ids = [c["challenge_id"] for c in challenges]
        assert len(challenge_ids) == len(set(challenge_ids))
        
        # Verify each challenge has a unique visual challenge
        visual_challenge_ids = [c["visual_challenge"]["challenge_id"] for c in challenges]
        assert len(visual_challenge_ids) == len(set(visual_challenge_ids))
        
        # Authenticate with the second challenge
        challenge = challenges[1]
        challenge_id = challenge["challenge_id"]
        challenge_value = challenge["challenge"]
        
        response = auth_service.compute_auth_response(
            username,
            challenge_id,
            challenge_value,
            password,
            salt
        )
        
        is_verified = auth_service.verify_response(
            username,
            challenge_id,
            response
        )
        
        assert is_verified is True
        
        # That challenge should be removed
        assert challenge_id not in auth_service.active_challenges
        
        # Other challenges should still be active
        assert challenges[0]["challenge_id"] in auth_service.active_challenges
        assert challenges[2]["challenge_id"] in auth_service.active_challenges
    
    def test_challenge_reuse_prevention(self, auth_service, test_user):
        """Test prevention of challenge reuse."""
        username = test_user["username"]
        password = test_user["password"]
        salt = base64.b64decode(test_user["registration"]["salt"])
        
        # Create challenge
        challenge = auth_service.create_challenge(username)
        challenge_id = challenge["challenge_id"]
        challenge_value = challenge["challenge"]
        
        # Compute response
        response = auth_service.compute_auth_response(
            username,
            challenge_id,
            challenge_value,
            password,
            salt
        )
        
        # First verification should succeed
        is_verified = auth_service.verify_response(
            username,
            challenge_id,
            response
        )
        
        assert is_verified is True
        
        # Second verification with same challenge should fail
        with pytest.raises(ZKPError, match="Unknown or expired challenge"):
            auth_service.verify_response(
                username,
                challenge_id,
                response
            )
    
    def test_parameter_export(self, auth_service):
        """Test export of cryptographic parameters."""
        params = auth_service.export_parameters()
        
        # Check structure
        assert "p" in params
        assert "q" in params
        assert "g" in params
        
        # Check values match internal parameters
        assert params["p"] == auth_service.params.p
        assert params["q"] == auth_service.params.q
        assert params["g"] == auth_service.params.g
    
    def test_compute_auth_response_edge_cases(self, auth_service, test_user):
        """Test edge cases for compute_auth_response method."""
        username = test_user["username"]
        password = test_user["password"]
        salt = base64.b64decode(test_user["registration"]["salt"])
        
        # Create challenge
        challenge = auth_service.create_challenge(username)
        challenge_id = challenge["challenge_id"]
        challenge_value = challenge["challenge"]
        
        # Test with invalid challenge value
        with pytest.raises(ZKPError):
            auth_service.compute_auth_response(
                username,
                challenge_id,
                0,  # Invalid challenge value
                password,
                salt
            )
        
        # Test with empty password
        with pytest.raises(ZKPError):
            auth_service.compute_auth_response(
                username,
                challenge_id,
                challenge_value,
                "",  # Empty password
                salt
            )
        
        # Test with wrong salt length
        with pytest.raises(ZKPError):
            auth_service.compute_auth_response(
                username,
                challenge_id,
                challenge_value,
                password,
                b"short"  # Too short salt
            )
    
    def test_verify_missing_visual_challenge(self, auth_service, test_user):
        """Test verification when visual challenge is required but not provided."""
        username = test_user["username"]
        password = test_user["password"]
        salt = base64.b64decode(test_user["registration"]["salt"])
        
        # Create challenge with visual pattern
        challenge = auth_service.create_challenge(username)
        challenge_id = challenge["challenge_id"]
        challenge_value = challenge["challenge"]
        
        # Compute ZKP response
        zkp_response = auth_service.compute_auth_response(
            username,
            challenge_id,
            challenge_value,
            password,
            salt
        )
        
        # Verify without providing visual challenge info
        # This should fail as we're using a service with visual patterns enabled
        is_verified = auth_service.verify_response(
            username,
            challenge_id,
            zkp_response
            # Missing visual_challenge_id and visual_response
        )
        
        assert is_verified is False
        
        # Challenge should be removed after verification
        assert challenge_id not in auth_service.active_challenges


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
            ZKPAuth(challenge_ttl=10)
        
        # Test with invalid key bits
        with pytest.raises(ZKPError, match="Key size must be at least 1024 bits"):
            ZKPAuth(key_bits=512)
    
    def test_parameter_generation(self, auth_service):
        """Test cryptographic parameter generation."""
        params = auth_service.params
        
        # Check parameter types
        assert isinstance(params.p, int)
        assert isinstance(params.q, int)
        assert isinstance(params.g, int)
        
        # Check mathematical properties
        assert (params.p - 1) % params.q == 0  # p = 2q + 1 for safe prime
        assert pow(params.g, params.q, params.p) == 1  # g^q ≡ 1 (mod p)
        assert params.g != 1  # g is not 1
    
    def test_key_derivation(self, auth_service):
        """Test key derivation from password."""
        password = "secure_password_123"
        
        # Test with auto-generated salt
        derived_key1, salt1 = auth_service.derive_key(password)
        assert 1 < derived_key1 < auth_service.params.q
        assert len(salt1) == 32  # Default salt length
        
        # Test with provided salt
        salt2 = get_random_bytes(32)
        derived_key2, salt2_returned = auth_service.derive_key(password, salt2)
        assert salt2 == salt2_returned
        
        # Test same password + salt produces same key
        derived_key3, _ = auth_service.derive_key(password, salt1)
        assert derived_key1 == derived_key3
        
        # Test different password produces different key
        derived_key4, _ = auth_service.derive_key("different_password", salt1)
        assert derived_key1 != derived_key4
        
        # Test with personalization
        derived_key5, _ = auth_service.derive_key(password, salt1, "device1")
        assert derived_key1 != derived_key5
    
    def test_keypair_generation(self, auth_service):
        """Test keypair generation."""
        # Test with password
        password = "another_secure_password"
        keypair1, salt = auth_service.generate_keypair(password)
        
        assert isinstance(keypair1, ZKPKeyPair)
        assert 1 < keypair1.private_key < auth_service.params.q
        assert isinstance(keypair1.public_key, int)
        
        # Test public key is correctly computed: y = g^x mod p
        expected_public_key = pow(auth_service.params.g, keypair1.private_key, auth_service.params.p)
        assert keypair1.public_key == expected_public_key
        
        # Test with explicit private key
        private_key = 12345  # Simple private key for testing
        keypair2, _ = auth_service.generate_keypair(private_key=private_key)
        assert keypair2.private_key == private_key
        
        # Test with neither password nor private key
        with pytest.raises(ZKPError, match="Either password or private_key must be provided"):
            auth_service.generate_keypair()
        
        # Test with invalid private key
        with pytest.raises(ZKPError, match="Private key must be in range"):
            auth_service.generate_keypair(private_key=0)
    
    def test_user_registration(self, auth_service):
        """Test user registration."""
        username = "alice"
        password = "alice_secure_password"
        
        # Register user
        registration = auth_service.register_user(username, password)
        
        # Check registration data
        assert registration["username"] == username
        assert isinstance(registration["public_key"], int)
        assert "salt" in registration
        assert "registered_at" in registration
        
        # Check user is stored
        assert username in auth_service.registered_users
        assert auth_service.registered_users[username] == registration["public_key"]
        
        # Test registering duplicate username
        with pytest.raises(ZKPError, match="Username 'alice' already registered"):
            auth_service.register_user(username, "different_password")
    
    def test_challenge_creation(self, auth_service, test_user):
        """Test authentication challenge creation."""
        username = test_user["username"]
        
        # Create challenge
        challenge = auth_service.create_challenge(username)
        
        # Check challenge data
        assert "challenge_id" in challenge
        assert "commitment" in challenge
        assert "challenge" in challenge
        assert "timestamp" in challenge
        assert "expires_at" in challenge
        assert challenge["expires_at"] == challenge["timestamp"] + auth_service.challenge_ttl
        
        # Check visual challenge is included
        assert "visual_challenge" in challenge
        assert "challenge_id" in challenge["visual_challenge"]
        assert "image_data" in challenge["visual_challenge"]
        
        # Check challenge is stored
        challenge_id = challenge["challenge_id"]
        assert challenge_id in auth_service.active_challenges
        
        # Test challenge for non-existent user
        with pytest.raises(ZKPError, match="User 'nonexistent' not registered"):
            auth_service.create_challenge("nonexistent")
    
    def test_challenge_creation_without_visual(self, auth_service_no_patterns, test_user):
        """Test challenge creation without visual patterns."""
        # Create a user in this service instance
        username = "bob"
        password = "bob_secure_password"
        auth_service_no_patterns.register_user(username, password)
        
        # Create challenge
        challenge = auth_service_no_patterns.create_challenge(username)
        
        # Check challenge data
        assert "challenge_id" in challenge
        assert "visual_challenge" not in challenge
    
    def test_response_verification_success(self, auth_service, test_user):
        """Test successful response verification."""
        username = test_user["username"]
        password = test_user["password"]
        salt = base64.b64decode(test_user["registration"]["salt"])
        
        # Create challenge
        challenge = auth_service.create_challenge(username)
        challenge_id = challenge["challenge_id"]
        challenge_value = challenge["challenge"]
        
        # Compute response (normally done by client)
        response = auth_service.compute_auth_response(
            username,
            challenge_id,
            challenge_value,
            password,
            salt
        )
        
        # No visual challenge for this test
        is_verified = auth_service.verify_response(
            username,
            challenge_id,
            response
        )
        
        assert is_verified is True
        
        # Challenge should be removed after verification
        assert challenge_id not in auth_service.active_challenges
    
    def test_response_verification_failure(self, auth_service, test_user):
        """Test failed response verification."""
        username = test_user["username"]
        salt = base64.b64decode(test_user["registration"]["salt"])
        
        # Create challenge
        challenge = auth_service.create_challenge(username)
        challenge_id = challenge["challenge_id"]
        challenge_value = challenge["challenge"]
        
        # Compute response with wrong password
        response = auth_service.compute_auth_response(
            username,
            challenge_id,
            challenge_value,
            "wrong_password",
            salt
        )
        
        # Verify should fail
        is_verified = auth_service.verify_response(
            username,
            challenge_id,
            response
        )
        
        assert is_verified is False
        
        # Challenge should be removed even after failed verification
        assert challenge_id not in auth_service.active_challenges
    
    def test_verify_unknown_challenge(self, auth_service, test_user):
        """Test verification with unknown challenge ID."""
        username = test_user["username"]
        
        with pytest.raises(ZKPError, match="Unknown or expired challenge"):
            auth_service.verify_response(
                username,
                "nonexistent_challenge_id",
                12345
            )
    
    def test_verify_nonexistent_user(self, auth_service):
        """Test verification with nonexistent user."""
        with pytest.raises(ZKPError, match="User 'nonexistent' not registered"):
            auth_service.verify_response(
                "nonexistent",
                "some_challenge_id",
                12345
            )
    
    @patch('time.time')
    def test_verify_expired_challenge(self, mock_time, auth_service, test_user):
        """Test verification with expired challenge."""
        mock_time.return_value = 1617211234
        
        username = test_user["username"]
        password = test_user["password"]
        salt = base64.b64decode(test_user["registration"]["salt"])
        
        # Create challenge
        challenge = auth_service.create_challenge(username)
        challenge_id = challenge["challenge_id"]
        challenge_value = challenge["challenge"]
        
        # Compute response
        response = auth_service.compute_auth_response(
            username,
            challenge_id,
            challenge_value,
            password,
            salt
        )
        
        # Advance time past expiration
        mock_time.return_value = 1617211234 + auth_service.challenge_ttl + 1
        
        # Verify should fail with expired error
        with pytest.raises(ZKPError, match="Challenge has expired"):
            auth_service.verify_response(
                username,
                challenge_id,
                response
            )
        
        # Challenge should be removed
        assert challenge_id not in auth_service.active_challenges
    
    def test_cleanup_expired_challenges(self, auth_service, test_user):
        """Test cleanup of expired challenges."""
        username = test_user["username"]
        
        # Create challenges
        challenges = []
        for i in range(5):
            challenge = auth_service.create_challenge(username)
            challenges.append(challenge)
        
        # Manually expire half of them
        current_time = int(time.time())
        for i, challenge in enumerate(challenges):
            if i % 2 == 0:
                cid = challenge["challenge_id"]
                auth_service.active_challenges[cid].expires_at = current_time - 10
        
        # Run cleanup
        auth_service._cleanup_expired_challenges()
        
        # Check expired challenges are removed
        for i, challenge in enumerate(challenges):
            cid = challenge["challenge_id"]
            if i % 2 == 0:
                assert cid not in auth_service.active_challenges
            else:
                assert cid in auth_service.active_challenges
    
    def test_integration_with_visual_patterns(self, auth_service, test_user):
        """Test integration with visual pattern verification."""
        username = test_user["username"]
        password = test_user["password"]
        salt = base64.b64decode(test_user["registration"]["salt"])
        
        # Create challenge with visual pattern
        challenge = auth_service.create_challenge(username)
        challenge_id = challenge["challenge_id"]
        challenge_value = challenge["challenge"]
        visual_challenge_id = challenge["visual_challenge"]["challenge_id"]
        
        # Compute ZKP response
        zkp_response = auth_service.compute_auth_response(
            username,
            challenge_id,
            challenge_value,
            password,
            salt
        )
        
        # For this test, we'll use a valid pattern from the pattern generator
        visual_pattern_data = auth_service.pattern_gen.active_challenges[visual_challenge_id]
        visual_response = visual_pattern_data["pattern"]
        
        # Verify with both factors
        is_verified = auth_service.verify_response(
            username,
            challenge_id,
            zkp_response,
            visual_challenge_id,
            visual_response
        )
        
        assert is_verified is True
        
        # Both challenges should be removed
        assert challenge_id not in auth_service.active_challenges
        assert visual_challenge_id not in auth_service.pattern_gen.active_challenges
    
    def test_visual_pattern_verification_failure(self, auth_service, test_user):
        """Test failed visual pattern verification."""
        username = test_user["username"]
        password = test_user["password"]
        salt = base64.b64decode(test_user["registration"]["salt"])
        
        # Create challenge
        challenge = auth_service.create_challenge(username)
        challenge_id = challenge["challenge_id"]
        challenge_value = challenge["challenge"]
        visual_challenge_id = challenge["visual_challenge"]["challenge_id"]
        
        # Compute correct ZKP response
        zkp_response = auth_service.compute_auth_response(
            username,
            challenge_id,
            challenge_value,
            password,
            salt
        )
        
        # Create an incorrect visual pattern response
        wrong_pattern = [[0 for _ in range(8)] for _ in range(8)]

