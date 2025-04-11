#!/usr/bin/env python3
"""
Visual Pattern Generator for Zero-Knowledge Proof Authentication.

This module implements a unique grid-based pattern generator that creates
visual challenges for authentication purposes without exposing any 
secret information.
"""

import os
import time
import hashlib
import base64
from typing import Tuple, List, Dict, Optional, Union, Any
from datetime import datetime
from io import BytesIO

import numpy as np
from PIL import Image
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


class PatternError(Exception):
    """Exception raised for errors in the visual pattern operations."""
    pass


class VisualPattern:
    """
    A class that generates and handles unique grid-based visual patterns for authentication.
    
    The pattern generation is based on the user's public key, current timestamp,
    and a random seed to ensure uniqueness and security of each authentication challenge.
    """
    
    def __init__(
        self, 
        grid_size: int = 8, 
        challenge_ttl: int = 30,
        color_depth: int = 8
    ):
        """
        Initialize the VisualPattern generator.
        
        Args:
            grid_size: Size of the pattern grid (grid_size x grid_size).
            challenge_ttl: Time-to-live for challenges in seconds.
            color_depth: Number of distinct colors used in patterns.
        
        Raises:
            PatternError: If parameters are invalid.
        """
        if grid_size < 4:
            raise PatternError("Grid size must be at least 4")
        if challenge_ttl < 5:
            raise PatternError("Challenge TTL must be at least 5 seconds")
        if color_depth < 2 or color_depth > 64:
            raise PatternError("Color depth must be between 2 and 64")
            
        self.grid_size = grid_size
        self.challenge_ttl = challenge_ttl
        self.color_depth = color_depth
        self.active_challenges: Dict[str, Dict[str, Any]] = {}
        
        # Color palette generation
        np.random.seed(42)  # Fixed seed for deterministic color palette
        self.color_palette = [
            tuple(np.random.randint(0, 240, 3).tolist()) 
            for _ in range(color_depth)
        ]
        # Add high contrast edges to palette
        self.color_palette.append((0, 0, 0))  # Black
        self.color_palette.append((255, 255, 255))  # White
        
    def _hash_inputs(self, public_key: str, timestamp: int, seed: bytes) -> bytes:
        """
        Create a hash from the input parameters.
        
        Args:
            public_key: User's public key or identifier.
            timestamp: Current timestamp.
            seed: Random seed bytes.
            
        Returns:
            A SHA256 hash of the combined inputs.
        """
        hasher = SHA256.new()
        hasher.update(public_key.encode('utf-8'))
        hasher.update(str(timestamp).encode('utf-8'))
        hasher.update(seed)
        return hasher.digest()
    
    def generate_pattern(
        self, 
        public_key: str,
        timestamp: Optional[int] = None,
        seed: Optional[bytes] = None
    ) -> np.ndarray:
        """
        Generate a unique pattern based on user's public key, timestamp, and a random seed.
        
        Args:
            public_key: User's public key or identifier.
            timestamp: Custom timestamp, defaults to current time if None.
            seed: Custom random seed, defaults to system-generated if None.
            
        Returns:
            A numpy array representing the pattern grid with color indices.
            
        Raises:
            PatternError: If public_key is invalid.
        """
        if not public_key or len(public_key) < 8:
            raise PatternError("Public key must be at least 8 characters")
            
        # Use provided values or defaults
        timestamp = timestamp or int(time.time())
        seed = seed or get_random_bytes(16)
        
        # Generate hash from inputs
        hash_bytes = self._hash_inputs(public_key, timestamp, seed)
        
        # Use hash to seed the numpy random generator
        np_seed = int.from_bytes(hash_bytes[:8], byteorder='big')
        pattern_gen = np.random.RandomState(np_seed)
        
        # Generate the pattern grid
        pattern = pattern_gen.randint(
            0, self.color_depth, 
            (self.grid_size, self.grid_size), 
            dtype=np.uint8
        )
        
        # Create some structure by introducing symmetry and patterns
        # This makes patterns more visually distinctive and user-recognizable
        
        # Add some symmetry
        if hash_bytes[0] % 4 == 0:  # 25% chance of horizontal symmetry
            pattern[self.grid_size//2:, :] = np.flipud(pattern[:self.grid_size//2, :])
        elif hash_bytes[0] % 4 == 1:  # 25% chance of vertical symmetry
            pattern[:, self.grid_size//2:] = np.fliplr(pattern[:, :self.grid_size//2])
        elif hash_bytes[0] % 4 == 2:  # 25% chance of quadrant symmetry
            quarter = pattern[:self.grid_size//2, :self.grid_size//2]
            pattern[:self.grid_size//2, self.grid_size//2:] = np.fliplr(quarter)
            pattern[self.grid_size//2:, :self.grid_size//2] = np.flipud(quarter)
            pattern[self.grid_size//2:, self.grid_size//2:] = np.flipud(np.fliplr(quarter))
            
        return pattern
    
    def pattern_to_image(self, pattern: np.ndarray, size: int = 400) -> Image.Image:
        """
        Convert a pattern array to a PIL Image.
        
        Args:
            pattern: The pattern grid as a numpy array.
            size: The output image size in pixels.
            
        Returns:
            A PIL Image representing the pattern.
            
        Raises:
            PatternError: If the pattern is invalid.
        """
        if not isinstance(pattern, np.ndarray):
            raise PatternError("Pattern must be a numpy array")
        
        if pattern.shape != (self.grid_size, self.grid_size):
            raise PatternError(f"Pattern must be {self.grid_size}x{self.grid_size}")
            
        # Create a blank image
        cell_size = size // self.grid_size
        img = Image.new('RGB', (size, size), color=(240, 240, 240))
        draw = Image.new('RGB', (size, size))
        
        # Draw each cell
        for y in range(self.grid_size):
            for x in range(self.grid_size):
                color_idx = pattern[y, x] % len(self.color_palette)
                color = self.color_palette[color_idx]
                
                # Calculate cell coordinates
                left = x * cell_size
                top = y * cell_size
                right = left + cell_size
                bottom = top + cell_size
                
                # Draw filled rectangle on our draw surface
                for py in range(top, bottom):
                    for px in range(left, right):
                        if px < size and py < size:  # Ensure within bounds
                            draw.putpixel((px, py), color)
        
        return draw
    
    def get_challenge(self, public_key: str) -> Dict[str, Any]:
        """
        Generate a new visual challenge for authentication.
        
        Args:
            public_key: User's public key or identifier.
            
        Returns:
            A dictionary containing:
                - challenge_id: Unique identifier for this challenge
                - image_data: Base64 encoded PNG image of the pattern
                - timestamp: When the challenge was created
                - expires_at: When the challenge expires
                
        Raises:
            PatternError: If public_key is invalid or challenge generation fails.
        """
        timestamp = int(time.time())
        challenge_id = hashlib.sha256(f"{public_key}:{timestamp}:{os.urandom(8)}".encode()).hexdigest()
        
        try:
            # Generate random seed for this challenge
            seed = get_random_bytes(16)
            
            # Generate the pattern
            pattern = self.generate_pattern(public_key, timestamp, seed)
            
            # Convert to image
            img = self.pattern_to_image(pattern)
            
            # Save pattern image to a bytes buffer and convert to base64
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            image_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            # Store challenge details
            expires_at = timestamp + self.challenge_ttl
            challenge_data = {
                "pattern": pattern.tolist(),
                "timestamp": timestamp,
                "public_key": public_key,
                "seed": seed,
                "expires_at": expires_at
            }
            
            self.active_challenges[challenge_id] = challenge_data
            
            # Clean up expired challenges
            self._cleanup_expired_challenges()
            
            return {
                "challenge_id": challenge_id,
                "image_data": image_data,
                "timestamp": timestamp,
                "expires_at": expires_at
            }
            
        except Exception as e:
            raise PatternError(f"Failed to generate challenge: {str(e)}")
    
    def verify_pattern(self, challenge_id: str, user_response: List[List[int]]) -> bool:
        """
        Verify a user's response to a visual pattern challenge.
        
        Args:
            challenge_id: The ID of the challenge being responded to.
            user_response: The user's response as a 2D grid of integers.
            
        Returns:
            True if verification succeeds, False otherwise.
            
        Raises:
            PatternError: If the challenge_id is unknown or expired.
        """
        # Check if challenge exists
        if challenge_id not in self.active_challenges:
            raise PatternError("Unknown or expired challenge")
            
        challenge = self.active_challenges[challenge_id]
        
        # Check if challenge has expired
        if int(time.time()) > challenge["expires_at"]:
            # Remove expired challenge
            del self.active_challenges[challenge_id]
            raise PatternError("Challenge has expired")
            
        # Convert stored pattern to same format as user response for comparison
        stored_pattern = challenge["pattern"]
        
        # Convert user_response to numpy array for comparison
        try:
            user_array = np.array(user_response, dtype=np.uint8)
            stored_array = np.array(stored_pattern, dtype=np.uint8)
            
            # Compare patterns
            if user_array.shape != stored_array.shape:
                return False
                
            # Check if patterns match
            result = np.array_equal(user_array, stored_array)
            
            # Remove used challenge regardless of result
            del self.active_challenges[challenge_id]
            
            return result
            
        except Exception:
            # Remove challenge and return False on any error
            if challenge_id in self.active_challenges:
                del self.active_challenges[challenge_id]
            return False
    
    def _cleanup_expired_challenges(self) -> None:
        """
        Remove expired challenges from the active challenges dictionary.
        """
        current_time = int(time.time())
        expired_ids = [
            cid for cid, data in self.active_challenges.items()
            if data["expires_at"] < current_time
        ]
        
        for cid in expired_ids:
            del self.active_challenges[cid]


# Example usage
if __name__ == "__main__":
    # Create pattern generator
    pattern_gen = VisualPattern(grid_size=10)
    
    # Generate a pattern for a user
    user_key = "test_user_123"
    challenge = pattern_gen.get_challenge(user_key)
    
    print(f"Generated challenge ID: {challenge['challenge_id']}")
    print(f"Challenge expires at: {datetime.fromtimestamp(challenge['expires_at'])}")
    
    # In a real system, the user would respond with their interpretation of the pattern
    # For this example, we'll just use the stored pattern as the response
    challenge_data = pattern_gen.active_challenges[challenge['challenge_id']]
    user_response = challenge_data["pattern"]
    
    # Verify the response
    is_valid = pattern_gen.verify_pattern(challenge['challenge_id'], user_response)
    print(f"Verification result: {is_valid}")

