#!/usr/bin/env python3
"""
Zero-Knowledge Proof Authentication Module.

This module implements Schnorr's protocol for zero-knowledge proofs,
allowing secure authentication without revealing password or secret information.
It integrates with the VisualPattern class to create a multi-factor
authentication system.
"""

import os
import time
import hashlib
import secrets
import base64
from typing import Dict, Tuple, Optional, Any, Union, List
from dataclasses import dataclass

from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Util.number import getPrime, getRandomRange, isPrime

# Import our visual pattern module
from .visual_pattern import VisualPattern, PatternError


class ZKPError(Exception):
    """Exception raised for errors in the ZKP authentication process."""
    pass


@dataclass
class ZKPParameters:
    """Parameters for the Schnorr ZKP protocol."""
    p: int  # Large prime number
    q: int  # Large prime factor of p-1
    g: int  # Generator element


@dataclass
class ZKPKeyPair:
    """Key pair for Schnorr ZKP protocol."""
    private_key: int
    public_key: int


@dataclass
class ZKPChallenge:
    """Challenge data for Schnorr ZKP protocol."""
    commitment: int
    challenge: int
    challenge_id: str
    timestamp: int
    expires_at: int
    visual_challenge_id: Optional[str] = None


class ZKPAuth:
    """
    Zero-Knowledge Proof Authentication implementation using Schnorr's protocol.
    
    This class implements a secure authentication system that verifies user
    identity without ever transmitting or storing actual passwords or secrets.
    It can be integrated with the VisualPattern class for multi-factor auth.
    """
    
    def __init__(
        self, 
        challenge_ttl: int = 60,
        key_bits: int = 2048,
        use_visual_patterns: bool = True,
        visual_pattern_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the ZKP authentication system.
        
        Args:
            challenge_ttl: Time-to-live for challenges in seconds.
            key_bits: Bit size for cryptographic parameters.
            use_visual_patterns: Whether to use visual pattern verification.
            visual_pattern_config: Configuration for the VisualPattern generator.
            
        Raises:
            ZKPError: If parameters are invalid or initialization fails.
        """
        if challenge_ttl < 15:
            raise ZKPError("Challenge TTL must be at least 15 seconds")
        
        if key_bits < 1024:
            raise ZKPError("Key size must be at least 1024 bits")
            
        self.challenge_ttl = challenge_ttl
        self.key_bits = key_bits
        self.use_visual_patterns = use_visual_patterns
        
        # Initialize pattern generator if enabled
        self.pattern_gen = None
        if use_visual_patterns:
            try:
                pattern_config = visual_pattern_config or {}
                self.pattern_gen = VisualPattern(**pattern_config)
            except Exception as e:
                raise ZKPError(f"Failed to initialize visual pattern generator: {str(e)}")
        
        # Generate system parameters if not provided
        self.params = self._generate_parameters(key_bits)
        
        # Storage for active challenges
        self.active_challenges: Dict[str, ZKPChallenge] = {}
        
        # Storage for registered users' public keys
        self.registered_users: Dict[str, int] = {}
    
    def _generate_parameters(self, bits: int) -> ZKPParameters:
        """
        Generate cryptographic parameters for the Schnorr protocol.
        
        Args:
            bits: Bit size for the prime number.
            
        Returns:
            ZKPParameters object containing p, q, and g.
            
        Raises:
            ZKPError: If parameter generation fails.
        """
        try:
            # Generate a safe prime p such that p = 2q + 1 where q is also prime
            while True:
                q = getPrime(bits - 1)
                p = 2 * q + 1
                if isPrime(p):
                    break
            
            # Find a generator g of the subgroup of order q
            while True:
                h = getRandomRange(2, p - 1)
                g = pow(h, 2, p)
                if g != 1:
                    break
            
            return ZKPParameters(p=p, q=q, g=g)
            
        except Exception as e:
            raise ZKPError(f"Failed to generate cryptographic parameters: {str(e)}")
    
    def derive_key(
        self, 
        password: str, 
        salt: Optional[bytes] = None,
        personalization: Optional[str] = None
    ) -> Tuple[int, bytes]:
        """
        Derive a secure private key from a password using scrypt.
        
        Args:
            password: User's password or secret.
            salt: Optional salt value, generated if not provided.
            personalization: Optional string to personalize the key.
            
        Returns:
            Tuple of (derived_key as integer, salt used).
            
        Raises:
            ZKPError: If key derivation fails.
        """
        try:
            # Generate salt if not provided
            if salt is None:
                salt = get_random_bytes(32)
            
            # Add personalization if provided
            if personalization:
                password = f"{password}:{personalization}"
            
            # Use scrypt to derive a key with strong parameters
            key_bytes = scrypt(
                password.encode('utf-8'),
                salt,
                key_len=32,  # 256-bit key
                N=2**17,     # CPU/memory cost parameter
                r=8,         # Block size parameter
                p=1,         # Parallelization parameter
                num_keys=1,
            )
            
            # Convert to integer
            derived_key = int.from_bytes(key_bytes, byteorder='big')
            
            # Ensure the derived key is in the correct range (1 < x < q)
            derived_key = derived_key % (self.params.q - 1) + 1
            
            return derived_key, salt
            
        except Exception as e:
            raise ZKPError(f"Key derivation failed: {str(e)}")
            
    def generate_keypair(
        self, 
        password: Optional[str] = None,
        private_key: Optional[int] = None,
        salt: Optional[bytes] = None,
        personalization: Optional[str] = None
    ) -> Tuple[ZKPKeyPair, bytes]:
        """
        Generate a keypair for ZKP authentication.
        
        Either password or private_key must be provided. If password is provided,
        a private key will be derived using the secure key derivation function.
        
        Args:
            password: Optional user password to derive private key from.
            private_key: Optional explicit private key.
            salt: Optional salt for key derivation.
            personalization: Optional string to personalize derived keys.
            
        Returns:
            Tuple of (ZKPKeyPair, salt used for derivation)
            
        Raises:
            ZKPError: If keypair generation fails.
        """
        try:
            if password is None and private_key is None:
                raise ZKPError("Either password or private_key must be provided")
            
            # Derive or use provided private key
            if password is not None:
                private_key, salt = self.derive_key(password, salt, personalization)
            else:
                if private_key <= 1 or private_key >= self.params.q:
                    raise ZKPError(f"Private key must be in range [2, q-1]")
                # Generate salt if not provided and using explicit private key
                if salt is None:
                    salt = get_random_bytes(32)
            
            # Compute public key: y = g^x mod p
            public_key = pow(self.params.g, private_key, self.params.p)
            
            return ZKPKeyPair(private_key=private_key, public_key=public_key), salt
            
        except ZKPError:
            raise
        except Exception as e:
            raise ZKPError(f"Failed to generate keypair: {str(e)}")
    
    def register_user(
        self, 
        username: str, 
        password: str,
        personalization: Optional[str] = None
    ) -> Dict[str, Union[str, bytes]]:
        """
        Register a new user in the system.
        
        Args:
            username: Unique username for the user.
            password: User's password (never stored).
            personalization: Optional string to personalize the key.
            
        Returns:
            Dictionary with registration data including user's public info.
            
        Raises:
            ZKPError: If registration fails or username already exists.
        """
        if username in self.registered_users:
            raise ZKPError(f"Username '{username}' already registered")
            
        try:
            # Generate a keypair from the password
            keypair, salt = self.generate_keypair(password, personalization=personalization)
            
            # Store only the public key
            self.registered_users[username] = keypair.public_key
            
            # Return registration data
            return {
                "username": username,
                "public_key": keypair.public_key,
                "salt": base64.b64encode(salt).decode('utf-8'),
                "registered_at": int(time.time())
            }
            
        except ZKPError:
            raise
        except Exception as e:
            raise ZKPError(f"User registration failed: {str(e)}")
    
    def create_challenge(self, username: str) -> Dict[str, Any]:
        """
        Create an authentication challenge for a user.
        
        Args:
            username: The username to authenticate.
            
        Returns:
            Dictionary with challenge data.
            
        Raises:
            ZKPError: If user not found or challenge creation fails.
        """
        if username not in self.registered_users:
            raise ZKPError(f"User '{username}' not registered")
            
        try:
            # Generate random commitment value k (1 < k < q)
            k = getRandomRange(2, self.params.q - 1)
            
            # Compute commitment r = g^k mod p
            r = pow(self.params.g, k, self.params.p)
            
            # Generate a random challenge
            challenge = getRandomRange(2, self.params.q - 1)
            
            # Create challenge ID and timestamp
            timestamp = int(time.time())
            challenge_id = hashlib.sha256(f"{username}:{timestamp}:{secrets.token_hex(16)}".encode()).hexdigest()
            
            # Store challenge
            challenge_data = ZKPChallenge(
                commitment=r,
                challenge=challenge,
                challenge_id=challenge_id,
                timestamp=timestamp,
                expires_at=timestamp + self.challenge_ttl
            )
            
            self.active_challenges[challenge_id] = challenge_data
            
            # Create visual challenge if enabled
            visual_challenge = None
            if self.use_visual_patterns and self.pattern_gen:
                try:
                    # Use username and public key as inputs for pattern generation
                    user_public_key = self.registered_users[username]
                    visual_challenge = self.pattern_gen.get_challenge(
                        f"{username}:{user_public_key}"
                    )
                    
                    # Link the visual challenge to the ZKP challenge
                    challenge_data.visual_challenge_id = visual_challenge["challenge_id"]
                    
                except PatternError as e:
                    # Continue with ZKP challenge even if visual pattern fails
                    pass
            
            # Clean up expired challenges
            self._cleanup_expired_challenges()
            
            # Return challenge data to client
            response = {
                "challenge_id": challenge_id,
                "commitment": r,
                "challenge": challenge,
                "timestamp": timestamp,
                "expires_at": timestamp + self.challenge_ttl
            }
            
            # Include visual challenge if available
            if visual_challenge:
                response["visual_challenge"] = {
                    "challenge_id": visual_challenge["challenge_id"],
                    "image_data": visual_challenge["image_data"],
                    "expires_at": visual_challenge["expires_at"]
                }
                
            return response
            
        except Exception as e:
            raise ZKPError(f"Failed to create challenge: {str(e)}")
    
    def verify_response(
        self, 
        username: str, 
        challenge_id: str, 
        response: int,
        visual_challenge_id: Optional[str] = None,
        visual_response: Optional[List[List[int]]] = None
    ) -> bool:
        """
        Verify a user's response to an authentication challenge.
        
        Args:
            username: The username being authenticated.
            challenge_id: ID of the challenge being responded to.
            response: The ZKP response value.
            visual_challenge_id: Optional ID of the visual challenge.
            visual_response: Optional response to the visual challenge.
            
        Returns:
            True if authentication succeeded, False otherwise.
            
        Raises:
            ZKPError: If verification fails due to expired or invalid challenge.
        """
        # Check if challenge exists
        if challenge_id not in self.active_challenges:
            raise ZKPError("Unknown or expired challenge")
            
        # Check if user exists
        if username not in self.registered_users:
            raise ZKPError(f"User '{username}' not registered")
            
        challenge = self.active_challenges[challenge_id]
        
        # Check if challenge has expired
        current_time = int(time.time())
        if current_time > challenge.expires_at:
            del self.active_challenges[challenge_id]
            raise ZKPError("Challenge has expired")
            
        try:
            # Get user's public key
            y = self.registered_users[username]
            
            # Compute expected value: g^s ?= r * y^e mod p
            # Where:
            # - g is the generator
            # - s is the response
            # - r is the commitment
            # - y is the public key
            # - e is the challenge
            
            # Compute left side: g^s mod p
            left = pow(self.params.g, response, self.params.p)
            
            # Compute right side: r * y^e mod p
            right = (challenge.commitment * pow(y, challenge.challenge, self.params.p)) % self.params.p
            
            # ZKP verification result
            zkp_verified = (left == right)
            
            # Visual pattern verification
            visual_verified = True
            if self.use_visual_patterns and self.pattern_gen:
                if challenge.visual_challenge_id:
                    # If visual challenge was created, it must be verified
                    if not visual_challenge_id or not visual_response:
                        visual_verified = False
                    else:
                        # Verify the visual pattern response
                        try:
                            visual_verified = self.pattern_gen.verify_pattern(
                                visual_challenge_id,
                                visual_response
                            )
                        except PatternError:
                            visual_verified = False
            
            # Overall verification result
            auth_result = zkp_verified and visual_verified
            
            # Remove the used challenge regardless of result
            del self.active_challenges[challenge_id]
            
            return auth_result
            
        except ZKPError:
            raise
        except Exception as e:
            raise ZKPError(f"Authentication verification failed: {str(e)}")
    
    def _cleanup_expired_challenges(self) -> None:
        """
        Remove expired challenges from active challenges.
        
        This helps prevent memory leaks by purging old, unused challenges.
        """
        current_time = int(time.time())
        expired_ids = [
            cid for cid, data in self.active_challenges.items()
            if data.expires_at < current_time
        ]
        
        for cid in expired_ids:
            del self.active_challenges[cid]
    
    def compute_auth_response(
        self, 
        username: str,
        challenge_id: str,
        challenge: int,
        password: str,
        salt: bytes,
        personalization: Optional[str] = None
    ) -> int:
        """
        Compute a response to an authentication challenge.
        
        This is a helper method typically used on the client side to generate
        the proper response to a ZKP challenge.
        
        Args:
            username: The username being authenticated.
            challenge_id: The ID of the challenge.
            challenge: The challenge value.
            password: User's password or secret.
            salt: Salt used for key derivation.
            personalization: Optional string used to personalize the key.
            
        Returns:
            The computed response value for the ZKP protocol.
            
        Raises:
            ZKPError: If response computation fails.
        """
        try:
            # Derive the private key from the password
            private_key, _ = self.derive_key(password, salt, personalization)
            
            # Compute response: s = k + e * x mod q
            # Where:
            # - k is the random commitment value (known only to the client)
            # - e is the challenge
            # - x is the private key
            
            # For security, this would be implemented on the client side
            # and only the response would be sent to the server
            # This is just for demonstration purposes
            
            # In a real implementation, the client would:
            # 1. Generate random k and compute r = g^k mod p
            # 2. Send r to the server
            # 3. Receive challenge e from server
            # 4. Compute s = k + e * x mod q
            # 5. Send s to the server
            
            # For demo purposes, we'll use a deterministic k derived from the challenge_id
            k_seed = hashlib.sha256(f"{password}:{challenge_id}".encode()).digest()
            k_value = int.from_bytes(k_seed, byteorder='big') % (self.params.q - 1) + 1
            
            # Compute response
            response = (k_value + challenge * private_key) % self.params.q
            
            return response
            
        except Exception as e:
            raise ZKPError(f"Failed to compute authentication response: {str(e)}")
    
    def export_parameters(self) -> Dict[str, int]:
        """
        Export the cryptographic parameters for client use.
        
        Returns:
            Dictionary containing the ZKP system parameters.
        """
        return {
            "p": self.params.p,
            "q": self.params.q,
            "g": self.params.g
        }


# Example usage
if __name__ == "__main__":
    # Create ZKP authentication system
    auth = ZKPAuth(challenge_ttl=60, key_bits=1024)  # Using smaller key for demo
    
    # Register a user
    username = "testuser"
    password = "securepassword123"
    registration = auth.register_user(username, password)
    
    print(f"Registered user: {username}")
    print(f"Public key: {registration['public_key']}")
    print(f"Salt: {registration['salt']}")
    
    # Create an authentication challenge
    challenge_data = auth.create_challenge(username)
    print(f"Challenge created with ID: {challenge_data['challenge_id']}")
    
    # Decode the salt from registration
    salt = base64.b64decode(registration['salt'])
    
    # Compute the response (normally done by client)
    response = auth.compute_auth_response(
        username,
        challenge_data['challenge_id'],
        challenge_data['challenge'],
        password,
        salt
    )
    
    # Verify the response
    is_authenticated = auth.verify_response(
        username,
        challenge_data['challenge_id'],
        response
    )
    
    print(f"Authentication result: {'Success' if is_authenticated else 'Failed'}")
    
    # Try with wrong password
    wrong_response = auth.compute_auth_response(
        username,
        challenge_data['challenge_id'],
        challenge_data['challenge'],
        "wrongpassword",
        salt
    )
    
    try:
        # This should fail because the challenge was already used
        is_authenticated = auth.verify_response(
            username,
            challenge_data['challenge_id'],
            wrong_response
        )
        print("This should not happen - challenge was already used")
    except ZKPError as e:
        print(f"Expected error: {e}")
    
    # Create a new challenge
    challenge_data = auth.create_challenge(username)
    print(f"New challenge created with ID: {challenge_data['challenge_id']}")
    
    # Try with a wrong response
    wrong_response = auth.compute_auth_response(
        username,
        challenge_data['challenge_id'],
        challenge_data['challenge'],
        "wrongpassword",
        salt
    )
    
    is_authenticated = auth.verify_response(
        username,
        challenge_data['challenge_id'],
        wrong_response
    )
    
    print(f"Authentication with wrong password: {'Success' if is_authenticated else 'Failed (expected)'}")

