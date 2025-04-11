#!/usr/bin/env python3
"""
Complete Authentication Flow Example

This script demonstrates a complete authentication flow with the ZKP Visual Authentication system.
It shows:
1. User registration
2. Authentication challenge request
3. ZKP response computation
4. Visual pattern handling
5. Authentication verification
6. Error handling

Run this script against a running ZKP Visual Authentication server.
"""

import os
import sys
import json
import time
import base64
import hashlib
import argparse
import numpy as np
from io import BytesIO
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image, ImageShow

import requests
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt

# Default server settings
DEFAULT_HOST = "http://localhost:8000"


class AuthClient:
    """Client for ZKP Visual Authentication API."""
    
    def __init__(self, base_url: str = DEFAULT_HOST):
        """Initialize the authentication client."""
        self.base_url = base_url
        self.session = requests.Session()
        
        # ZKP parameters - will be fetched from server in a production system
        # These are the parameters for a toy example
        self.params = {
            "p": 23,  # A small prime for demonstration
            "q": 11,  # (p-1)/2, another prime
            "g": 4    # A generator
        }
    
    def register_user(self, username: str, password: str, 
                      personalization: Optional[str] = None) -> Dict[str, Any]:
        """
        Register a new user with the authentication system.
        
        Args:
            username: The username to register
            password: The user's password (never stored on server)
            personalization: Optional device-specific string for added security
            
        Returns:
            The registration data including public key and salt
            
        Raises:
            Exception: If registration fails
        """
        print(f"🔑 Registering user: {username}")
        
        # Prepare registration data
        register_data = {
            "username": username,
            "password": password
        }
        if personalization:
            register_data["personalization"] = personalization
        
        try:
            # Send registration request
            response = self.session.post(
                f"{self.base_url}/register",
                json=register_data
            )
            
            # Check response
            if response.status_code == 201:
                registration = response.json()
                print(f"✅ User registered successfully!")
                print(f"📝 Public key: {registration['public_key']}")
                print(f"🧂 Salt: {registration['salt']}")
                print(f"⏱️ Registered at: {registration['registered_at']}")
                return registration
            else:
                error = response.json()
                print(f"❌ Registration failed: {error['detail']}")
                raise Exception(f"Registration failed: {error['detail']}")
                
        except requests.RequestException as e:
            print(f"❌ Connection error: {str(e)}")
            raise
    
    def request_challenge(self, username: str) -> Dict[str, Any]:
        """
        Request an authentication challenge.
        
        Args:
            username: The username to authenticate
            
        Returns:
            The challenge data including challenge_id, challenge value, and optional visual challenge
            
        Raises:
            Exception: If challenge request fails
        """
        print(f"🔐 Requesting authentication challenge for: {username}")
        
        try:
            # Send challenge request
            response = self.session.post(
                f"{self.base_url}/challenge",
                json={"username": username}
            )
            
            # Check response
            if response.status_code == 200:
                challenge = response.json()
                print(f"✅ Challenge received:")
                print(f"📝 Challenge ID: {challenge['challenge_id']}")
                print(f"⏱️ Challenge expires at: {time.ctime(challenge['expires_at'])}")
                
                # Check if visual challenge is included
                if "visual_challenge" in challenge:
                    print(f"🖼️ Visual challenge included with ID: {challenge['visual_challenge']['challenge_id']}")
                
                return challenge
            else:
                error = response.json()
                print(f"❌ Challenge request failed: {error['detail']}")
                raise Exception(f"Challenge request failed: {error['detail']}")
                
        except requests.RequestException as e:
            print(f"❌ Connection error: {str(e)}")
            raise
    
    def derive_key(self, password: str, salt: bytes, personalization: Optional[str] = None) -> int:
        """
        Derive a private key from the password and salt.
        
        Args:
            password: The user's password
            salt: The salt value from registration
            personalization: Optional device-specific string
            
        Returns:
            The derived private key as an integer
        """
        print(f"🔑 Deriving private key from password")
        
        # Add personalization if provided
        if personalization:
            password = f"{password}:{personalization}"
        
        # Use scrypt to derive a secure key
        # In a production system, use the same parameters as the server
        key_bytes = scrypt(
            password.encode('utf-8'),
            salt,
            key_len=32,  # 256-bit key
            N=2**14,     # CPU/memory cost parameter (lower for demo)
            r=8,         # Block size parameter
            p=1,         # Parallelization parameter
            num_keys=1,
        )
        
        # Convert to integer
        derived_key = int.from_bytes(key_bytes, byteorder='big')
        
        # Ensure the derived key is in the correct range (1 < x < q)
        derived_key = derived_key % (self.params["q"] - 1) + 1
        
        print(f"✅ Private key derived successfully")
        return derived_key
    
    def compute_response(self, private_key: int, challenge_id: str, 
                         challenge_value: int, password: str) -> int:
        """
        Compute a response to the ZKP challenge.
        
        Args:
            private_key: The user's private key
            challenge_id: The challenge ID
            challenge_value: The challenge value
            password: The user's password (used for k derivation)
            
        Returns:
            The computed response value
        """
        print(f"🧮 Computing ZKP response")
        
        # In a real implementation, the client would:
        # 1. Generate random k and compute r = g^k mod p
        # 2. Send r to the server
        # 3. Receive challenge e from server
        # 4. Compute s = k + e * x mod q
        # 5. Send s to the server
        
        # For this example, we'll derive k deterministically from the challenge_id
        # In a real system, k should be randomly generated for each authentication
        k_seed = hashlib.sha256(f"{password}:{challenge_id}".encode()).digest()
        k_value = int.from_bytes(k_seed, byteorder='big') % (self.params["q"] - 1) + 1
        
        # Compute response: s = k + e * x mod q
        # Where:
        # - k is the random commitment value (derived from challenge_id in this example)
        # - e is the challenge
        # - x is the private key
        response = (k_value + challenge_value * private_key) % self.params["q"]
        
        print(f"✅ Response computed successfully")
        return response
    
    def display_visual_challenge(self, image_data: str) -> np.ndarray:
        """
        Display the visual challenge and get user's response.
        
        Args:
            image_data: Base64 encoded image data
            
        Returns:
            The user's response as a 2D array
        """
        print(f"🖼️ Processing visual challenge")
        
        # Decode the image
        image_bytes = base64.b64decode(image_data)
        img = Image.open(BytesIO(image_bytes))
        
        # In a real application, you would:
        # 1. Display the image to the user
        # 2. Let the user provide a response based on the visual pattern
        
        print(f"🖼️ Visual challenge image size: {img.size}")
        
        # For this example, let's save and display the image if possible
        try:
            img.save("visual_challenge.png")
            print(f"✅ Visual challenge image saved to visual_challenge.png")
            
            # Try to display the image
            try:
                # This will display the image if running in an environment with display support
                img.show()
                print(f"✅ Visual challenge displayed")
            except Exception:
                print(f"⚠️ Could not display image. See visual_challenge.png")
        except Exception as e:
            print(f"⚠️ Could not save image: {str(e)}")
        
        # In a real application, the user would respond to the pattern
        # For this example, we'll just return a dummy pattern
        # This will not authenticate successfully since it's not the real pattern
        grid_size = 8  # Assuming 8x8 grid
        user_response = [[i % 4 for i in range(grid_size)] for j in range(grid_size)]
        
        print(f"📝 Generated dummy visual pattern response (this will not authenticate)")
        return user_response
    
    def verify_authentication(self, username: str, challenge_id: str, response: int,
                             visual_challenge_id: Optional[str] = None,
                             visual_response: Optional[List[List[int]]] = None) -> Dict[str, Any]:
        """
        Verify authentication with the server.
        
        Args:
            username: The username being authenticated
            challenge_id: The challenge ID
            response: The computed ZKP response
            visual_challenge_id: Optional visual challenge ID
            visual_response: Optional visual pattern response
            
        Returns:
            The verification result from the server
            
        Raises:
            Exception: If verification fails
        """
        print(f"🔐 Verifying authentication for: {username}")
        
        # Prepare verification data
        verify_data = {
            "username": username,
            "challenge_id": challenge_id,
            "response": str(response)
        }
        
        # Add visual challenge data if provided
        if visual_challenge_id and visual_response:
            verify_data["visual_challenge_id"] = visual_challenge_id
            verify_data["visual_response"] = visual_response
        
        try:
            # Send verification request
            response = self.session.post(
                f"{self.base_url}/verify",
                json=verify_data
            )
            
            # Check response
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Authentication successful!")
                print(f"📝 Session token: {result['session_token']}")
                return result
            else:
                error = response.json()
                print(f"❌ Authentication failed: {error['detail']}")
                raise Exception(f"Authentication failed: {error['detail']}")
                
        except requests.RequestException as e:
            print(f"❌ Connection error: {str(e)}")
            raise


def main():
    """Run the complete authentication flow example."""
    parser = argparse.ArgumentParser(description="ZKP Visual Authentication Example")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server host URL")
    parser.add_argument("--username", default=f"user_{int(time.time())}", help="Username for registration")
    parser.add_argument("--password", default="secure-password-123", help="Password for registration")
    parser.add_argument("--personalization", default="example-device", help="Device personalization string")
    args = parser.parse_args()
    
    # Create the authentication client
    client = AuthClient(args.host)
    
    try:
        # Step 1: Register user
        print("\n" + "="*50)
        print("STEP 1: USER REGISTRATION")
        print("="*50)
        registration = client.register_user(args.username, args.password, args.personalization)
        
        # Decode the salt
        salt = base64.b64decode(registration["salt"])
        
        # Step 2: Request authentication challenge
        print("\n" + "="*50)
        print("STEP 2: REQUEST AUTHENTICATION CHALLENGE")
        print("="*50)
        challenge = client.request_challenge(args.username)
        
        # Parse challenge values
        challenge_id = challenge["challenge_id"]
        challenge_value = int(challenge["commitment"])
        
        # Step 3: Derive private key
        print("\n" + "="*50)
        print("STEP 3: DERIVE PRIVATE KEY")
        print("="*50)
        private_key = client.derive_key(args.password, salt, args.personalization)
        
        # Step 4: Compute ZKP response
        print("\n" + "="*50)
        print("STEP 4: COMPUTE ZKP RESPONSE")
        print("="*50)
        zkp_response = client.compute_response(
            private_key, 
            challenge_id, 
            int(challenge["challenge"]), 
            args.password
        )
        
        # Step 5: Process visual challenge if present
        visual_challenge_id = None
        visual_response = None
        
        if "visual_challenge" in challenge:
            print("\n" + "="*50)
            print("STEP 5: PROCESS VISUAL CHALLENGE")
            print("="*50)
            visual_challenge = challenge["visual_challenge"]
            visual_challenge_id = visual_challenge["challenge_id"]
            visual_response = client.display_visual_challenge(visual_challenge["image_data"])
        
        # Step 6: Verify authentication
        print("\n" + "="*50)
        print("STEP 6: VERIFY AUTHENTICATION")
        print("="*50)
        
        # Note: This will likely fail since we're using a dummy visual pattern response
        # For a real app, the user would need to provide the correct visual pattern
        try:
            result = client.verify_authentication(
                args.username,
                challenge_id,
                zkp_response,
                visual_challenge_id,
                visual_response
            )
            print("\n✅ AUTHENTICATION COMPLETE")
        except Exception as e:
            print(f"\n❌ AUTHENTICATION FAILED: {str(e)}")
            print("Note: This is expected since we used a dummy visual pattern response.")
            print("In a real application, the user would need to correctly interpret the visual pattern.")
        
        print("\n" + "="*50)
        print("COMPLETE AUTHENTICATION FLOW EXAMPLE FINISHED")
        print("="*50)
        
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

