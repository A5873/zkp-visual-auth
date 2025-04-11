```
  _______  ___  __ ________    __     __ _                  _                   _   _     
 |__  /  |/ / |/ // ____/ /_   \ \   / /(_)___ _  __ ___   / \ __ __  / /_/ /_ | | | |    
   / /|  / /|   // /_  / __ \   \ \ / // // __ `/ / // _ \ /  // // / / __/ __ \| |_| |    
  / /_/ /_//   // __/ / /_/ /    \ V // // /_/ / / //  __// /_// // // /_/ / / /|  _  |    
 /____/(_)/_/|_/_/    \____/      \_//_/ \__,_/ /_/ \___//_/(_)_//_/ \__/_/ /_/ |_| |_|    
                                                                                            
   +-------------------------------+                    ╔═══════════════════╗
   |  ┌─┬─┬─┬─┬─┬─┐  +--------+   |                    ║ ▓▓▓░░▓▓▓░░▓▓▓░░▓ ║
   |  ├─┼─┼─┼─┼─┼─┤  | ┌────┐ |   |                    ║ ░▓▓▓░░▓▓▓░░▓▓▓░░ ║
   |  ├─┼─┼─┼─┼─┼─┤  | │ ZKP│ |   |  ⌐─────────┐       ║ ▓░░▓▓▓░░▓▓▓░░▓▓▓ ║
   |  ├─┼─┼─┼─┼─┼─┤  | └────┘ |   | [┌──────┐  |       ║ ░▓▓▓░░▓▓▓░░▓▓▓░░ ║
   |  ├─┼─┼─┼─┼─┼─┤  +--------+   |  └──────┘  |       ║ ▓▓▓░░▓▓▓░░▓▓▓░░▓ ║
   |  └─┴─┴─┴─┴─┴─┘               └────────────┘       ╚═══════════════════╝
   +-------------------------------+                    
```

# ZKP Visual Authentication

A secure, privacy-focused authentication system that combines Zero-Knowledge Proofs (ZKP) with visual pattern verification to create a multi-factor authentication solution without storing sensitive credentials.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

## ✨ Features

- **Zero-Knowledge Proof Authentication**: Verify identity without ever transmitting or storing passwords
- **Visual Pattern Verification**: Additional authentication factor using unique visual patterns
- **RESTful API**: Complete FastAPI server with Swagger documentation
- **Strong Cryptography**: Implements Schnorr's protocol for ZKP with secure key derivation
- **Privacy by Design**: Protects user privacy through cryptographic methods
- **Production Ready**: Includes security headers, error handling, and deployment guidelines

## 📋 Table of Contents

- [Installation](#-installation)
- [Security Considerations](#-security-considerations)
- [Usage Examples](#-usage-examples)
- [Development Setup](#-development-setup)
- [Production Deployment](#-production-deployment)
- [API Documentation](#-api-documentation)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- virtualenv (recommended)

### Basic Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/zkp-visual-auth.git
   cd zkp-visual-auth
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows, use: venv\Scripts\activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the server (development mode):
   ```bash
   cd src
   python -m uvicorn server:app --reload
   ```

5. Visit `http://localhost:8000/docs` in your browser to see the API documentation.

## 🛡️ Security Considerations

This authentication system provides strong security guarantees, but proper deployment is critical:

### Key Security Features

- **Zero-Knowledge Authentication**: Proves identity without revealing any secret information
- **No Password Storage**: Unlike traditional systems, passwords are never stored
- **Multi-Factor Authentication**: Combines cryptographic proofs with visual pattern recognition
- **Strong Key Derivation**: Uses scrypt with robust parameters for key generation
- **Limited Challenge Lifetime**: All authentication challenges expire quickly

### Implementation Considerations

1. **Always Use HTTPS**: In production, always deploy behind HTTPS to prevent MITM attacks
2. **Proper Secrets Management**: Ensure cryptographic parameters and secrets are properly managed
3. **Rate Limiting**: Implement rate limiting to prevent brute force attacks
4. **Persistent Storage**: For production, implement secure database storage for user information
5. **Regular Security Audits**: Have the cryptographic implementation reviewed by experts

## 📝 Usage Examples

### Complete Authentication Flow

#### 1. Register a User

```bash
curl -X POST "http://localhost:8000/register" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "alice",
           "password": "secure-password-example",
           "personalization": "my-device-id"
         }'
```

Response:
```json
{
  "username": "alice",
  "public_key": "8675309...",
  "salt": "base64-encoded-salt-value",
  "registered_at": 1618087345
}
```

> 💡 **Important**: Store the salt value securely - it's needed for authentication!

#### 2. Request an Authentication Challenge

```bash
curl -X POST "http://localhost:8000/challenge" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "alice"
         }'
```

Response:
```json
{
  "challenge_id": "abc123def456...",
  "commitment": "123456789...",
  "challenge": "987654321...",
  "timestamp": 1618087400,
  "expires_at": 1618087700,
  "visual_challenge": {
    "challenge_id": "vis123def456...",
    "image_data": "base64-encoded-image",
    "expires_at": 1618087700
  }
}
```

#### 3. Verify Authentication

In a real client application, you would:
1. Derive the private key from the user's password and saved salt
2. Compute the ZKP response
3. Process the visual pattern for the second factor
4. Send the responses to verify

```bash
curl -X POST "http://localhost:8000/verify" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "alice",
           "challenge_id": "abc123def456...",
           "response": "computed-zkp-response-value",
           "visual_challenge_id": "vis123def456...",
           "visual_response": [[0,1,2],[3,4,5],[6,7,8]]
         }'
```

Response:
```json
{
  "authenticated": true,
  "username": "alice",
  "timestamp": 1618087500,
  "session_token": "your-secure-session-token"
}
```

## 🧪 Development Setup

For development and testing purposes:

1. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the tests:
   ```bash
   pytest
   ```

3. Start the server in development mode:
   ```bash
   cd src
   python -m uvicorn server:app --reload --host 0.0.0.0 --port 8000
   ```

### Environment Variables

You can customize the server behavior with these environment variables:

- `HOST`: The host to bind the server to (default: `0.0.0.0`)
- `PORT`: The port to run the server on (default: `8000`)
- `LOG_LEVEL`: Logging level (default: `info`)

## 📂 Project Structure

The project is organized in a clean, modular structure:

```
zkp-visual-auth/
├── requirements.txt      # Project dependencies
├── README.md            # Project documentation
├── src/                 # Source code
│   ├── __init__.py      # Package initialization
│   ├── visual_pattern.py # Visual pattern generation & verification
│   ├── zkp_auth.py      # Zero-Knowledge Proof authentication
│   └── server.py        # FastAPI web server
├── tests/               # Test suite
│   ├── conftest.py      # Shared test fixtures
│   ├── test_visual_pattern.py # Tests for visual pattern module
│   ├── test_zkp_auth.py # Tests for ZKP authentication module
│   └── test_server.py   # Tests for REST API endpoints
└── examples/            # Example usage scripts (optional)
```

### Core Modules

- **visual_pattern.py**: Implements the visual pattern generation and verification system
- **zkp_auth.py**: Provides the Zero-Knowledge Proof authentication using Schnorr's protocol
- **server.py**: Implements the FastAPI REST API for the authentication system

## 🧪 Testing

The project includes a comprehensive test suite covering all aspects of the authentication system:

### Running Tests

Run the entire test suite:
```bash
pytest
```

Run specific test modules:
```bash
pytest tests/test_visual_pattern.py  # Test visual pattern system only
pytest tests/test_zkp_auth.py        # Test ZKP authentication only
pytest tests/test_server.py          # Test API endpoints only
```

Run tests with verbose output:
```bash
pytest -v
```

Generate test coverage report:
```bash
pytest --cov=src --cov-report=term-missing
```

### Test Organization

The test suite is organized into three main components:

1. **Visual Pattern Tests**: Tests for pattern generation, verification, and security features
2. **ZKP Authentication Tests**: Tests for cryptographic operations, key generation, challenge-response, and security
3. **API Tests**: Tests for API endpoints, request validation, error handling, and security headers

### Test Fixtures

Shared test fixtures are defined in `tests/conftest.py`:

- **Authentication Fixtures**: Pre-configured instances of `VisualPattern` and `ZKPAuth`
- **Test Data Fixtures**: Generate test users, patterns, challenges, and responses
- **Mock Fixtures**: For time functions, random functions, and verification responses
- **Cleanup Fixtures**: Reset state between tests to ensure isolation

### Test Coverage

The test suite aims for high coverage of all components:

- **Core Logic**: 95%+ coverage of all authentication logic
- **Edge Cases**: Tests for expired challenges, invalid inputs, and error conditions
- **Security Features**: Tests for challenge expiration, replay protection, and proper error handling

### Continuous Integration

For continuous integration, add these commands to your CI workflow:

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest

# Run tests with coverage
pytest --cov=src --cov-report=xml

# Run security checks
bandit -r src/
```

## 🚢 Production Deployment

For production deployment, we recommend:

### Using Gunicorn with Uvicorn workers

1. Install production dependencies:
   ```bash
   pip install gunicorn
   ```

2. Run with Gunicorn:
   ```bash
   gunicorn -w 4 -k uvicorn.workers.UvicornWorker src.server:app
   ```

### Docker Deployment

A sample Dockerfile is provided:

```Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "src.server:app", "--bind", "0.0.0.0:8000"]
```

Build and run:
```bash
docker build -t zkp-visual-auth .
docker run -p 8000:8000 zkp-visual-auth
```

### Security in Production

1. Set up HTTPS with a proper certificate
2. Use a reverse proxy like Nginx
3. Implement proper rate limiting
4. Store user data in a secure database
5. Set up proper monitoring and alerting

## 📚 API Documentation

Once the server is running, visit `/docs` for the Swagger UI documentation.

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register` | POST | Register a new user |
| `/challenge` | POST | Create an authentication challenge |
| `/verify` | POST | Verify an authentication response |

For detailed request/response schemas and examples, see the Swagger documentation.

## 👥 Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Contribution Guidelines

- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass before submitting a PR

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
---

```
  +-------------------------------+                    
  |                               |                    
  |  ┌─┬─┬─┬─┬─┬─┐               |          🔐  
  |  ├─┼─┼─┼─┼─┼─┤               |         /│\  
  |  ├─┼─┼─┼─┼─┼─┤  SECURITY     |        / │ \  
  |  ├─┼─┼─┼─┼─┼─┤  PRIVACY      |       /  │  \  
  |  ├─┼─┼─┼─┼─┼─┤  TRUST        |      /___│___\  
  |  └─┴─┴─┴─┴─┴─┘               |          │      
  |                               |          │      
  +-------------------------------+          │      
```

Built with ❤️ for secure, privacy-focused authentication

