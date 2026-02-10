"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from passlib import exc as passlib_exc
import json
import logging
import os
import secrets
import threading
from pathlib import Path
from typing import Dict

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Module-level logger
logger = logging.getLogger(__name__)

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")


class LoginRequest(BaseModel):
    username: str
    password: str


# Password hashing configuration
# Using bcrypt for secure password hashing with passlib's CryptContext
# 
# Security Benefits:
# 1. **Hashing vs Plaintext Storage**: bcrypt creates a one-way cryptographic hash of passwords.
#    If the credential file is compromised, attackers cannot reverse-engineer the original passwords.
#    This is crucial for protecting user accounts even when data is leaked.
#
# 2. **Salting**: bcrypt automatically generates a unique salt for each password hash.
#    This prevents rainbow table attacks and ensures identical passwords produce different hashes.
#    The salt is embedded in the hash output, so no separate storage is needed.
#
# 3. **Adaptive Cost Factor**: bcrypt's computational cost can be increased over time as hardware improves.
#    This work factor (default: 12 rounds) makes brute-force attacks computationally expensive.
#    Each increment doubles the computation time, providing long-term security.
#
# 4. **Constant-Time Comparison**: The verify() method uses constant-time comparison to prevent
#    timing attacks where attackers measure response times to guess password characteristics.
#    This ensures validation time is independent of where the password comparison fails.
#
# Learn More:
# - OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
# - bcrypt Algorithm Explained: https://en.wikipedia.org/wiki/Bcrypt
# - Timing Attack Prevention: https://codahale.com/a-lesson-in-timing-attacks/
# - Passlib Documentation: https://passlib.readthedocs.io/en/stable/narr/quickstart.html
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def load_teachers(path: Path) -> Dict[str, str]:
    if not path.exists():
        logger.warning(
            "Teacher credentials file not found at %s. "
            "All teacher login attempts will fail. "
            "Please create the file with valid teacher credentials to enable admin functionality.",
            path
        )
        return {}

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        
        # Validate that data is a list
        if not isinstance(data, list):
            logger.warning(
                "Teacher credentials file at %s has invalid structure (expected a list, got %s). "
                "All teacher login attempts will fail. "
                "Please ensure the file contains a JSON array of teacher credentials.",
                path, type(data).__name__
            )
            return {}
        
        # Build credentials dict with validation
        credentials = {}
        for entry in data:
            if not isinstance(entry, dict):
                logger.warning(
                    "Teacher credentials file at %s contains invalid entry (expected dict, got %s). "
                    "Skipping invalid entry.",
                    path, type(entry).__name__
                )
                continue
            if "username" not in entry or "password" not in entry:
                logger.warning(
                    "Teacher credentials file at %s contains entry missing required fields (username and/or password). "
                    "Skipping invalid entry.",
                    path
                )
                continue
            
            # Validate that username and password are non-empty strings
            username = entry["username"]
            password = entry["password"]
            if not isinstance(username, str) or not isinstance(password, str):
                logger.warning(
                    "Teacher credentials file at %s contains entry with non-string username or password (username type: %s, password type: %s). "
                    "Skipping invalid entry.",
                    path, type(username).__name__, type(password).__name__
                )
                continue
            
            # Strip whitespace and validate non-empty
            username = username.strip()
            password = password.strip()
            if not username or not password:
                logger.warning(
                    "Teacher credentials file at %s contains entry with empty or whitespace-only username or password. "
                    "Skipping invalid entry.",
                    path
                )
                continue
            
            credentials[username] = password
        
        return credentials
    except json.JSONDecodeError as e:
        logger.warning(
            "Teacher credentials file at %s is malformed and cannot be parsed: %s. "
            "All teacher login attempts will fail. "
            "Please fix the JSON syntax to enable admin functionality.",
            path, e
        )
        return {}
    except Exception:
        logger.exception(
            "Failed to load teacher credentials from %s. "
            "All teacher login attempts will fail.",
            path
        )
        return {}


teachers_path = current_dir / "teachers.json"
teacher_credentials = load_teachers(teachers_path)

# JWT configuration
# JWT_SECRET_KEY must be set as an environment variable for secure token signing
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError(
        "JWT_SECRET_KEY environment variable is required. "
        "Please set it to a secure random string. "
        "You can generate one using: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
    )
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# JWT Token Revocation Manager
# Singleton class for tracking revoked tokens with automatic expiration cleanup
#
# Limitations:
# - Uses in-memory storage (not shared across multiple worker processes)
# - Revoked tokens are lost on application restart
# - Each worker process maintains its own revocation list
#
# For production multi-process deployments, consider:
# - Redis with TTL support (recommended for horizontal scaling)
# - Shared database with indexed expiration timestamps
# - Distributed cache systems (Memcached, etc.)
#
# Thread-Safety:
# - Singleton creation uses dedicated _instance_lock (one-time operation)
# - Runtime operations use separate _tokens_lock (prevents creation contention)

class TokenRevocationManager:
    """
    Singleton for managing JWT token revocation with automatic TTL-based cleanup.
    
    IMPORTANT: In-memory storage only - not suitable for multi-process deployments.
    See block comment above for limitations and production alternatives.
    """
    
    # Class-level attributes for singleton pattern
    _instance = None
    _instance_lock = threading.Lock()
    
    def __new__(cls):
        """Ensure only one instance exists (singleton pattern)."""
        if cls._instance is None:
            with cls._instance_lock:
                # Double-check after acquiring lock (another thread may have created it)
                if cls._instance is None:
                    instance = super().__new__(cls)
                    # Initialize all instance attributes atomically while holding the lock
                    instance._revoked_tokens = {}
                    instance._cleanup_counter = 0
                    instance._cleanup_threshold = 100  # Cleanup every N checks
                    instance._tokens_lock = threading.Lock()
                    cls._instance = instance
        return cls._instance
    
    def is_revoked(self, jti: str) -> bool:
        """Check if a token has been revoked."""
        with self._tokens_lock:
            # Increment counter and trigger cleanup if threshold reached
            self._cleanup_counter += 1
            if self._cleanup_counter >= self._cleanup_threshold:
                self._cleanup_counter = 0
                self._cleanup_expired()
            
            return jti in self._revoked_tokens
    
    def revoke(self, jti: str, expiration_time: int) -> None:
        """Revoke a token by storing its JTI with expiration time."""
        with self._tokens_lock:
            self._revoked_tokens[jti] = expiration_time
    
    def _cleanup_expired(self) -> None:
        """Remove expired tokens from the revocation list."""
        now = int(datetime.now(timezone.utc).timestamp())
        expired = [jti for jti, exp in self._revoked_tokens.items() if exp <= now]
        for jti in expired:
            del self._revoked_tokens[jti]
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about the revocation manager."""
        with self._tokens_lock:
            return {
                "total_revoked": len(self._revoked_tokens)
            }


# Singleton instance for tracking revoked JWT tokens
# Automatically cleans up expired tokens every 100 checks to prevent memory growth
revocation_manager = TokenRevocationManager()


def require_teacher(token: str | None) -> tuple[str, str, int]:
    """Validate JWT token and return (username, jti, exp)."""
    if not token:
        raise HTTPException(status_code=401, detail="Teacher login required")
    
    try:
        # Decode and verify JWT signature and expiration
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        exp: int = payload.get("exp")
        
        # Ensure all required claims are present
        if username is None or jti is None or exp is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Check if token has been explicitly revoked (e.g., via logout)
        if revocation_manager.is_revoked(jti):
            raise HTTPException(status_code=401, detail="Invalid token")
            
        return username, jti, exp
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "GitHub Skills": {
        "description": "Learn practical coding and collaboration skills with GitHub",
        "schedule": "Wednesdays, 3:30 PM - 4:30 PM",
        "max_participants": 25,
        "participants": []
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/auth/login")
def login(request: LoginRequest):
    # Retrieve the stored password hash for the username
    stored_password_hash = teacher_credentials.get(request.username)
    
    # Use a dummy hash for invalid usernames to prevent timing attacks
    # This ensures pwd_context.verify() is always called, maintaining constant time
    # regardless of whether the username exists. Without this, an attacker could
    # measure response times to enumerate valid usernames.
    dummy_hash = "$2b$12$YVp7allSvMoMAAfCeMBxy.5dAqb0StaIo8x/f2m8IhJm/zB8FVrbq"
    hash_to_verify = stored_password_hash if stored_password_hash else dummy_hash
    
    # Validate credentials using constant-time hash verification
    # The verify() method uses constant-time comparison internally to prevent
    # timing attacks that could reveal information about the password.
    try:
        is_valid = pwd_context.verify(request.password, hash_to_verify)
    except (ValueError, passlib_exc.UnknownHashError):
        # Handle malformed or non-bcrypt hashes in teachers.json
        # Log a warning if the stored hash is invalid (but not for dummy hash failures)
        if stored_password_hash:
            logger.warning("Invalid password hash detected for user %s", request.username)
        is_valid = False
    
    # Only proceed if both username exists AND password is valid
    if not stored_password_hash or not is_valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create JWT token with expiration and unique JTI
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta
    jti = secrets.token_urlsafe(32)  # Generate unique token ID
    to_encode = {"sub": request.username, "exp": int(expire.timestamp()), "jti": jti}
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return {"token": token, "username": request.username}


@app.post("/auth/logout")
def logout(token: str | None = Header(None, alias="X-Teacher-Token")):
    # Validate the token and get the JTI and expiration time
    _, jti, exp_time = require_teacher(token)
    
    # Revoke the token using the singleton manager
    revocation_manager.revoke(jti, exp_time)
    
    return {"message": "Logged out successfully"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str,
    token: str | None = Header(None, alias="X-Teacher-Token")
):
    """Sign up a student for an activity"""
    _, _, _ = require_teacher(token)
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str,
    token: str | None = Header(None, alias="X-Teacher-Token")
):
    """Unregister a student from an activity"""
    _, _, _ = require_teacher(token)
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
