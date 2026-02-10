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

class TokenRevocationManager:
    """
    Singleton class for managing JWT token revocation with automatic TTL-based cleanup.
    
    This class provides thread-safe token revocation tracking with automatic cleanup of 
    expired tokens to prevent unbounded memory growth.
    
    IMPORTANT: This implementation uses in-memory storage and is NOT suitable for 
    multi-process deployments (e.g., multiple Uvicorn workers). For production use 
    with multiple processes, integrate with a shared data store like Redis.
    
    Limitations:
    - Token revocations are not shared across multiple process instances
    - Revoked tokens are lost on application restart
    - Each worker process maintains its own revocation list
    
    For production multi-process deployments, consider:
    - Redis with TTL support (recommended)
    - Shared database with expiration timestamps
    - Distributed cache systems
    
    Thread-Safety:
    - Singleton instantiation uses a dedicated class-level lock (_instance_lock)
    - Runtime operations (is_revoked, revoke, get_stats) use a separate instance-level lock (_tokens_lock)
    - This separation prevents singleton creation from contending with runtime token operations
    - All public methods are thread-safe; no external synchronization required
    
    Example Usage:
        # Check if a token is revoked during authentication
        if revocation_manager.is_revoked(jti):
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Revoke a token on logout
        revocation_manager.revoke(jti, expiration_time)
        
        # Get statistics for monitoring
        stats = revocation_manager.get_stats()
        print(f"Currently tracking {stats['total_revoked']} revoked tokens")
    """
    
    # Class-level attributes for singleton pattern
    _instance = None  # Holds the single instance of this class
    _instance_lock = threading.Lock()  # Protects singleton creation from race conditions
    
    def __new__(cls):
        """
        Ensure only one instance exists (singleton pattern).
        
        Uses double-checked locking to minimize lock contention while preventing
        race conditions during initialization. All instance attributes are initialized
        atomically within the lock to ensure thread-safety.
        
        Returns:
            The singleton instance of TokenRevocationManager
        
        Note:
            Initialization in __new__ rather than __init__ prevents race conditions
            where multiple threads could partially initialize the same instance.
        """
        if cls._instance is None:
            with cls._instance_lock:
                # Double-check after acquiring lock (another thread may have created it)
                if cls._instance is None:
                    instance = super().__new__(cls)
                    # Initialize all instance attributes atomically while holding the lock
                    # to prevent race conditions where another thread could access a
                    # partially initialized instance
                    instance._revoked_tokens = {}  # Maps JTI -> expiration timestamp
                    instance._cleanup_counter = 0  # Tracks number of checks since last cleanup
                    instance._cleanup_threshold = 100  # Cleanup every N checks to balance overhead vs memory
                    instance._tokens_lock = threading.Lock()  # Instance-level lock for runtime operations
                    cls._instance = instance
        return cls._instance
    
    def is_revoked(self, jti: str) -> bool:
        """
        Check if a token (identified by JTI) has been revoked.
        
        This method also performs periodic cleanup of expired tokens to prevent
        unbounded memory growth. Cleanup occurs every 100 calls to balance the
        overhead of cleanup operations with memory efficiency.
        
        Args:
            jti: The unique token identifier (JTI claim from JWT)
        
        Returns:
            True if the token has been revoked, False otherwise
        
        Performance:
            - O(1) lookup for revocation check
            - O(n) cleanup operation every 100 calls, where n is the number of revoked tokens
            - Lock acquisition on every call may become a bottleneck under extreme load
        """
        with self._tokens_lock:
            # Increment counter and trigger cleanup if threshold reached
            # This amortizes the cost of cleanup across multiple checks
            self._cleanup_counter += 1
            if self._cleanup_counter >= self._cleanup_threshold:
                self._cleanup_counter = 0
                self._cleanup_expired()
            
            # Fast O(1) lookup to check if token is in revoked set
            return jti in self._revoked_tokens
    
    def revoke(self, jti: str, expiration_time: int) -> None:
        """
        Revoke a token by storing its JTI with expiration time.
        
        The expiration time is stored so that expired tokens can be automatically
        cleaned up later, preventing unbounded memory growth. Tokens are not removed
        immediately upon expiration but during periodic cleanup operations.
        
        Args:
            jti: The unique token identifier (JTI claim from JWT)
            expiration_time: Unix timestamp (seconds since epoch) when the token expires
        
        Note:
            If the same JTI is revoked multiple times, the latest expiration time
            will be used (dict update behavior).
        """
        with self._tokens_lock:
            self._revoked_tokens[jti] = expiration_time
    
    def _cleanup_expired(self) -> None:
        """
        Remove expired tokens from the revocation list.
        
        This internal method scans all revoked tokens and removes those whose
        expiration time has passed. This prevents the revoked token list from
        growing indefinitely.
        
        This method should only be called while holding self._tokens_lock to ensure
        thread-safe modification of _revoked_tokens.
        
        Complexity:
            O(n) where n is the number of revoked tokens. This is acceptable since
            it's only called periodically (every 100 checks).
        
        Note:
            We build a list of expired JTIs first, then delete them to avoid
            modifying the dictionary while iterating over it.
        """
        now = int(datetime.now(timezone.utc).timestamp())
        # Find all tokens whose expiration time has passed
        expired = [jti for jti, exp in self._revoked_tokens.items() if exp <= now]
        # Remove expired tokens from the revocation list
        for jti in expired:
            del self._revoked_tokens[jti]
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get statistics about the revocation manager.
        
        Useful for monitoring and debugging to understand how many tokens
        are currently being tracked as revoked.
        
        Returns:
            Dictionary with 'total_revoked' count representing the number of
            currently tracked revoked tokens (includes both expired and non-expired)
        
        Note:
            The count includes tokens that have expired but haven't been cleaned up yet.
            The actual number of active revoked tokens may be lower after cleanup.
        """
        with self._tokens_lock:
            return {
                "total_revoked": len(self._revoked_tokens)
            }


# Initialize the singleton instance of TokenRevocationManager
# This instance is shared across all authentication operations in this process.
# It provides a centralized, thread-safe way to track revoked JWTs with automatic cleanup.
#
# Usage throughout the application:
#   - require_teacher() uses revocation_manager.is_revoked() to check tokens
#   - logout() uses revocation_manager.revoke() to revoke tokens
#
# Memory Management:
#   The manager automatically cleans up expired tokens every 100 authentication checks,
#   preventing unbounded memory growth while minimizing cleanup overhead.
revocation_manager = TokenRevocationManager()


def require_teacher(token: str | None) -> tuple[str, str, int]:
    """
    Validate JWT token and return (username, jti, exp).
    
    This function performs complete JWT validation including:
    1. Token presence check
    2. JWT signature and expiration verification
    3. Required claims validation (sub, jti, exp)
    4. Revocation status check
    
    Args:
        token: JWT token string from X-Teacher-Token header
    
    Returns:
        Tuple of (username, jti, expiration_time) if token is valid
    
    Raises:
        HTTPException: 401 if token is missing, invalid, expired, or revoked
    """
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
        # This prevents revoked tokens from being used even if not yet expired
        if revocation_manager.is_revoked(jti):
            raise HTTPException(status_code=401, detail="Invalid token")
            
        return username, jti, exp
    except JWTError:
        # Handle any JWT-related errors (malformed, expired, invalid signature, etc.)
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
    is_valid = pwd_context.verify(request.password, hash_to_verify)
    
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
    """
    Log out a teacher by revoking their JWT token.
    
    This endpoint adds the token's JTI (unique identifier) to the revocation list,
    preventing it from being used for future authenticated requests. The token
    remains revoked until its natural expiration time, after which it's automatically
    cleaned up to save memory.
    
    Args:
        token: JWT token from X-Teacher-Token header
    
    Returns:
        Success message confirming logout
    
    Raises:
        HTTPException: 401 if token is missing, invalid, or already revoked
    
    Note:
        After logout, the client should clear the token from localStorage to
        complete the logout process on the frontend.
    """
    # Validate the token and extract JTI and expiration time
    # This ensures only valid tokens can be revoked (prevents abuse)
    _, jti, exp_time = require_teacher(token)
    
    # Add token to revocation list with its expiration time for automatic cleanup
    # The expiration time allows the manager to remove this entry once the token
    # would have expired anyway, preventing unbounded memory growth
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
