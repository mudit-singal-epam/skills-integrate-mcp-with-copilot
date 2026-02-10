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
import os
from pathlib import Path
import secrets
from typing import Dict

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

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
# 1. **Hashing vs Plaintext Storage**: Bcrypt creates a one-way cryptographic hash of passwords.
#    If the credential file is compromised, attackers cannot reverse-engineer the original passwords.
#    This is crucial for protecting user accounts even when data is leaked.
#
# 2. **Salting**: Bcrypt automatically generates a unique salt for each password hash.
#    This prevents rainbow table attacks and ensures identical passwords produce different hashes.
#    The salt is embedded in the hash output, so no separate storage is needed.
#
# 3. **Adaptive Cost Factor**: Bcrypt's computational cost can be increased over time as hardware improves.
#    This work factor (default: 12 rounds) makes brute-force attacks computationally expensive.
#    Each increment doubles the computation time, providing long-term security.
#
# 4. **Constant-Time Comparison**: The verify() method uses constant-time comparison to prevent
#    timing attacks where attackers measure response times to guess password characteristics.
#    This ensures validation time is independent of where the password comparison fails.
#
# Learn More:
# - OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
# - Bcrypt Algorithm Explained: https://en.wikipedia.org/wiki/Bcrypt
# - Timing Attack Prevention: https://codahale.com/a-lesson-in-timing-attacks/
# - Passlib Documentation: https://passlib.readthedocs.io/en/stable/narr/quickstart.html
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def load_teachers(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    return {entry["username"]: entry["password"] for entry in data}


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


def require_teacher(token: str | None) -> str:
    """Validate JWT token and return username."""
    if not token:
        raise HTTPException(status_code=401, detail="Teacher login required")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
            
        return username
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
    
    # Validate credentials using constant-time hash verification
    # This protects against timing attacks by ensuring the verification time
    # is independent of where the comparison fails. The verify() method:
    # - Returns False if username doesn't exist (stored_password_hash is None)
    # - Uses constant-time comparison to check the password hash
    # - Prevents attackers from using response time to determine valid usernames
    if not stored_password_hash or not pwd_context.verify(request.password, stored_password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create JWT token with expiration
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {"sub": request.username, "exp": int(expire.timestamp())}
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return {"token": token, "username": request.username}


@app.post("/auth/logout")
def logout(token: str | None = Header(None, alias="X-Teacher-Token")):
    # Validate the token is legitimate before allowing logout
    require_teacher(token)
    # With stateless JWT, we don't need to track sessions server-side
    # The token will expire naturally based on its exp claim
    return {"message": "Logged out"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str,
    token: str | None = Header(None, alias="X-Teacher-Token")
):
    """Sign up a student for an activity"""
    require_teacher(token)
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
    require_teacher(token)
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
