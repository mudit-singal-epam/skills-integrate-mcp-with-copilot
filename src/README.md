# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Teacher login for admin actions
- Teacher-only signup/unregister for students (when auth is enabled)
- Read-only mode when `JWT_SECRET_KEY` is not set

## Getting Started

### Prerequisites

Before running the application, you need to set up the following:

#### 1. Environment Variables

The application requires the `JWT_SECRET_KEY` environment variable to be set for secure JWT token signing. This is used for teacher authentication.

**Generate a secure secret key:**

```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

**Set the environment variable:**

- **Linux/Mac:**
  ```bash
  export JWT_SECRET_KEY='your-generated-secret-key-here'
  ```

- **Windows (Command Prompt):**
  ```cmd
  set JWT_SECRET_KEY=your-generated-secret-key-here
  ```

- **Windows (PowerShell):**
  ```powershell
  $env:JWT_SECRET_KEY='your-generated-secret-key-here'
  ```

**Note:** If `JWT_SECRET_KEY` is not set, the application runs in read-only mode. Teacher login and admin actions (signup/unregister) return 503 until the key is configured.

#### 2. Teacher Credentials File

The application requires a `teachers.json` file in the `src` directory for teacher authentication. This file should contain a JSON array of teacher credentials with bcrypt-hashed passwords.

**File location:** `src/teachers.json`

**Format:**
```json
[
  {
    "username": "teacher1",
    "password": "$2b$12$...(bcrypt hash of teacher1's password)..."
  },
  {
    "username": "coach",
    "password": "$2b$12$...(bcrypt hash of coach's password)..."
  }
]
```

**Generate a bcrypt password hash:**

```python
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
hashed_password = pwd_context.hash("your-password-here")
print(hashed_password)
```

**Note:** If the `teachers.json` file is missing or invalid, the application will start but all teacher login attempts will fail. Check the logs for warnings about missing or invalid teacher credentials.

### Installation and Running

1. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

   This will install FastAPI, Uvicorn, python-jose (for JWT), passlib (for bcrypt), and other required dependencies.

2. Set up the environment variables and teachers.json file as described above.

3. Run the application:

   ```bash
   python app.py
   ```

4. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up for an activity                                             |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
