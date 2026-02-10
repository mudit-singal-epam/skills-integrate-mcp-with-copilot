# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Authenticate users with roles (student, staff, admin)
- Sign up for activities (students can only register themselves; staff/admin can register anyone)

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Review the sample users in `users.json` (username, password, role, email).

3. Run the application:

   ```
   python app.py
   ```

4. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/auth/login`                                                     | Log in and receive an auth token                                    |
| POST   | `/auth/logout`                                                    | Log out and revoke the auth token                                   |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up for an activity (requires auth token)                       |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Unregister from an activity (requires auth token)                |

### Authentication

1. Call `/auth/login` with JSON body `{ "username": ..., "password": ... }`.
2. Use the returned token in the `X-User-Token` header for write requests.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Users** - Uses username as identifier:
   - Password
   - Role
   - Email

All data is stored in memory, which means data will be reset when the server restarts.
