# Tatva AI Chat 

## Description
The Tatva AI Chat App is a web-based chat to talk with AI (using Gemini). It uses PostgreSQL database for data storage.

## Prerequisites
- Python 3.8 or higher
- PostgreSQL
- MongoDB

## Setup Instructions

### 1. Clone Repository
```bash
git clone <repository-url>
cd <project-directory>
```

### 2. Set Up Environment Variables
Create a `.env` file in your project directory and include:
```env
POSTGRES_URL="postgresql://postgres:tiger@localhost:5432/mydb"
GEMINI_API_KEY=<your-gemini-api-key>

JWT_SECRET_KEY=<your-jwt-secret-key>
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Initialize Database
```bash
python init_db.py
```

## Running the Application
Run Backend and Frontend as two separate processes using different terminals.
### Backend (FastAPI)
```bash
uvicorn main:app --reload
```

### Frontend
```bash
streamlit run app.py
```

Open your browser and navigate to `http://localhost:8000` for the backend and `http://localhost:8501` for the frontend interface.

## Additional Utilities

### Clear Database
```bash
python clear_data.py
```

### Database Testing
```bash
python test_db.py
```

## Demo
Refer to the demo video titled "demo" for visual execution guidance.

## Troubleshooting
- **Database Issues:** Ensure PostgreSQL services are active and accessible.
- **Authentication Issues:** Verify JWT secret keys and tokens in your environment configuration.

## Notes
- The application backend defaults to `http://localhost:8000`.
- Ensure the `.env` file is correctly configured.

Enjoy using the Tatva AI!

