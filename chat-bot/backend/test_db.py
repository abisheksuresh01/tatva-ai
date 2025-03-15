import os
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from pymongo import MongoClient
from dotenv import load_dotenv
from backend.models import User
from backend.database import engine, Base



load_dotenv()

# Initialize SQLAlchemy session
Session = sessionmaker(bind=engine)

# MongoDB Setup
mongo_client = MongoClient(os.getenv("MONGODB_URL"))
chat_collection = mongo_client.chat_history.messages

# Create tables
Base.metadata.create_all(bind=engine)

def store_user(username, email, password):
    session = Session()
    new_user = User(username=username, email=email, password=password)
    try:
        session.add(new_user)
        session.commit()
        print(f"User '{username}' registered successfully.")
    except IntegrityError as e:
        session.rollback()
        print(f"Integrity error: {e}")
    finally:
        session.close()

def store_chat_message(user_id, message, response):
    chat_document = {
        "user_id": user_id,
        "message": message,
        "response": response
    }
    chat_collection = MongoClient(os.getenv("MONGODB_URL")).chat_history.messages
    result = chat_collection.insert_one(chat_document)
    if result.inserted_id:
        print("Chat message stored successfully.")
    else:
        print("Failed to store chat message.")

if __name__ == "__main__":
    session = Session()
    user = User(username="testuser", email="test@example.com", password="password123")
    session.add(user)
    try:
        session.commit()
        print("User registered successfully.")
    except Exception as e:
        session.rollback()
        print(f"Error registering user: {e}")

    chat_document = {
        "user_id": user.id,
        "message": "Hello",
        "response": "Hi, how can I help?"
    }
    result = chat_collection.insert_one(chat_document)
    if result.inserted_id:
        print("Chat message stored successfully.")