import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from pymongo import MongoClient

# Load environment variables from .env file
load_dotenv()

# ---------------------------
# PostgreSQL Setup & Clearing
# ---------------------------
DATABASE_URL = os.getenv("POSTGRES_URL")
if not DATABASE_URL:
    raise ValueError("POSTGRES_URL not set in environment variables.")

# Create the engine and session
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

def clear_postgres_data():
    """
    Clears all data from the PostgreSQL tables.
    The tables are truncated with RESTART IDENTITY and CASCADE to handle
    foreign key constraints properly.
    """
    truncate_query = text("TRUNCATE TABLE messages, conversations, users RESTART IDENTITY CASCADE;")
    with engine.connect() as connection:
        trans = connection.begin()
        try:
            connection.execute(truncate_query)
            trans.commit()
            print("PostgreSQL data cleared successfully.")
        except Exception as e:
            trans.rollback()
            print("Error clearing PostgreSQL data:", e)

# ---------------------------
# MongoDB Setup & Clearing
# ---------------------------
MONGODB_URL = os.getenv("MONGODB_URL")
if not MONGODB_URL:
    raise ValueError("MONGODB_URL not set in environment variables.")

mongo_client = MongoClient(MONGODB_URL)

def clear_mongodb_data():
    """
    Clears all documents from the MongoDB 'messages' collection
    in the 'chat_history' database.
    """
    try:
        db = mongo_client.chat_history
        result = db.messages.delete_many({})
        print(f"MongoDB: Deleted {result.deleted_count} documents from 'chat_history.messages'.")
    except Exception as e:
        print("Error clearing MongoDB data:", e)

# ---------------------------
# Main execution
# ---------------------------
if __name__ == "__main__":
    clear_postgres_data()
    clear_mongodb_data()
