from database import engine
from models import Base

def init_db():
    Base.metadata.create_all(bind=engine)
    print("Database tables cexirtreated successfully.")

if __name__ == "__main__":
    init_db()
