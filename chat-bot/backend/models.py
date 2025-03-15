from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from backend.database import Base
import uuid
from datetime import datetime

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    hashed_password = Column(String)

    conversations = relationship('Conversation', back_populates='user')

class Conversation(Base):
    __tablename__ = 'conversations'  # Fixed missing '__tablename__'

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey('users.id'))
    title = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship('User', back_populates='conversations')
    messages = relationship('Message', back_populates='conversation')

class Message(Base):
    __tablename__ = 'messages'

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    conversation_id = Column(String, ForeignKey('conversations.id'))
    sender = Column(String)  # either "user" or "bot"
    text = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    conversation = relationship('Conversation', back_populates='messages')
