from fastapi import FastAPI, Depends, HTTPException, status, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import bcrypt, jwt, os, uuid
from dotenv import load_dotenv
from pydantic import BaseModel
import google.generativeai as genai
from backend.models import User, Conversation, Message
from backend.database import engine, SessionLocal
from fastapi import FastAPI, UploadFile, File, Form, Depends
from backend.models import Conversation, Message
from backend.database import SessionLocal
from google.generativeai import GenerativeModel
import google.generativeai as genai
import os

print(engine)


load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
app = FastAPI()


# Mount static files and serve index.html on the root route
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def read_root():
    return FileResponse("static/index.html")


# Enable CORS for all origins (adjust for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


JWT_SECRET = os.getenv("JWT_SECRET_KEY")


# Dependency: get a DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Generate unique UUID
def generate_uuid():
    return str(uuid.uuid4())


# Create and decode JWT tokens
def create_jwt(user_id: int):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def decode_jwt(token: str):
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if decoded_token['exp'] < datetime.utcnow().timestamp():
            return None
        return decoded_token
    except jwt.PyJWTError:
        return None


# Dependency: extract current user from Authorization header
def get_current_user(Authorization: str = Header(...)):
    print(datetime.now())
    token = Authorization.split(" ")[1]
    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return payload['user_id']


# Pydantic models
class UserSignup(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class MessageRequest(BaseModel):
    conversation_id: str
    sender: str
    message_text: str

CHATBOT_PROMPT = """
You are Tatva Assistant integrated into the Tatva AI Chat App. I'm here to help you have enjoyable and productive conversations! 😄🎉

What you can do for :
- Answer questions, solve problems, and explain concepts clearly.
- Provide concise, accurate, and practical information.
- Engage in casual, friendly interactions with playful Unicode emojis! 

Interaction guidelines:
- You'll format responses clearly using markdown:
  - **Bold**, *Italics*, `Code snippets`, > Quotes, and ||Spoiler tags||.
- You'll reply concise and clear messages for better understanding.
- You'll ask questions or provide context to guide the conversation.
- Most responses should be under 100 words for readability.    

Important notes:
- You don't handle sensitive topics (violence, self-harm, drugs, gambling, etc.).
- You'll always clarify if a request is beyond my capabilities.
- You won't answer queries related to gambling.

Let's have fun and productive chats together!
"""

# ---------------------------
# User Endpoints
# ---------------------------
@app.post("/api/signup", status_code=status.HTTP_201_CREATED)
def signup(user_data: UserSignup, db: Session = Depends(get_db)):
    print(datetime.now())
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email already exists")
    hashed_pw = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt())
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pw.decode('utf-8')
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"id": new_user.id, "username": new_user.username, "email": new_user.email}


@app.post("/api/login")
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    print(datetime.now())
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not bcrypt.checkpw(login_data.password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_jwt(user.id)
    return {"user_id": user.id, "token": token}


@app.get("/users/{user_id}")
def get_user(user_id: int, current_user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    print(datetime.now())
    if user_id != current_user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized access")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.id, "username": user.username, "email": user.email}


# ---------------------------
# Conversation Endpoints
# ---------------------------
# Always create a new conversation (no check for an existing "New Conversation")
@app.post("/conversations/create")
def create_conversation(db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user)):
    print(datetime.now())
    new_conv = Conversation(user_id=current_user_id, title="Untitled")
    db.add(new_conv)
    db.commit()
    db.refresh(new_conv)
    return {"conversation_id": new_conv.id, "title": new_conv.title, "message": "New conversation created."}


# --- Modified Here: Sorted from recent to old (order by created_at descending) ---
@app.get("/conversations")
def get_conversations(user_id: int, fields: str = Query(None), current_user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    print(datetime.now())
    if user_id != current_user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized access")
    conversations_query = db.query(Conversation).filter(Conversation.user_id == user_id).order_by(Conversation.created_at.desc())
    if fields == "title":
        conversations = conversations_query.with_entities(Conversation.id, Conversation.title).all()
        return [{"conversation_id": conv.id, "title": conv.title or "Untitled"} for conv in conversations]
    conversations = conversations_query.all()
    result = [{"conversation_id": conv.id, "title": conv.title or "Untitled", "created_at": conv.created_at} for conv in conversations]
    return result


@app.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str, current_user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    print(datetime.now())
    conversation = db.query(Conversation).filter(Conversation.id == conversation_id, Conversation.user_id == current_user_id).first()
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found or access denied")
    messages = [{"sender": msg.sender, "text": msg.text, "timestamp": msg.timestamp} for msg in conversation.messages]
    return {"conversation_id": conversation_id, "title": conversation.title, "messages": messages}


# ---------------------------
# Messaging Endpoint (Streaming LLM Response)
# ---------------------------
@app.post("/messages")
def send_message(message_data: MessageRequest, current_user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    
    # Fetch the conversation from DB
    conversation = db.query(Conversation).filter(
        Conversation.id == message_data.conversation_id, 
        Conversation.user_id == current_user_id
    ).first()

    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found or access denied")

    # Create the user's message
    user_message = Message(
        id=str(uuid.uuid4()),
        conversation_id=conversation.id,
        sender="user",
        text=message_data.message_text
    )
    db.add(user_message)
    db.commit()

    # Rebuild conversation prompt from previous messages
    conversation_messages = db.query(Message).filter(
        Message.conversation_id == conversation.id
    ).order_by(Message.timestamp).all()

    #conversation_messages=CHATBOT_PROMPT+conversation_messages

    prompt ="system: "+CHATBOT_PROMPT+ "\n".join([f"{msg.sender}: {msg.text}" for msg in conversation_messages])
    
    # Generator function to stream response
    def stream_llm_response():
        try:
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            model = genai.GenerativeModel('gemini-2.0-flash')
            response_stream = model.generate_content(prompt, stream=True)

            full_response = ""
            for chunk in response_stream:
                text_chunk = chunk.text
                full_response += text_chunk
                yield text_chunk  # yield chunk by chunk immediately

            # After streaming ends, save bot response to DB
            bot_message = Message(
                id=str(uuid.uuid4()),
                conversation_id=message_data.conversation_id,
                sender="bot",
                text=full_response  # Use correctly accumulated text
            )
            db.add(bot_message)
            db.commit()

        except Exception as e:
            error_message = f"\n[Error generating response: {str(e)}]"
            yield error_message

    # Return a StreamingResponse
    return StreamingResponse(stream_llm_response(), media_type="text/plain")