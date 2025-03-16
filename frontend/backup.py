














import streamlit as st
import requests
import os
from dotenv import load_dotenv
import google.generativeai as genai

# Set page configuration at the very top
st.set_page_config(page_title="Chat App", layout="wide", initial_sidebar_state="collapsed")

# Hide the default multipage navigation in the sidebar
hide_sidebar_style = """
    <style>
    [data-testid="stSidebarNav"] { display: none; }
    </style>
"""
st.markdown(hide_sidebar_style, unsafe_allow_html=True)

# Load environment variables and set backend URL
load_dotenv()
BACKEND_URL = "http://localhost:8000"

# Prompt engineering for chatbot efficiency

# -------------------- Authentication Flow -------------------- #
if "token" not in st.session_state:
    st.title("Welcome to Chat App")
    auth_mode = st.radio("Select Action", ["Login", "Signup"], index=0)

    if auth_mode == "Login":
        st.header("Login 🔑")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            res = requests.post(f"{BACKEND_URL}/api/login", json={
                "username": username,
                "password": password
            })
            if res.ok:
                data = res.json()
                st.session_state.token = data["token"]
                st.session_state.user_id = data["user_id"]
                st.success("Login successful!")
                st.experimental_rerun()
            else:
                st.error("Invalid credentials")
    else:
        st.header("Signup")
        username = st.text_input("Username", key="signup_username")
        email = st.text_input("Email", key="signup_email")
        password = st.text_input("Password", type="password", key="signup_password")
        if st.button("Signup"):
            res = requests.post(f"{BACKEND_URL}/api/signup", json={
                "username": username,
                "email": email,
                "password": password
            })
            if res.ok:
                st.success("Signup successful! Please login.")
                st.experimental_rerun()
            else:
                st.error(f"Signup failed: {res.text}")

# -------------------- Chat Interface -------------------- #
else:
    # Configure Gemini API and set authorization headers
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    user_id = st.session_state.user_id

    # Sidebar: Logout button
    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.experimental_rerun()

    # Sidebar: Display user greeting
    user_res = requests.get(f"{BACKEND_URL}/users/{user_id}", headers=headers)
    if user_res.ok:
        user = user_res.json()
        st.sidebar.header(f"Welcome, {user['username']} 👋")
    else:
        st.error("Could not fetch user details.")

    # Sidebar: "New Conversation" button creates a fresh conversation and loads it immediately
    if st.sidebar.button("✏️ New Conversation"):
        create_conv_res = requests.post(f"{BACKEND_URL}/conversations/create", headers=headers)
        if create_conv_res.ok:
            new_conv = create_conv_res.json()
            st.session_state.conversation_id = new_conv["conversation_id"]
            st.experimental_rerun()  # Immediately open the new conversation window
        else:
            st.sidebar.error("Failed to create a new conversation.")

    # Sidebar: List saved conversations
    conv_res = requests.get(
        f"{BACKEND_URL}/conversations",
        params={"user_id": user_id, "fields": "title"},
        headers=headers
    )
    if conv_res.ok:
        conversations = conv_res.json()
    else:
        st.error("Could not fetch conversations.")
        conversations = []

    # Build a mapping of conversation_id -> title
    if conversations:
        conversation_options = {conv["conversation_id"]: conv["title"] for conv in conversations}
        conv_ids = list(conversation_options.keys())
        # Use the current conversation_id from session_state if available;
        # otherwise, default to the first conversation in the list.
        if "conversation_id" not in st.session_state or st.session_state.conversation_id not in conv_ids:
            st.session_state.conversation_id = conv_ids[0]
        # Find the index of the current conversation_id so that it is selected by default
        default_index = conv_ids.index(st.session_state.conversation_id)
        selected_conv_id = st.sidebar.selectbox(
            "Your Conversations",
            options=conv_ids,
            index=default_index,
            format_func=lambda key: conversation_options[key]
        )
        # Update the conversation_id if user selects a different conversation
        if selected_conv_id != st.session_state.get("conversation_id"):
            st.session_state.conversation_id = selected_conv_id
    else:
        # If no conversations exist, automatically create one
        create_conv_res = requests.post(f"{BACKEND_URL}/conversations/create", headers=headers)
        if create_conv_res.ok:
            new_conv = create_conv_res.json()
            st.session_state.conversation_id = new_conv["conversation_id"]
            st.experimental_rerun()
        else:
            st.sidebar.error("Failed to create a new conversation.")

    # Main Chat Area: Fetch and display the current conversation details
    conv_id = st.session_state.conversation_id
    conv_detail_res = requests.get(f"{BACKEND_URL}/conversations/{conv_id}", headers=headers)
    if conv_detail_res.ok:
        conversation_data = conv_detail_res.json()
        st.header(f"Chat: {conversation_data.get('title', 'Untitled')}")
        for msg in conversation_data.get("messages", []):
            with st.chat_message(msg["sender"]):
                st.write(msg["text"])
    else:
        st.error("Could not fetch conversation details.")

    # Chat Input: Allow the user to send a new message
    prompt = st.chat_input("Type your message here...")
    if prompt:
        with st.chat_message("user"):
            st.write(prompt)
        # Send the message to the backend with streaming enabled
        response = requests.post(
            f"{BACKEND_URL}/messages",
            json={
                "conversation_id": st.session_state.conversation_id,
                "sender": "user",
                "message_text": prompt
            },
            headers=headers,
            stream=True  # Enable streaming of the response
        )
        if response.status_code == 200:
            bot_message = ""
            # Create a placeholder for streaming response
            message_placeholder = st.empty()
            # Iterate over streamed chunks
            for chunk in response.iter_lines():
                if chunk:
                    text_chunk = chunk.decode('utf-8')
                    bot_message += text_chunk
                    message_placeholder.markdown(bot_message)
        else:
            st.error("Failed to send message.")

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


print(engine)


load_dotenv()
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


# ---------------------------
# User Endpoints
# ---------------------------
@app.post("/api/signup", status_code=status.HTTP_201_CREATED)
def signup(user_data: UserSignup, db: Session = Depends(get_db)):
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
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not bcrypt.checkpw(login_data.password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_jwt(user.id)
    return {"user_id": user.id, "token": token}


@app.get("/users/{user_id}")
def get_user(user_id: int, current_user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
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
    new_conv = Conversation(user_id=current_user_id, title="New Conversation")
    db.add(new_conv)
    db.commit()
    db.refresh(new_conv)
    return {"conversation_id": new_conv.id, "title": new_conv.title, "message": "New conversation created."}


# --- Modified Here: Sorted from recent to old (order by created_at descending) ---
@app.get("/conversations")
def get_conversations(user_id: int, fields: str = Query(None), current_user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
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
    conversation = db.query(Conversation).filter(
        Conversation.id == message_data.conversation_id,
        Conversation.user_id == current_user_id
    ).first()
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found or access denied")
   
    # Update conversation title if still default, using first 50 characters of message
    if conversation.title == "New Conversation":
        conversation.title = message_data.message_text[:50]
   
    # Store the user's message
    user_message = Message(
        id=str(uuid.uuid4()),
        conversation_id=message_data.conversation_id,
        sender=message_data.sender,
        text=message_data.message_text
    )
    db.add(user_message)
    db.commit()
    db.refresh(user_message)
   
    # Build prompt from conversation history
    conversation_messages = db.query(Message).filter(Message.conversation_id == conversation.id).order_by(Message.timestamp).all()
    prompt = ""
    for msg in conversation_messages:
        prompt += f"{msg.sender}: {msg.text}\n"
    prompt += "bot: "
   
    # Generator to stream LLM response
    def stream_llm_response():
        try:
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            model = genai.GenerativeModel('gemini-2.0-flash-thinking-exp-01-21')
            contents = [prompt]
            response_stream = model.generate_content(contents, stream=True)
            llm_text = ""
            for chunk in response_stream:
                llm_text += chunk.text
                yield chunk.text  # Stream each chunk as it arrives
            # After streaming, store the complete bot response
            bot_message = Message(
                id=str(uuid.uuid4()),
                conversation_id=message_data.conversation_id,
                sender="bot",
                text=llm_text
            )
            db.add(bot_message)
            db.commit()
        except Exception as e:
            yield f"\n[Error generating response: {e}]"
   
    return StreamingResponse(stream_llm_response(), media_type="text/plain")