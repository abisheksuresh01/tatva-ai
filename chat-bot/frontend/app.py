import streamlit as st
import requests
import os
from dotenv import load_dotenv

# Load environment variables and set backend URL
load_dotenv()
BACKEND_URL = "http://localhost:8000"


# Set page configuration once at the very top
st.set_page_config(page_title="Tatva", layout="wide", initial_sidebar_state="expanded")



# Hide default multipage navigation and sidebar initially
if "token" not in st.session_state:
    st.markdown("""
    <style>
    [data-testid="stSidebarNav"],
    [data-testid="stSidebar"] {
        display: none;
    }
    </style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <style>
    [data-testid="stSidebarNav"] { display: none; }
    html, body, [class*="css"] {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    </style>
    """, unsafe_allow_html=True)

# Cached API calls
@st.cache_data(ttl=300)
def fetch_user(user_id, token):
    res = requests.get(f"{BACKEND_URL}/users/{user_id}", headers={"Authorization": f"Bearer {token}"})
    return res.json() if res.ok else {}

@st.cache_data(ttl=120)
def fetch_conversations(user_id, token):
    res = requests.get(f"{BACKEND_URL}/conversations", params={"user_id": user_id, "fields": "title"}, headers={"Authorization": f"Bearer {token}"})
    return res.json() if res.ok else []

#@st.cache_data(ttl=60)
def fetch_conversation_details(conversation_id, token):
    res = requests.get(f"{BACKEND_URL}/conversations/{conversation_id}", headers={"Authorization": f"Bearer {token}"})
    return res.json() if res.ok else {}

# Authentication Check
if "token" not in st.session_state:
    st.title("Chat with Tatva")
    auth_mode = st.radio("Select Action", ["Login", "Signup"], index=0)

    if auth_mode == "Login":
        st.header("Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            res = requests.post(f"{BACKEND_URL}/api/login", json={"username": username, "password": password})
            if res.ok:
                data = res.json()
                st.session_state.token = data["token"]
                st.session_state.user_id = data["user_id"]
                st.experimental_rerun()
            else:
                st.error("Invalid credentials")
    else:
        st.header("Signup")
        username = st.text_input("Username", key="signup_username")
        email = st.text_input("Email", key="signup_email")
        password = st.text_input("Password", type="password", key="signup_password")
        if st.button("Signup"):
            res = requests.post(f"{BACKEND_URL}/api/signup", json={"username": username, "email": email, "password": password})
            if res.ok:
                st.success("Signup successful! Please login.")
            else:
                st.error(f"Signup failed: {res.text}")
    st.stop()

# Sidebar after login
headers = {"Authorization": f"Bearer {st.session_state.token}"}
user_id = st.session_state.user_id


def logout():
    st.session_state.clear()
    st.experimental_rerun()

# Sidebar menu
#st.sidebar.header("Menu")
st.sidebar.button("Logout", on_click=logout)

user = fetch_user(user_id, st.session_state.token)
st.sidebar.write(f"Welcome, {user.get('username', 'User')} 👋")

# New conversation button
if st.sidebar.button("➕ New Conversation"):
    create_res = requests.post(f"{BACKEND_URL}/conversations/create", headers=headers)
    if create_res.ok:
        st.session_state.conversation_id = create_res.json()["conversation_id"]
        st.experimental_rerun()
    else:
        st.sidebar.error("Failed to create a new conversation.")

# Sidebar conversation list
conversations = fetch_conversations(user_id, st.session_state.token)
for conv in conversations:
    title = conv["title"] or "Untitled"
    if st.sidebar.button(title, key=conv["conversation_id"]):
        st.session_state.conversation_id = conv["conversation_id"]
        st.experimental_rerun()

# Main chat window
if "conversation_id" in st.session_state:
    conv_id = st.session_state.conversation_id
    conversation_data = fetch_conversation_details(conv_id, st.session_state.token)
    st.header(f"{conversation_data.get('title', 'Untitled')}")
    for msg in conversation_data.get("messages", []):
        with st.chat_message(msg["sender"]):
            st.write(msg["text"])

# Chat input and sending
prompt = st.chat_input("Type your message here...")
if prompt:
    with st.chat_message("user"):
        st.write(prompt)
    response = requests.post(f"{BACKEND_URL}/messages", json={"conversation_id": st.session_state.conversation_id, "sender": "user", "message_text": prompt}, headers=headers)
    #st.experimental_rerun()

    with st.chat_message("bot"):
        message_placeholder = st.empty()
        full_response = ""
        for chunk in response.iter_content(chunk_size=None, decode_unicode=True):
            if chunk:
                full_response += chunk
                message_placeholder.markdown(full_response + "▌")
        message_placeholder.markdown(full_response)

    
