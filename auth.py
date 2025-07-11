# auth.py
# ---------------------------------------------
# Handles login validation and session control
# ---------------------------------------------

import streamlit as st
import json
import os

# File to persist session data
SESSION_FILE = "data/session.json"

# Dummy user credentials (extend if needed)
USER_CREDENTIALS = {
    "user@example.com": "password123",
    "admin@mscproject.com": "admin2025"
}

def _persist_session(email):
    """Store session data to file."""
    os.makedirs("data", exist_ok=True)
    with open(SESSION_FILE, "w") as f:
        json.dump({
            "logged_in": True,
            "user_email": email
        }, f)

def _load_persisted_session():
    """Load session state from disk into st.session_state."""
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, "r") as f:
                data = json.load(f)
            # Defensive: ensure keys exist and are valid
            if not isinstance(data, dict) or "logged_in" not in data or "user_email" not in data:
                raise ValueError("Malformed session file.")
            st.session_state["logged_in"] = data.get("logged_in", False)
            st.session_state["user_email"] = data.get("user_email", "")
        except (json.JSONDecodeError, ValueError):
            # If the file is invalid or empty, reset everything
            os.remove(SESSION_FILE)
            st.session_state["logged_in"] = False
            st.session_state["user_email"] = ""
    else:
        st.session_state["logged_in"] = False
        st.session_state["user_email"] = ""

def login():
    """Render login form and handle validation."""
    st.title("🔐 Login to Access the App")

    # Do not reload login if already logged in
    if st.session_state.get("logged_in", False):
        return

    email = st.text_input("Email", placeholder="Enter your email")
    password = st.text_input("Password", type="password", placeholder="Enter your password")

    if st.button("Login"):
        if not email or not password:
            st.warning("⚠️ Both fields are required.")
            return

        if email in USER_CREDENTIALS and USER_CREDENTIALS[email] == password:
            st.success("✅ Login successful!")
            st.session_state["logged_in"] = True
            st.session_state["user_email"] = email
            _persist_session(email)
            st.rerun()
        else:
            st.error("❌ Invalid email or password.")

def protect_route():
    """Prevent access to internal pages if not logged in."""
    if not st.session_state.get("logged_in", False):
        _load_persisted_session()
        if not st.session_state.get("logged_in", False):
            st.warning("⚠️ You must log in to access this page.")
            st.stop()

def logout():
    """Clear session and remove saved file."""
    st.session_state.clear()
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)
    st.success("🚪 Logged out successfully.")
    st.rerun()