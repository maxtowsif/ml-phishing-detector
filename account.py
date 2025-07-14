# account.py
# ---------------------------------------------------------
# Enhanced Account Management Module
# User registration, password reset, account statistics
# ---------------------------------------------------------

import streamlit as st
import json
import os
import hashlib
import secrets
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# File paths
USERS_FILE = "data/users.json"
PASSWORD_RESETS_FILE = "data/password_resets.json"


def _load_users():
    """Load user data from file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_users(users):
    """Save user data to file."""
    os.makedirs("data", exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def _hash_password(password: str) -> str:
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def _verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash."""
    return _hash_password(password) == hashed


def _generate_reset_token() -> str:
    """Generate a secure reset token."""
    return secrets.token_urlsafe(32)


def _load_password_resets():
    """Load password reset tokens."""
    if os.path.exists(PASSWORD_RESETS_FILE):
        try:
            with open(PASSWORD_RESETS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_password_resets(resets):
    """Save password reset tokens."""
    os.makedirs("data", exist_ok=True)
    with open(PASSWORD_RESETS_FILE, "w") as f:
        json.dump(resets, f, indent=2)


def register_user(email: str, password: str, confirm_password: str, security_question: str, security_answer: str) -> dict:
    """
    Register a new user with security question/answer.
    """
    # Validation
    if not email or not password or not security_question or not security_answer:
        return {"success": False, "message": "All fields are required."}
    if password != confirm_password:
        return {"success": False, "message": "Passwords do not match."}
    if len(password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters long."}
    if "@" not in email or "." not in email:
        return {"success": False, "message": "Please enter a valid email address."}
    users = _load_users()
    if email in users:
        return {"success": False, "message": "User already exists."}
    user_data = {
        "email": email,
        "password_hash": _hash_password(password),
        "security_question": security_question,
        "security_answer_hash": _hash_password(security_answer.strip().lower()),
        "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "last_login": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "role": "user",
        "status": "active"
    }
    users[email] = user_data
    _save_users(users)
    return {"success": True, "message": "Account created successfully!"}


def reset_password(email: str) -> dict:
    """
    Initiate password reset process.
    
    Args:
        email (str): User email
        
    Returns:
        dict: Reset result
    """
    users = _load_users()
    
    if email not in users:
        return {"success": False, "message": "User not found."}
    
    # Generate reset token
    token = _generate_reset_token()
    expiry = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    
    # Save reset token
    resets = _load_password_resets()
    resets[token] = {
        "email": email,
        "expires": expiry,
        "used": False
    }
    _save_password_resets(resets)
    
    # In a real application, you would send an email here
    # For demo purposes, we'll just return the token
    reset_link = f"http://localhost:8501/reset?token={token}"
    
    return {
        "success": True, 
        "message": f"Password reset link sent to {email}",
        "reset_link": reset_link  # For demo purposes
    }


def verify_reset_token(token: str) -> dict:
    """
    Verify password reset token.
    
    Args:
        token (str): Reset token
        
    Returns:
        dict: Verification result
    """
    resets = _load_password_resets()
    
    if token not in resets:
        return {"valid": False, "message": "Invalid reset token."}
    
    reset_data = resets[token]
    
    # Check if token is expired
    expiry = datetime.strptime(reset_data["expires"], '%Y-%m-%d %H:%M:%S')
    if datetime.now() > expiry:
        return {"valid": False, "message": "Reset token has expired."}
    
    # Check if token has been used
    if reset_data["used"]:
        return {"valid": False, "message": "Reset token has already been used."}
    
    return {"valid": True, "email": reset_data["email"]}


def update_password_with_token(token: str, new_password: str) -> dict:
    """
    Update password using reset token.
    
    Args:
        token (str): Reset token
        new_password (str): New password
        
    Returns:
        dict: Update result
    """
    # Verify token
    verification = verify_reset_token(token)
    if not verification["valid"]:
        return {"success": False, "message": verification["message"]}
    
    # Validate password
    if len(new_password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters long."}
    
    # Update user password
    users = _load_users()
    email = verification["email"]
    
    if email not in users:
        return {"success": False, "message": "User not found."}
    
    users[email]["password_hash"] = _hash_password(new_password)
    _save_users(users)
    
    # Mark token as used
    resets = _load_password_resets()
    resets[token]["used"] = True
    _save_password_resets(resets)
    
    return {"success": True, "message": "Password updated successfully!"}


def verify_security_answer(email: str, answer: str) -> bool:
    """Verify the security answer for a user."""
    users = _load_users()
    if email not in users:
        return False
    expected_hash = users[email].get("security_answer_hash", "")
    return _hash_password(answer.strip().lower()) == expected_hash


def get_user_statistics(email: str) -> dict:
    """
    Get user statistics and activity data.
    
    Args:
        email (str): User email
        
    Returns:
        dict: User statistics
    """
    users = _load_users()
    user_data = users.get(email, {})
    
    # Load user history
    user = email.split("@")[0]
    history_file = f"data/history_{user}.json"
    feedback_file = f"data/feedback_{user}.json"
    
    stats = {
        "total_scans": 0,
        "threats_detected": 0,
        "legitimate_sites": 0,
        "threat_ratio": 0,
        "feedback_count": 0,
        "account_age": 0,
        "last_scan": "Never",
        "success_rate": 0
    }
    
    # Calculate statistics from history
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                history = json.load(f)
                stats["total_scans"] = len(history)
                stats["threats_detected"] = sum(1 for entry in history if entry.get('prediction') == 'Phishing')
                stats["legitimate_sites"] = stats["total_scans"] - stats["threats_detected"]
                
                if stats["total_scans"] > 0:
                    stats["threat_ratio"] = (stats["threats_detected"] / stats["total_scans"]) * 100
                    stats["success_rate"] = 100 - stats["threat_ratio"]
                
                if history:
                    stats["last_scan"] = history[-1].get('timestamp', 'Unknown')
        except Exception:
            pass
    
    # Calculate feedback count
    if os.path.exists(feedback_file):
        try:
            with open(feedback_file, "r") as f:
                feedback_data = json.load(f)
                stats["feedback_count"] = len(feedback_data)
        except Exception:
            pass
    
    # Calculate account age
    if user_data.get('created_at'):
        try:
            created_date = datetime.strptime(user_data['created_at'], '%Y-%m-%d %H:%M:%S')
            account_age = (datetime.now() - created_date).days
            stats["account_age"] = account_age
        except Exception:
            stats["account_age"] = 0
    
    return stats


def display_account_page():
    """
    Display the account management page.
    This function is now handled by account_page.py
    """
    st.info("Account management is now handled by the dedicated Account Page.")
    st.info("Click the Profile button in the top-right corner to access your account.") 