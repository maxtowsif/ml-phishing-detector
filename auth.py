# auth.py
# ---------------------------------------------
# Enhanced Authentication with Role-based Access Control
# ---------------------------------------------

import streamlit as st
import json
import os
import hashlib
from datetime import datetime, timedelta

# File to persist session data
SESSION_FILE = "data/session.json"
USERS_FILE = "data/users.json"

# Enhanced user credentials with roles and permissions
USER_CREDENTIALS = {
    "user@example.com": {
        "password": "password123",
        "role": "user",
        "permissions": ["detection", "history", "account"]
    },
    "admin@mscproject.com": {
        "password": "admin2025",
        "role": "admin",
        "permissions": ["dashboard", "detection", "bulk", "history", "account", "admin"]
    },
    "analyst@example.com": {
        "password": "analyst123",
        "role": "analyst",
        "permissions": ["dashboard", "detection", "bulk", "history"]
    }
}

# Role definitions
ROLES = {
    "admin": {
        "name": "Administrator",
        "description": "Full system access",
        "permissions": ["dashboard", "detection", "bulk", "history", "account", "admin", "analytics", "reports"]
    },
    "analyst": {
        "name": "Security Analyst",
        "description": "Advanced analysis capabilities",
        "permissions": ["dashboard", "detection", "bulk", "history", "analytics"]
    },
    "user": {
        "name": "Standard User",
        "description": "Basic detection and history",
        "permissions": ["detection", "history", "account"]
    }
}

def _load_users():
    """Load user data from file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
                # If users file is empty or corrupted, create default users
                if not users:
                    return _create_default_users()
                return users
        except (json.JSONDecodeError, Exception):
            # If file is corrupted, create default users
            return _create_default_users()
    else:
        # If file doesn't exist, create default users
        return _create_default_users()

def _create_default_users():
    """Create default user accounts."""
    default_users = {
        "admin@mscproject.com": {
            "email": "admin@mscproject.com",
            "password_hash": _hash_password("admin2025"),  # Password: admin2025
            "security_question": "What is your favorite color?",
            "security_answer_hash": _hash_password("blue"),  # Answer: blue
            "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "last_login": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "role": "admin",
            "status": "active"
        },
        "user@example.com": {
            "email": "user@example.com",
            "password_hash": _hash_password("password123"),  # Password: password123
            "security_question": "What is your favorite color?",
            "security_answer_hash": _hash_password("red"),  # Answer: red
            "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "last_login": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "role": "user",
            "status": "active"
        }
    }
    
    # Save default users
    _save_users(default_users)
    return default_users

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

def _persist_session(email, role="user"):
    """Store session data to file."""
    os.makedirs("data", exist_ok=True)
    with open(SESSION_FILE, "w") as f:
        json.dump({
            "logged_in": True,
            "user_email": email,
            "user_role": role,
            "login_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
            
            # Validate that the user still exists in the users database
            user_email = data.get("user_email", "")
            if user_email:
                users = _load_users()
                if user_email not in users:
                    # User no longer exists, clear session
                    raise ValueError("User no longer exists.")
            
            # Load session data
            st.session_state["logged_in"] = data.get("logged_in", False)
            st.session_state["user_email"] = user_email
            st.session_state["user_role"] = data.get("user_role", "user")
            st.session_state["login_time"] = data.get("login_time", "")
            
        except (json.JSONDecodeError, ValueError, FileNotFoundError) as e:
            # If the file is invalid, corrupted, or user doesn't exist, reset everything
            if os.path.exists(SESSION_FILE):
                try:
                    os.remove(SESSION_FILE)
                except:
                    pass
            st.session_state["logged_in"] = False
            st.session_state["user_email"] = ""
            st.session_state["user_role"] = "user"
            st.session_state["login_time"] = ""
    else:
        # No session file exists
        st.session_state["logged_in"] = False
        st.session_state["user_email"] = ""
        st.session_state["user_role"] = "user"
        st.session_state["login_time"] = ""

def check_permission(required_permission: str) -> bool:
    """
    Check if current user has required permission.
    
    Args:
        required_permission (str): Permission to check
        
    Returns:
        bool: True if user has permission
    """
    user_role = st.session_state.get("user_role", "user")
    user_permissions = ROLES.get(user_role, {}).get("permissions", [])
    return required_permission in user_permissions

def get_user_role() -> str:
    """Get current user's role."""
    return st.session_state.get("user_role", "user")

def get_user_permissions() -> list:
    """Get current user's permissions."""
    user_role = get_user_role()
    return ROLES.get(user_role, {}).get("permissions", [])

def login():
    # Removed background CSS and div
    if st.session_state.get("logged_in", False):
        st.success("You are already logged in!")
        return
    if 'auth_mode' not in st.session_state:
        st.session_state['auth_mode'] = 'login'
    if st.session_state['auth_mode'] == 'register':
        show_register()
        return
    if st.session_state['auth_mode'] == 'forgot':
        show_forgot_password()
        return
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<div style='text-align:center;'><img src='https://img.icons8.com/ios-filled/100/3b82f6/shield.png' width='48'/></div>", unsafe_allow_html=True)
        st.markdown("<div style='text-align:center; font-size:2.2rem; font-weight:700; margin-bottom:0.2rem;'>Threat Detection System</div>", unsafe_allow_html=True)
        st.markdown("<div style='text-align:center; color:rgba(255,255,255,0.8); margin-bottom:1rem;'>Advanced Phishing Detection</div>", unsafe_allow_html=True)
        # Display any messages
        if 'login_msg' in st.session_state and st.session_state['login_msg']:
            msg_type = st.session_state.get('login_msg_type', 'error')
            if msg_type == 'success':
                st.success(st.session_state['login_msg'])
            else:
                st.error(st.session_state['login_msg'])
            del st.session_state['login_msg']
            if 'login_msg_type' in st.session_state:
                del st.session_state['login_msg_type']
        with st.form("login_form", clear_on_submit=False):
            email = st.text_input("Email", placeholder="Enter your email", key="login_email", help="")
            password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_password", help="")
            submitted = st.form_submit_button("Login", use_container_width=True)
        if submitted:
            if not email or not password:
                st.session_state['login_msg'] = "Both email and password are required."
                st.session_state['login_msg_type'] = 'error'
                st.rerun()
            users = _load_users()
            if email in users:
                stored_password_hash = users[email].get("password_hash", "")
                if _verify_password(password, stored_password_hash):
                    st.session_state['login_msg'] = "Login successful!"
                    st.session_state['login_msg_type'] = 'success'
                    st.session_state["logged_in"] = True
                    st.session_state["user_email"] = email
                    st.session_state["user_role"] = users[email].get("role", "user")
                    st.session_state["login_time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    users[email]["last_login"] = st.session_state["login_time"]
                    _save_users(users)
                    _persist_session(email, users[email].get("role", "user"))
                    st.rerun()
                else:
                    st.session_state['login_msg'] = "Invalid email or password."
                    st.session_state['login_msg_type'] = 'error'
                    st.rerun()
            else:
                st.session_state['login_msg'] = "Invalid email or password."
                st.session_state['login_msg_type'] = 'error'
                st.rerun()
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Create an Account", key="goto_register_btn", use_container_width=True):
                st.session_state['auth_mode'] = 'register'
                st.rerun()
        with col2:
            if st.button("Forgot Password?", key="goto_forgot_btn", use_container_width=True):
                st.session_state['auth_mode'] = 'forgot'
                st.session_state['forgot_stage'] = 'email'  # Ensure reset to email stage
                st.rerun()
    st.markdown("""
    <div style='text-align:center; margin-top:3rem; padding:2rem 0;'>
        <span style='font-size:1.1rem; font-weight:600; color:white;'>MSc Project 2025</span><br>
        <span style='font-size:1rem; color:rgba(255,255,255,0.8);'>Author: <b>Towsif Ahmed</b></span>
    </div>
    """, unsafe_allow_html=True)


def show_register():
    # Removed background CSS and div
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<div style='text-align:center;'><img src='https://img.icons8.com/ios-filled/100/3b82f6/shield.png' width='48'/></div>", unsafe_allow_html=True)
        st.markdown("<div style='text-align:center; font-size:2.2rem; font-weight:700; margin-bottom:0.2rem;'>Threat Detection System</div>", unsafe_allow_html=True)
        st.markdown("<div style='text-align:center; color:rgba(255,255,255,0.8); margin-bottom:1rem;'>Advanced Phishing Detection</div>", unsafe_allow_html=True)
        st.header("Create an Account")
        # Display any messages
        if 'register_msg' in st.session_state and st.session_state['register_msg']:
            if st.session_state.get('register_msg_type') == 'success':
                st.success(st.session_state['register_msg'])
            else:
                st.error(st.session_state['register_msg'])
            del st.session_state['register_msg']
            if 'register_msg_type' in st.session_state:
                del st.session_state['register_msg_type']
        with st.form("register_form", clear_on_submit=True):
            email = st.text_input("Email", key="register_email", help="")
            password = st.text_input("Password", type="password", key="register_password", help="")
            confirm_password = st.text_input("Confirm Password", type="password", key="register_confirm_password", help="")
            security_question = st.selectbox("Security Question", [
                "What is your favorite color?",
                "What is your mother's maiden name?",
                "What was your first pet's name?",
                "What is your favorite food?",
                "What city were you born in?"
            ], key="register_security_question")
            security_answer = st.text_input("Security Answer", key="register_security_answer", help="")
            submitted = st.form_submit_button("Register", use_container_width=True)
        if submitted:
            import account
            result = account.register_user(email, password, confirm_password, security_question, security_answer)
            if result["success"]:
                st.session_state['register_msg'] = "Account created successfully! You can now log in."
                st.session_state['register_msg_type'] = 'success'
                st.session_state['auth_mode'] = 'login'
                st.rerun()
            else:
                st.session_state['register_msg'] = result['message']
                st.session_state['register_msg_type'] = 'error'
                st.rerun()
        if st.button("Back to Login", key="back_login_from_register", use_container_width=True):
            st.session_state['auth_mode'] = 'login'
            st.rerun()
    st.markdown("""
    <div style='text-align:center; margin-top:3rem; padding:2rem 0;'>
        <span style='font-size:1.1rem; font-weight:600; color:white;'>MSc Project 2025</span><br>
        <span style='font-size:1rem; color:rgba(255,255,255,0.8);'>Author: <b>Towsif Ahmed</b></span>
    </div>
    """, unsafe_allow_html=True)


def show_forgot_password():
    # Removed background CSS and div
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<div style='text-align:center;'><img src='https://img.icons8.com/ios-filled/100/3b82f6/shield.png' width='48'/></div>", unsafe_allow_html=True)
        st.markdown("<div style='text-align:center; font-size:2.2rem; font-weight:700; margin-bottom:0.2rem;'>Threat Detection System</div>", unsafe_allow_html=True)
        st.markdown("<div style='text-align:center; color:rgba(255,255,255,0.8); margin-bottom:1rem;'>Advanced Phishing Detection</div>", unsafe_allow_html=True)
        st.header("Reset Password")
        
        if 'forgot_msg' in st.session_state and st.session_state['forgot_msg']:
            if st.session_state.get('forgot_msg_type') == 'success':
                st.success(st.session_state['forgot_msg'])
            else:
                st.error(st.session_state['forgot_msg'])
            del st.session_state['forgot_msg']
            if 'forgot_msg_type' in st.session_state:
                del st.session_state['forgot_msg_type']
        if 'forgot_stage' not in st.session_state:
            st.session_state['forgot_stage'] = 'email'
        if st.session_state['forgot_stage'] == 'email':
            with st.form("forgot_form_email", clear_on_submit=False):
                email = st.text_input("Email", key="forgot_email", placeholder="Enter your email address", help="")
                submitted = st.form_submit_button("Next", use_container_width=True)
            if submitted:
                if not email:
                    st.session_state['forgot_msg'] = "Email is required."
                    st.session_state['forgot_msg_type'] = 'error'
                    st.rerun()
                users = _load_users()
                if email in users:
                    # Store email in internal session state variable to avoid widget key conflicts
                    st.session_state['_forgot_email_internal'] = email
                    st.session_state['forgot_stage'] = 'security_question'
                    st.rerun()
                else:
                    st.session_state['forgot_msg'] = "No account found with this email address."
                    st.session_state['forgot_msg_type'] = 'error'
                    st.rerun()
        elif st.session_state['forgot_stage'] == 'security_question':
            email = st.session_state.get('_forgot_email_internal', '')
            users = _load_users()
            if email in users:
                question = users[email].get('security_question', 'Unknown question')
                with st.form("forgot_form_security", clear_on_submit=False):
                    st.markdown(f"**Security Question:** {question}")
                    answer = st.text_input("Your Answer", key="forgot_security_answer", placeholder="Enter your security answer", help="")
                    submitted = st.form_submit_button("Verify", use_container_width=True)
                if submitted:
                    if not answer:
                        st.session_state['forgot_msg'] = "Security answer is required."
                        st.session_state['forgot_msg_type'] = 'error'
                        st.rerun()
                    import account
                    correct = account.verify_security_answer(email, answer.strip().lower())
                    if correct:
                        # Keep email in internal session state variable
                        st.session_state['_forgot_email_internal'] = email
                        st.session_state['forgot_msg'] = "Security answer verified! Please set your new password."
                        st.session_state['forgot_msg_type'] = 'success'
                        st.session_state['forgot_stage'] = 'reset_password'
                        st.rerun()
                    else:
                        st.session_state['forgot_msg'] = "Incorrect security answer. (Tip: Check for extra spaces or capitalization)"
                        st.session_state['forgot_msg_type'] = 'error'
                        st.rerun()
        elif st.session_state['forgot_stage'] == 'reset_password':
            email = st.session_state.get('_forgot_email_internal', '')
            
            # Safety check: if email is missing, go back to email stage
            if not email:
                st.error("Session expired. Please start the password reset process again.")
                st.session_state['forgot_stage'] = 'email'
                st.rerun()
                return
            
            st.markdown('<div style="color: #3b82f6; font-weight: bold;">Please enter your new password below:</div>', unsafe_allow_html=True)
            with st.form("forgot_form_reset", clear_on_submit=False):
                new_password = st.text_input("New Password", type="password", key="forgot_new_password_reset", placeholder="Enter new password", help="")
                confirm_password = st.text_input("Confirm New Password", type="password", key="forgot_confirm_password_reset", placeholder="Confirm new password", help="")
                submitted = st.form_submit_button("Reset Password", use_container_width=True)
            if submitted:
                if not new_password or not confirm_password:
                    st.session_state['forgot_msg'] = "Both password fields are required."
                    st.session_state['forgot_msg_type'] = 'error'
                    st.rerun()
                elif new_password != confirm_password:
                    st.session_state['forgot_msg'] = "Passwords do not match."
                    st.session_state['forgot_msg_type'] = 'error'
                    st.rerun()
                elif len(new_password) < 8:
                    st.session_state['forgot_msg'] = "Password must be at least 8 characters long."
                    st.session_state['forgot_msg_type'] = 'error'
                    st.rerun()
                else:
                    users = _load_users()
                    if email in users:
                        users[email]['password_hash'] = _hash_password(new_password)
                        _save_users(users)
                        st.session_state['forgot_msg'] = "Password reset successfully! You can now log in."
                        st.session_state['forgot_msg_type'] = 'success'
                        st.session_state['auth_mode'] = 'login'
                        st.session_state['forgot_stage'] = 'email'
                        # Clear the internal email variable
                        if '_forgot_email_internal' in st.session_state:
                            del st.session_state['_forgot_email_internal']
                        st.rerun()
                    else:
                        st.session_state['forgot_msg'] = "User not found."
                        st.session_state['forgot_msg_type'] = 'error'
                        st.rerun()
        # Fallback: If for some reason the form is not rendered, show a message
        elif st.session_state['forgot_stage'] not in ['email', 'security_question', 'reset_password']:
            st.error("[DEBUG] Unknown forgot password stage. Please try again or contact support.")
        if st.button("Back to Login", key="back_login_from_forgot", use_container_width=True):
            st.session_state['auth_mode'] = 'login'
            st.session_state['forgot_stage'] = 'email'
            # Clear the internal email variable
            if '_forgot_email_internal' in st.session_state:
                del st.session_state['_forgot_email_internal']
            st.rerun()
    st.markdown("""
    <div style='text-align:center; margin-top:3rem; padding:2rem 0;'>
        <span style='font-size:1.1rem; font-weight:600; color:white;'>MSc Project 2025</span><br>
        <span style='font-size:1rem; color:rgba(255,255,255,0.8);'>Author: <b>Towsif Ahmed</b></span>
    </div>
    """, unsafe_allow_html=True)

def protect_route():
    """Prevent access to internal pages if not logged in."""
    if not st.session_state.get("logged_in", False):
        _load_persisted_session()
        if not st.session_state.get("logged_in", False):
            st.warning("You must log in to access this page.")
            st.stop()

def protect_route_with_permission(required_permission: str):
    """
    Protect route with specific permission requirement.
    
    Args:
        required_permission (str): Required permission to access
    """
    protect_route()
    if not check_permission(required_permission):
        st.error(f"You don't have permission to access this feature. Required: {required_permission}")
        st.stop()

def logout():
    """Clear session and remove saved file."""
    # Clear all session state
    session_keys_to_clear = ['logged_in', 'user_email', 'user_role', 'login_time', 'show_account', 'auth_mode', 'forgot_stage']
    for key in session_keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]
    
    # Remove session file
    if os.path.exists(SESSION_FILE):
        try:
            os.remove(SESSION_FILE)
        except:
            pass
    
    st.success("Logged out successfully.")
    st.rerun()

def get_user_info():
    """Get comprehensive user information."""
    return {
        "email": st.session_state.get("user_email", ""),
        "role": st.session_state.get("user_role", "user"),
        "role_name": ROLES.get(st.session_state.get("user_role", "user"), {}).get("name", "User"),
        "permissions": get_user_permissions(),
        "login_time": st.session_state.get("login_time", ""),
        "session_duration": _calculate_session_duration()
    }

def _calculate_session_duration():
    """Calculate how long user has been logged in."""
    login_time = st.session_state.get("login_time", "")
    if login_time:
        try:
            login_dt = datetime.strptime(login_time, '%Y-%m-%d %H:%M:%S')
            duration = datetime.now() - login_dt
            return str(duration).split('.')[0]  # Remove microseconds
        except:
            return "Unknown"
    return "Unknown"

def display_user_status():
    """Display current user status in sidebar."""
    if st.session_state.get("logged_in", False):
        user_info = get_user_info()
        st.sidebar.markdown("### Current User")
        st.sidebar.info(f"**Email:** {user_info['email']}")
        st.sidebar.info(f"**Role:** {user_info['role_name']}")
        st.sidebar.info(f"**Login:** {user_info['login_time']}")
        st.sidebar.info(f"**Session:** {user_info['session_duration']}")
        
        # Display permissions
        st.sidebar.markdown("### Permissions")
        for permission in user_info['permissions']:
            st.sidebar.success(f"✓ {permission.title()}")
    else:
        st.sidebar.warning("Not logged in")