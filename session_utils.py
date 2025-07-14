import streamlit as st

def init_ui_settings():
    st.session_state.setdefault("font_size", "medium")
    st.session_state.setdefault("user_email", "Guest")

def load_session_preferences():
    size = st.session_state.get("font_size", "medium")
    if size not in ["small", "medium", "large"]:
        st.session_state["font_size"] = "medium"

def set_font_size(size_label):
    if size_label in ["small", "medium", "large"]:
        st.session_state["font_size"] = size_label
    apply_theme()  # Apply immediately

def apply_theme():
    st.markdown(generate_font_style(), unsafe_allow_html=True)

def generate_font_style():
    size_map = {
        "small": "14px",
        "medium": "17px",
        "large": "20px"
    }
    font_size = size_map.get(st.session_state.get("font_size", "medium"), "17px")

    return f"""
    <style>
        html, body, [class*="css"] {{
            font-size: {font_size} !important;
        }}
    </style>
    """
