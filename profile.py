# profile.py
import streamlit as st

def render_profile_page():
    st.markdown("## 👤 User Profile", unsafe_allow_html=True)

    st.markdown("---")

    user_email = st.session_state.get("user_email", "Guest")
    font_size = st.session_state.get("font_size", "medium").capitalize()
    dark_mode = "Enabled" if st.session_state.get("dark_mode", True) else "Disabled"

    st.write("**Email:**", user_email)
    st.write("**Font Size Preference:**", font_size)
    st.write("**Dark Mode:**", dark_mode)

    st.markdown("---")
    st.caption("This profile section is currently a placeholder. Additional settings and preferences will be added in the future.")
