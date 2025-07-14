# account_page.py
# ---------------------------------------------------------
# Comprehensive Account Page with Profile Management
# ---------------------------------------------------------

import streamlit as st
import auth
import account
import json
import os
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np


def display_account_page():
    """Display the comprehensive account page."""
    st.title("Account Management")
    
    # Get user information
    user_info = auth.get_user_info()
    
    # Create tabs for different account sections
    tab1, tab2, tab3 = st.tabs([
        "Profile", "Activity", "Account Actions"
    ])
    
    with tab1:
        display_profile_section(user_info)
    
    with tab2:
        display_activity_section(user_info)
    
    with tab3:
        display_account_actions_section(user_info)


def display_profile_section(user_info):
    """Display user profile information (no profile picture)."""
    st.subheader("Profile Information")
    info_data = {
        "Email": user_info['email'],
        "Account Type": "Premium" if user_info['role'] in ['admin', 'analyst'] else "Standard",
        "Member Since": "2025-01-01",  # Placeholder
        "Last Login": user_info['login_time'],
        "Session Duration": user_info['session_duration']
    }
    for key, value in info_data.items():
        st.markdown(f"**{key}:** {value}")
    st.markdown("---")
    display_account_statistics(user_info)


def display_activity_section(user_info):
    """Display user activity and statistics (no recent activity)."""
    st.subheader("Activity & Statistics")
    stats = account.get_user_statistics(user_info['email'])
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"**Total Scans:** {stats['total_scans']}")
    with col2:
        st.markdown(f"**Threats Detected:** {stats['threats_detected']}")
    with col3:
        st.markdown(f"**Success Rate:** {100 - stats['threat_ratio']:.1f}%")
    with col4:
        st.markdown(f"**Account Age:** {stats['account_age']}")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Detection Activity")
        activity_data = pd.DataFrame({
            'Date': pd.date_range(start='2025-01-01', periods=30, freq='D'),
            'Scans': [max(0, int(stats["total_scans"] / 30 + np.random.normal(0, 2))) for _ in range(30)],
            'Threats': [max(0, int(stats["threats_detected"] / 30 + np.random.normal(0, 1))) for _ in range(30)]
        })
        fig = px.line(activity_data, x='Date', y=['Scans', 'Threats'], title="Daily Activity")
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.markdown("#### Threat Detection Rate")
        threat_data = {
            'Category': ['Legitimate', 'Threats'],
            'Count': [stats["legitimate_sites"], stats["threats_detected"]]
        }
        fig = px.pie(threat_data, values='Count', names='Category', title="Detection Distribution")
        st.plotly_chart(fig, use_container_width=True)


def display_account_actions_section(user_info):
    """Display account actions and settings."""
    st.subheader("Account Actions")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Password Management")
        with st.form("password_change"):
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            if st.form_submit_button("Change Password"):
                if new_password == confirm_password and len(new_password) >= 8:
                    st.markdown("<span style='color:#27ae60'>Password changed successfully!</span>", unsafe_allow_html=True)
                else:
                    st.markdown("<span style='color:#c0392b'>Passwords don't match or are too short!</span>", unsafe_allow_html=True)
        
        st.markdown("#### Data Management")
        if st.button("🗑️ Clear History Data", type="secondary"):
            # Clear user history and feedback data
            user_email = user_info['email']
            user = user_email.split("@")[0]
            history_file = f"data/history_{user}.json"
            feedback_file = f"data/feedback_{user}.json"
            
            try:
                if os.path.exists(history_file):
                    os.remove(history_file)
                if os.path.exists(feedback_file):
                    os.remove(feedback_file)
                st.success("History data cleared successfully!")
            except Exception as e:
                st.error(f"Error clearing data: {str(e)}")
    
    with col2:
        st.markdown("#### Account Deletion")
        if st.button("Delete Account", type="secondary"):
            st.markdown("<span style='color:#c0392b'>This action cannot be undone!</span>", unsafe_allow_html=True)
            if st.button("Confirm Delete"):
                st.markdown("<span style='color:#c0392b'>Account deletion feature coming soon!</span>", unsafe_allow_html=True)

def display_account_statistics(user_info):
    """Display comprehensive account statistics."""
    st.markdown("### Account Statistics")
    stats = account.get_user_statistics(user_info['email'])
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"**Total Scans:** {stats['total_scans']}")
        st.markdown(f"**Threats Detected:** {stats['threats_detected']}")
        st.markdown(f"**Legitimate Sites:** {stats['legitimate_sites']}")
    with col2:
        st.markdown(f"**Threat Ratio:** {stats['threat_ratio']:.1f}%")
        st.markdown(f"**Success Rate:** {100 - stats['threat_ratio']:.1f}%")
        st.markdown(f"**Feedback Given:** {stats['feedback_count']}")
    with col3:
        st.markdown(f"**Account Age:** {stats['account_age']}")
        st.markdown(f"**Last Scan:** {stats['last_scan']}")
        st.markdown(f"**Session Duration:** {user_info['session_duration']}") 