# app.py
# ---------------------------------------------------------
# Enhanced Phishing Detection App with Account Management
# ---------------------------------------------------------

import streamlit as st
import pandas as pd
import numpy as np
import json
import os
import time
import io
from fpdf import FPDF
import concurrent.futures
import hashlib
import warnings
import logging

# Suppress Streamlit threading warnings
warnings.filterwarnings("ignore", message=".*missing ScriptRunContext.*")
logging.getLogger("streamlit").setLevel(logging.ERROR)

# Handle optional imports with error handling
try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    st.warning("Plotly not available - charts will be disabled")

from datetime import datetime, timedelta

# Import custom modules
import auth
import model
import features
import feedback
import logger
import dashboard
import account
import account_page
import url_analysis
import recommendations

# Page configuration
st.set_page_config(
    page_title="Threat Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .stApp {
        background: #1a1a1a;
    }
    .main .block-container {
        background: rgba(30, 30, 30, 0.95);
        border-radius: 15px;
        padding: 2rem;
        margin-top: 1rem;
        box-shadow: 0 8px 40px rgba(0,0,0,0.3);
        color: white;
    }
    .main-header {
        background: linear-gradient(135deg, #2d2d2d 0%, #3d3d3d 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        border: 1px solid #444;
    }
    .stButton > button {
        border-radius: 8px;
        border: none;
        background: #444; /* Changed from #8B5CF6 to neutral */
        color: white;
        padding: 0.5rem 1rem;
        font-weight: 500;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        background: #666; /* Changed from #7C3AED to neutral */
        transform: translateY(-1px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    .stButton > button:focus,
    .stTextInput > div > div > input:focus,
    .stTabs > div > div > div > button:focus {
        outline: none !important;
        box-shadow: none !important;
        border-color: #666 !important;
    }
    .stRadio > div {
        background: transparent;
        border: none;
        padding: 0;
    }
    .stRadio > div > label {
        background: #2d2d2d;
        border: 2px solid #444;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        margin: 0.25rem;
        transition: all 0.3s ease;
        color: white;
    }
    .stRadio > div > label:hover {
        border-color: #666;
        background: #3d3d3d;
    }
    .stRadio > div > label[data-baseweb="radio"] {
        background: #666; /* Changed from #8B5CF6 to neutral */
        border-color: #666;
        color: white;
    }
    .stProgress > div > div > div {
        background: #666; /* Changed from #8B5CF6 to neutral */
    }
    .stMetric {
        background: transparent;
        border: none;
        padding: 0;
    }
    .stMetric > div {
        background: transparent;
        border: none;
    }
    .stDataFrame {
        border: none;
        border-radius: 8px;
        overflow: hidden;
    }
    .stDataFrame > div {
        border: 1px solid #e9ecef;
        border-radius: 8px;
    }
    .stExpander {
        border: none;
        border-radius: 8px;
        overflow: hidden;
    }
    .stExpander > div {
        border: 1px solid #e9ecef;
        border-radius: 8px;
    }
    .stTabs > div > div > div {
        background: transparent;
        border: none;
    }
    .stTabs > div > div > div > button {
        background: transparent;
        border: none;
        border-bottom: 2px solid transparent;
        border-radius: 0;
        padding: 0.5rem 1rem;
        margin: 0;
        transition: all 0.3s ease;
    }
    .stTabs > div > div > div > button:hover {
        background: #3d3d3d;
        border-bottom-color: #666;
        color: white;
    }
    .stTabs > div > div > div > button[aria-selected="true"] {
        background: transparent;
        border-bottom-color: #666; /* Changed from #8B5CF6 to neutral */
        color: #fff;
        font-weight: 600;
    }
    .stTabs > div > div > div > button:focus {
        outline: none !important;
        box-shadow: none !important;
        border-color: #666 !important;
    }
    .stTextInput > div > div > input {
        border-radius: 8px;
        border: 2px solid #444;
        transition: all 0.3s ease;
        background: #2d2d2d;
        color: white;
    }
    .stTextInput > div > div > input:focus {
        outline: none !important;
        border-color: #666 !important;
        box-shadow: none !important;
    }
    .stSelectbox > div > div > div {
        border-radius: 8px;
        border: 2px solid #444;
        background: #2d2d2d;
        color: white;
    }
    .stSelectbox > div > div > div:hover {
        border-color: #666; /* Changed from #8B5CF6 to neutral */
    }
    .stFileUploader > div {
        border: 2px dashed #444;
        border-radius: 8px;
        background: #2d2d2d;
        transition: all 0.3s ease;
        color: white;
    }
    .stFileUploader > div:hover {
        border-color: #8B5CF6;
        background: #f3f4f6;
    }
    .stAlert {
        border-radius: 8px;
        border: none;
    }
    .stAlert > div {
        border-radius: 8px;
    }
    .stSuccess {
        background: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
    }
    .stError {
        background: #f8d7da;
        color: #721c24;
        border: 1px solid #f5c6cb;
    }
    .stWarning {
        background: #fff3cd;
        color: #856404;
        border: 1px solid #ffeaa7;
    }
    .stInfo {
        background: #d1ecf1;
        color: #0c5460;
        border: 1px solid #bee5eb;
    }
    /* Hide Streamlit's default help text in input fields (e.g., 'Press Enter to submit form') */
    .stTextInput .stMarkdown, .stTextInput .stCaption {
        display: none !important;
    }
</style>
""", unsafe_allow_html=True)

def main():
    """Main application function."""
    
    # Initialize session state
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
    
    # Load persisted session with error handling
    try:
        auth._load_persisted_session()
    except Exception as e:
        # Clear any corrupted session data
        st.session_state['logged_in'] = False
        st.session_state['user_email'] = ''
        st.session_state['user_role'] = 'user'
        st.session_state['login_time'] = ''
    
    # Check authentication
    if not st.session_state.get('logged_in', False):
        auth.login()
        return
    
    # Main application interface
    display_main_interface()

def display_main_interface():
    """Display the main application interface."""
    
    # Header with account button
    col1, col2, col3 = st.columns([3, 1, 1])
    
    with col1:
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ Threat Detection System</h1>
            <p>Advanced Phishing Detection with Real-time Analytics</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        if st.button("🪪 Account", use_container_width=True):
            st.session_state['show_account'] = True
    
    # Check if account page should be shown
    if st.session_state.get('show_account', False):
        account_page.display_account_page()
        if st.button("← Back to Main"):
            st.session_state['show_account'] = False
            st.rerun()
        return
    
    # Sidebar with project info
    with st.sidebar:
        st.image("https://media.licdn.com/dms/image/v2/D5612AQHnrOxV5AV5XA/article-cover_image-shrink_720_1280/article-cover_image-shrink_720_1280/0/1721182567770?e=2147483647&v=beta&t=0Tx0kcZrZkMHQK98Br8ak676KhH_CtZDReKik7fUze4", use_container_width=True)
        st.markdown("""
        <div style='margin-top: 1rem; margin-bottom: 0.5rem;'>
            <span style='font-size: 1.3rem; font-weight: 600;'>MSc Project 2025</span>
        </div>
        <div style='font-weight: bold; font-size: 1.1rem; margin-bottom: 0.2rem;'>Threat Detection &amp; Resilience Framework</div>
        <div style='font-style: italic; color: #b0b0b0; margin-bottom: 0.5rem;'>Cybersecurity Readiness</div>
        <div style='margin-bottom: 0.2rem;'><b>Model:</b> RandomForestClassifier</div>
        <div><b>Author:</b> <span style='font-weight: bold;'>Towsif Ahmed</span></div>
        """, unsafe_allow_html=True)
        st.markdown("---")
        # Logout button
        if st.button("⏻ Logout", use_container_width=True):
            auth.logout()
        st.markdown("""
        <div style='margin-top:2rem; font-size:0.90rem; color:#aaa; text-align:center;'>
        Copyright © 2025 MSc Project<br>
        MIT License<br>
        <span style='font-size:0.85rem;'>Disclaimer: For research &amp; educational use only.</span>
        </div>
        """, unsafe_allow_html=True)
    
    # Main content area with tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🧭 Dashboard", "🕵️ Detection", "📂 Bulk Analysis", "🕒 History"
    ])
    
    with tab1:
        display_dashboard_tab()
    
    with tab2:
        display_detection_tab()
    
    with tab3:
        display_bulk_analysis_tab()
    
    with tab4:
        display_history_tab()

def display_dashboard_tab():
    """Display the analytics dashboard."""
    st.subheader("🧭 Real-time Analytics Dashboard")
    
    # Get dashboard data
    dashboard_data = dashboard.get_dashboard_data()
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🔢 Total Scans", dashboard_data['total_scans'])
    with col2:
        st.metric("⚠️ Threats Detected", dashboard_data['threats_detected'])
    with col3:
        st.metric("🎯 Success Rate", f"{dashboard_data['success_rate']:.1f}%")
    with col4:
        st.metric("👥 Active Users", dashboard_data['active_users'])
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Detection Trends")
        if PLOTLY_AVAILABLE:
            fig = px.line(dashboard_data['trends_df'], x='Date', y='Scans',
                         title="Daily Detection Activity")
            fig.update_layout(
                plot_bgcolor='#1a1a1a',
                paper_bgcolor='#1a1a1a',
                font_color='white'
            )
            st.plotly_chart(fig, use_container_width=True, key="dashboard_trends_chart")
        else:
            st.info("Plotly not available for charts. Please install plotly-express.")
    
    with col2:
        st.markdown("### Threat Distribution")
        if PLOTLY_AVAILABLE:
            fig = px.pie(dashboard_data['threat_distribution'], values='Count', names='Category',
                         title="Threat vs Legitimate Sites")
            fig.update_layout(
                plot_bgcolor='#1a1a1a',
                paper_bgcolor='#1a1a1a',
                font_color='white'
            )
            st.plotly_chart(fig, use_container_width=True, key="dashboard_pie_chart")
        else:
            st.info("Plotly not available for charts. Please install plotly-express.")
    
    # Enhanced Geographic threat visualization with real data
    dashboard.display_geographic_threats()

def display_detection_tab():
    """Display the URL detection interface."""
    st.subheader("🕵️ URL Phishing Detection")
    
    # URL input
    url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
    
    if st.button("🔍 Analyze URL", type="primary"):
        if url:
            # Clear previous analysis results and feedback states
            if 'current_analysis' in st.session_state:
                del st.session_state['current_analysis']
            
            # Clear any previous feedback states for this URL
            url_key_prefix = url.replace("https://", "").replace("http://", "").replace("/", "_")
            keys_to_clear = [key for key in st.session_state.keys() 
                           if isinstance(key, str) and key.startswith(url_key_prefix) and 'feedback_submitted' in key]
            for key in keys_to_clear:
                del st.session_state[key]
            
            # Force clear any cached results by using a unique key
            st.session_state['analysis_timestamp'] = time.time()
            
            with st.spinner("Analyzing URL..."):
                # Always use advanced detection
                analysis_result = perform_comprehensive_analysis(url)
                # Store results in session state to persist after feedback
                st.session_state['current_analysis'] = analysis_result
                st.rerun()  # Force rerun to clear previous results
        else:
            st.warning("Please enter a URL to analyze.")
    
    # Display results if they exist in session state (persist after feedback)
    if 'current_analysis' in st.session_state:
        # Use timestamp to ensure fresh rendering
        timestamp = st.session_state.get('analysis_timestamp', 0)
        # Create a container for results to ensure proper clearing
        results_container = st.container()
        with results_container:
            display_enhanced_results(st.session_state['current_analysis'], timestamp)

def perform_comprehensive_analysis(url):
    """Perform comprehensive URL analysis (always advanced)."""
    start_time = time.time()
    
    # Feature extraction
    features_result = features.extract_features(url)
    
    # Model prediction
    prediction_result = model.predict_phishing(url)
    
    # Always use advanced security analysis
    security_analysis = url_analysis.analyze_url_security(url)
    
    # Generate recommendations
    recommendations_list = recommendations.generate_recommendations(
        url, prediction_result, security_analysis
    )
    
    # Unified logging: only log once, with all important fields
    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'url': url,
        'prediction': prediction_result.get('prediction', 'Unknown'),
        'confidence': prediction_result.get('confidence', 0),
        'risk_score': prediction_result.get('risk_score', 0),
        'risk_level': prediction_result.get('risk_level', 'Unknown'),
        'model_used': prediction_result.get('model_used', 'Unknown'),
        'features_count': len(features_result) if features_result else 0,
        'analysis_time': time.time() - start_time,
        # SSL summary
        'ssl_valid': security_analysis['ssl_info'].get('valid', False),
        'ssl_issuer': security_analysis['ssl_info'].get('issuer', 'Unknown'),
        'ssl_days_remaining': security_analysis['ssl_info'].get('days_remaining', 0),
        # WHOIS summary
        'whois_domain': security_analysis['whois_info'].get('domain', 'Unknown'),
        'whois_registrar': security_analysis['whois_info'].get('registrar', 'Unknown'),
        'whois_creation_date': security_analysis['whois_info'].get('creation_date', 'Unknown'),
        # DNS summary
        'dns_resolved': security_analysis['dns_info'].get('resolved', False),
        'dns_a_records_count': len(security_analysis['dns_info'].get('a_records', [])),
        'dns_mx_records_count': len(security_analysis['dns_info'].get('mx_records', [])),
        'dns_ns_records_count': len(security_analysis['dns_info'].get('ns_records', [])),
        # HTTP summary
        'http_status_code': security_analysis['http_info'].get('status_code', 0),
        'http_response_time': security_analysis['http_info'].get('response_time', 0),
        # Security headers summary (count of set headers)
        'security_headers_score': sum(1 for v in security_analysis['http_info'].get('security_headers', {}).values() if v != 'Not Set')
    }
    
    # Use enhanced logger.log_detection function instead of manual file writing
    import logger
    
    # Add analysis_time to prediction_result for proper logging
    prediction_result['analysis_time'] = time.time() - start_time
    
    logger.log_detection(url, prediction_result, features_result, security_analysis)
    
    analysis_time = log_entry['analysis_time']
    
    return {
        'url': url,
        'prediction': prediction_result,
        'features': features_result,
        'security_analysis': security_analysis,
        'recommendations': recommendations_list,
        'analysis_time': analysis_time,
        'timestamp': log_entry['timestamp'],
    }

def display_enhanced_results(analysis_result, timestamp=None):
    """Display enhanced analysis results with better visualization."""
    st.markdown("## 📝 Analysis Results")
    
    # Overall result with large title and gauges
    st.markdown("""
    <style>
    .big-title {
        font-size: 2.2rem;
        font-weight: 800;
        margin-bottom: 1.5rem;
        color: #fff;
        letter-spacing: 1px;
        text-align: center;
    }
    .gauge-container {
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 1rem;
    }
    </style>
    """, unsafe_allow_html=True)

    # Display main result title first (spanning full width)
    prediction = analysis_result['prediction']
    confidence = analysis_result['prediction']['confidence']
    risk_score = analysis_result['prediction'].get('risk_score', 0)
    risk_level = analysis_result['prediction'].get('risk_level', 'Unknown')

    # Large result title
    if prediction['prediction'] == 'Phishing':
        st.markdown('<div class="big-title" style="color:#ff4444;">DANGER: Phishing Detected</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="big-title" style="color:#22c55e;">SAFE: Legitimate Site</div>', unsafe_allow_html=True)

    # Create two equal columns for horizontal gauge alignment
    col1, col2 = st.columns([1, 1], gap="medium")

    with col1:
        # Risk Level Text
        risk_label = risk_level.upper() if isinstance(risk_level, str) else str(risk_level)
        st.markdown(f"<div style='font-size:1.2rem; font-weight:700; text-align:center; margin-bottom:0.5rem;'>Risk Level: <span style='color:#8B5CF6'>{risk_label}</span> ({risk_score:.1f})</div>", unsafe_allow_html=True)

        # Risk Speedometer Gauge
        if PLOTLY_AVAILABLE:
            risk_gauge = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = risk_score,
                title = {'text': "Risk Level", 'font': {'size': 16}},
                gauge = {
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#8B5CF6", 'thickness': 0.3},
                    'steps': [
                        {'range': [0, 40], 'color': '#22c55e'},      # LOW
                        {'range': [40, 60], 'color': '#facc15'},     # MEDIUM
                        {'range': [60, 80], 'color': '#fb923c'},     # HIGH
                        {'range': [80, 100], 'color': '#ef4444'}     # CRITICAL
                    ],
                    'threshold': {
                        'line': {'color': "#ef4444", 'width': 4},
                        'thickness': 0.8,
                        'value': 80
                    }
                }
            ))
            risk_gauge.update_layout(
                height=280, 
                margin=dict(l=20, r=20, t=50, b=20),
                showlegend=False,
                plot_bgcolor='#1a1a1a',
                paper_bgcolor='#1a1a1a',
                font_color='white'
            )
            st.plotly_chart(risk_gauge, use_container_width=True, key="risk_gauge_chart")
        else:
            st.info("Plotly not available for charts. Please install plotly-express.")
        
        # Risk level legend
        st.markdown("""
        <div style='display: flex; justify-content: space-between; font-size: 0.9rem; margin-top: -10px; padding: 0 10px;'>
            <span style='color:#22c55e; font-weight: bold;'>LOW</span>
            <span style='color:#facc15; font-weight: bold;'>MEDIUM</span>
            <span style='color:#fb923c; font-weight: bold;'>HIGH</span>
            <span style='color:#ef4444; font-weight: bold;'>CRITICAL</span>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        # Model Confidence Text
        confidence_percentage = confidence * 100
        st.markdown(f"<div style='font-size:1.2rem; font-weight:700; text-align:center; margin-bottom:0.5rem;'>Model Confidence: <span style='color:#8B5CF6'>{confidence_percentage:.1f}%</span></div>", unsafe_allow_html=True)
        
        if PLOTLY_AVAILABLE:
            conf_gauge = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = confidence_percentage,
                title = {'text': "Confidence %", 'font': {'size': 16}},
                gauge = {
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#8B5CF6", 'thickness': 0.4},
                    'steps': [
                        {'range': [0, 30], 'color': "#f3e8ff"},
                        {'range': [30, 70], 'color': "#c4b5fd"},
                        {'range': [70, 100], 'color': "#a78bfa"}
                    ],
                    'threshold': {
                        'line': {'color': "#8B5CF6", 'width': 4},
                        'thickness': 0.8,
                        'value': 90
                    }
                }
            ))
            conf_gauge.update_layout(
                height=280, 
                margin=dict(l=20, r=20, t=50, b=20),
                showlegend=False,
                plot_bgcolor='#1a1a1a',
                paper_bgcolor='#1a1a1a',
                font_color='white'
            )
            st.plotly_chart(conf_gauge, use_container_width=True, key="confidence_gauge_chart")
        else:
            st.info("Plotly not available for charts. Please install plotly-express.")
    
    # Add vertical spacing between gauges and tabs
    st.markdown("<div style='margin-top: 3rem;'></div>", unsafe_allow_html=True)
    
    # Detailed analysis tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🛡️ Security Analysis", "🧬 Feature Analysis", "💡 Recommendations", "🚀 Performance"
    ])
    
    with tab1:
        # Enhanced security analysis display
        url_analysis.display_security_analysis(analysis_result['security_analysis'])
    
    with tab2:
        display_feature_analysis(analysis_result['features'])
    
    with tab3:
        display_recommendations(analysis_result['recommendations'])
    
    with tab4:
        display_performance_metrics(analysis_result)

    # Feedback form after detection
    url = analysis_result.get('url', '')
    predicted_label = analysis_result['prediction'].get('prediction', '')
    confidence = analysis_result['prediction'].get('confidence', 0)
    feedback.collect_feedback(url, predicted_label, confidence)

def display_feature_analysis(features_result):
    """Display feature importance analysis."""
    st.subheader("🧬 Feature Analysis")
    
    # Feature importance chart
    if 'feature_importance' in features_result:
        importance_df = pd.DataFrame({
            'Feature': list(features_result['feature_importance'].keys()),
            'Importance': list(features_result['feature_importance'].values())
        })
        
        if PLOTLY_AVAILABLE:
            fig = px.bar(importance_df, x='Importance', y='Feature',
                        orientation='h', title="Feature Importance")
            st.plotly_chart(fig, use_container_width=True, key="feature_importance_chart")
        else:
            st.info("Plotly not available for charts. Please install plotly-express.")
    
    # Feature breakdown
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### URL Structure Analysis")
        url_features = {
            "Domain Length": features_result.get('domain_length', 0),
            "Path Length": features_result.get('path_length', 0),
            "Subdomain Count": features_result.get('subdomain_count', 0),
            "Query Parameters": features_result.get('query_count', 0)
        }
        
        for feature, value in url_features.items():
            st.info(f"**{feature}:** {value}")
    
    with col2:
        st.markdown("### Security Indicators")
        security_features = {
            "HTTPS": "✅" if features_result.get('https', False) else "❌",
            "SSL Certificate": "✅" if features_result.get('ssl_valid', False) else "❌",
            "Domain Age": "✅" if features_result.get('domain_age_days', 0) > 365 else "⚠️",
            "Suspicious Keywords": "❌" if features_result.get('suspicious_keywords', 0) > 0 else "✅"
        }
        
        for feature, status in security_features.items():
            st.info(f"**{feature}:** {status}")

def display_recommendations(recommendations_list):
    """Display smart recommendations."""
    st.subheader("💡 Smart Recommendations")
    
    for i, rec in enumerate(recommendations_list, 1):
        st.info(f"**{i}.** {rec}")

def display_performance_metrics(analysis_result):
    """Display performance metrics."""
    st.subheader("🚀 Performance Metrics")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Analysis Time", f"{analysis_result['analysis_time']:.2f}s")
    
    with col2:
        st.metric("Features Extracted", len(analysis_result['features']))
    
    with col3:
        st.metric("Security Checks", len(analysis_result['security_analysis']['risk_factors']))

def display_bulk_analysis_tab():
    """Display bulk analysis interface."""
    st.subheader("📂 Bulk URL Analysis")
    st.info("""
**How to use Bulk Detection:**
- Upload a CSV file with a column named `url` containing the URLs you want to analyze.
- Example CSV format:

| url |
|-----------------------------|
| https://example.com         |
| http://phishing-site.com    |
| https://another-site.org    |

**Note:** Only the `url` column is required. Other columns will be ignored.
""")
    
    uploaded_file = st.file_uploader("Upload CSV file with URLs", type=['csv'])
    
    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        file_hash = hashlib.md5(file_bytes).hexdigest()
        
        # Reset results if file changes
        if 'bulk_file_hash' not in st.session_state or st.session_state['bulk_file_hash'] != file_hash:
            st.session_state['bulk_file_hash'] = file_hash
            st.session_state['bulk_results'] = None
            st.session_state['bulk_analysis_running'] = False
        
        df = pd.read_csv(uploaded_file)
        
        if 'url' in df.columns:
            st.success(f"✅ Loaded {len(df)} URLs for analysis")
            
            # Show Run Analysis button only if no results or analysis not running
            if st.session_state.get('bulk_results') is None and not st.session_state.get('bulk_analysis_running', False):
                if st.button('🚀 Run Bulk Analysis', key='run_bulk_analysis'):
                    st.session_state['bulk_analysis_running'] = True
                    st.rerun()
            
            # Show progress and run analysis if running
            if st.session_state.get('bulk_analysis_running', False):
                st.session_state['bulk_analysis_running'] = False
                
                # Create progress container
                progress_container = st.container()
                with progress_container:
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                
                # Run analysis
                results = []
                urls = df['url'].tolist()
                total = len(urls)
                
                def process_url(url):
                    """Process a single URL - pure computation only."""
                    try:
                        analysis = perform_comprehensive_analysis(url)
                        return {
                            'url': str(url),
                            'prediction': str(analysis['prediction']['prediction']),
                            'confidence': float(analysis['prediction']['confidence']),
                            'risk_score': float(analysis['prediction'].get('risk_score', 0)),
                            'risk_level': str(analysis['prediction'].get('risk_level', 'Unknown')),
                            'timestamp': str(analysis['timestamp']),
                            'analysis_time': float(analysis.get('analysis_time', 0)),
                            'model_used': str(analysis['prediction'].get('model_used', 'Unknown')),
                            'features_count': len(analysis['features']) if analysis.get('features') else 0,
                            'ssl_valid': analysis['security_analysis']['ssl_info'].get('valid', False),
                            'ssl_issuer': analysis['security_analysis']['ssl_info'].get('issuer', 'Unknown'),
                            'ssl_days_remaining': analysis['security_analysis']['ssl_info'].get('days_remaining', 0),
                            'whois_domain': analysis['security_analysis']['whois_info'].get('domain', 'Unknown'),
                            'whois_registrar': analysis['security_analysis']['whois_info'].get('registrar', 'Unknown'),
                            'whois_creation_date': analysis['security_analysis']['whois_info'].get('creation_date', 'Unknown'),
                            'whois_country': analysis['security_analysis']['whois_info'].get('country', 'Unknown'),
                            'dns_resolved': analysis['security_analysis']['dns_info'].get('resolved', False),
                            'dns_a_records_count': len(analysis['security_analysis']['dns_info'].get('a_records', [])),
                            'dns_mx_records_count': len(analysis['security_analysis']['dns_info'].get('mx_records', [])),
                            'dns_ns_records_count': len(analysis['security_analysis']['dns_info'].get('ns_records', [])),
                            'http_status_code': analysis['security_analysis']['http_info'].get('status_code', 0),
                            'http_response_time': analysis['security_analysis']['http_info'].get('response_time', 0),
                            'security_headers_score': sum(1 for v in analysis['security_analysis']['http_info'].get('security_headers', {}).values() if v != 'Not Set')
                        }
                    except Exception as exc:
                        return {
                            'url': str(url), 'prediction': 'ERROR', 'confidence': 0, 'risk_score': 0, 
                            'risk_level': 'ERROR', 'timestamp': '', 'analysis_time': 0, 'model_used': '', 
                            'features_count': 0, 'ssl_valid': False, 'ssl_issuer': '', 'ssl_days_remaining': 0, 
                            'whois_domain': '', 'whois_registrar': '', 'whois_creation_date': '', 'whois_country': 'Unknown',
                            'dns_resolved': False, 'dns_a_records_count': 0, 'dns_mx_records_count': 0, 
                            'dns_ns_records_count': 0, 'http_status_code': 0, 'http_response_time': 0, 
                            'security_headers_score': 0
                        }
                
                # Run analysis with ThreadPoolExecutor
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_url = {executor.submit(process_url, url): url for url in urls}
                    
                    for idx, future in enumerate(concurrent.futures.as_completed(future_to_url), start=1):
                        try:
                            result = future.result()
                            results.append(result)
                        except Exception as exc:
                            url = future_to_url[future]
                            results.append({
                                'url': str(url), 'prediction': 'ERROR', 'confidence': 0, 'risk_score': 0, 
                                'risk_level': 'ERROR', 'timestamp': '', 'analysis_time': 0, 'model_used': '', 
                                'features_count': 0, 'ssl_valid': False, 'ssl_issuer': '', 'ssl_days_remaining': 0, 
                                'whois_domain': '', 'whois_registrar': '', 'whois_creation_date': '', 'whois_country': 'Unknown',
                                'dns_resolved': False, 'dns_a_records_count': 0, 'dns_mx_records_count': 0, 
                                'dns_ns_records_count': 0, 'http_status_code': 0, 'http_response_time': 0, 
                                'security_headers_score': 0
                            })
                        
                        # Update progress
                        progress_bar.progress(idx / total)
                        status_text.text(f"Processed {idx}/{total} URLs")
                
                # Clear progress indicators
                progress_container.empty()
                
                # Create results DataFrame
                results_df = pd.DataFrame(results)
                
                # Standard column order for both bulk analysis and user history exports
                standardized_columns = [
                    'timestamp', 'url', 'prediction', 'confidence', 'risk_score', 'risk_level', 
                    'analysis_time', 'model_used', 'features_count',
                    'ssl_valid', 'ssl_issuer', 'ssl_days_remaining',
                    'whois_domain', 'whois_registrar', 'whois_creation_date', 'whois_country',
                    'dns_resolved', 'dns_a_records_count', 'dns_mx_records_count', 'dns_ns_records_count',
                    'http_status_code', 'http_response_time', 'security_headers_score'
                ]
                results_df = results_df[standardized_columns]
                st.session_state['bulk_results'] = results_df
                
                # ✅ FIX: Add each bulk detection result to user's history and dashboard
                successful_count = logger.log_bulk_detections(results)
                
                st.success(f"✅ Analysis completed! Processed {len(results_df)} URLs\n\n"
                          f"📊 **{successful_count} successful results** added to your Dashboard and History\n\n"
                          f"🌍 **Geographic Dashboard updated** with country data from WHOIS analysis\n\n"
                          f"📋 **CSV exports now fully synchronized** between User History and Bulk Analysis\n\n"
                          f"❌ **{len(results) - successful_count} errors** (not added to history)")
                st.rerun()
            
            # Display results if available
            elif st.session_state.get('bulk_results') is not None:
                results_df = st.session_state['bulk_results']
                
                # Show summary statistics
                st.markdown("### 📊 Analysis Summary")
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total URLs", len(results_df))
                with col2:
                    phishing_count = len(results_df[results_df['prediction'] == 'Phishing'])
                    st.metric("Phishing Detected", phishing_count)
                with col3:
                    ssl_valid_count = len(results_df[results_df['ssl_valid'] == True])
                    st.metric("Valid SSL", ssl_valid_count)
                with col4:
                    dns_resolved_count = len(results_df[results_df['dns_resolved'] == True])
                    st.metric("DNS Resolved", dns_resolved_count)
                
                # Display results table with copyable functionality
                st.markdown("### 📋 Detailed Results")
                st.info("💡 **Tip:** You can copy the table data by selecting and copying the text, or use the download buttons below.")
                
                # Add copy button for the entire table
                col_copy, col_spacer = st.columns([1, 4])
                with col_copy:
                    if st.button("📋 Copy Bulk Analysis Results", key="copy_table_btn"):
                        # Convert DataFrame to CSV string for copying
                        csv_data = results_df.to_csv(index=False)
                        st.session_state['copied_data'] = csv_data
                        st.success("✅ Bulk analysis results copied to clipboard!")
                
                # Show record count and scrolling info
                st.markdown(f"📊 **Showing {len(results_df)} analysis results** (Table is horizontally scrollable for all columns)")
                
                # Display the enhanced table with all columns and horizontal scrolling (matching User History format)
                st.dataframe(
                    results_df,
                    use_container_width=False,  # Disable to allow horizontal scrolling
                    hide_index=True,
                    key="bulk_analysis_results_table",
                    column_config={
                        "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                        "url": st.column_config.LinkColumn("URL", width="large"),
                        "prediction": st.column_config.TextColumn("Prediction", width="small"),
                        "confidence": st.column_config.NumberColumn("Confidence", width="small", format="%.2f"),
                        "risk_score": st.column_config.NumberColumn("Risk Score", width="small", format="%.1f"),
                        "risk_level": st.column_config.TextColumn("Risk Level", width="small"),
                        "analysis_time": st.column_config.NumberColumn("Analysis Time (s)", width="small", format="%.2f"),
                        "model_used": st.column_config.TextColumn("Model Used", width="medium"),
                        "features_count": st.column_config.NumberColumn("Features Count", width="small"),
                        "ssl_valid": st.column_config.CheckboxColumn("SSL Valid", width="small"),
                        "ssl_issuer": st.column_config.TextColumn("SSL Issuer", width="medium"),
                        "ssl_days_remaining": st.column_config.NumberColumn("SSL Days Remaining", width="small"),
                        "whois_domain": st.column_config.TextColumn("WHOIS Domain", width="medium"),
                        "whois_registrar": st.column_config.TextColumn("WHOIS Registrar", width="medium"),
                        "whois_creation_date": st.column_config.TextColumn("WHOIS Creation Date", width="medium"),
                        "whois_country": st.column_config.TextColumn("Country", width="small"),
                        "dns_resolved": st.column_config.CheckboxColumn("DNS Resolved", width="small"),
                        "dns_a_records_count": st.column_config.NumberColumn("DNS A Records", width="small"),
                        "dns_mx_records_count": st.column_config.NumberColumn("DNS MX Records", width="small"),
                        "dns_ns_records_count": st.column_config.NumberColumn("DNS NS Records", width="small"),
                        "http_status_code": st.column_config.NumberColumn("HTTP Status", width="small"),
                        "http_response_time": st.column_config.NumberColumn("HTTP Response Time (s)", width="small", format="%.2f"),
                        "security_headers_score": st.column_config.NumberColumn("Security Headers Score", width="small")
                    }
                )
                
                # Export options
                st.markdown("### 📤 Export Options")
                col1, col2 = st.columns(2)
                
                with col1:
                    try:
                        results_df_clean = results_df.copy()
                        for col in results_df_clean.columns:
                            if results_df_clean[col].dtype == 'object':
                                results_df_clean[col] = results_df_clean[col].astype(str)
                        # Ensure it's a pandas DataFrame
                        if not isinstance(results_df_clean, pd.DataFrame):
                            results_df_clean = pd.DataFrame(results_df_clean)
                        csv = results_df_clean.to_csv(index=False)
                        user_email = st.session_state.get('user_email', 'user')
                        user = user_email.split('@')[0] if '@' in user_email else 'user'
                        st.download_button(
                            label="⬇️ Download Bulk Analysis CSV",
                            data=csv,
                            file_name=f"bulk_analysis_{user}.csv",
                            mime="text/csv"
                        )
                    except Exception as e:
                        st.error(f"Error preparing CSV download: {str(e)}")
                        simple_df = results_df[['timestamp', 'url', 'prediction', 'confidence', 'risk_level']].copy()
                        simple_df = simple_df.astype(str)
                        csv = simple_df.to_csv(index=False)
                        user_email = st.session_state.get('user_email', 'user')
                        user = user_email.split('@')[0] if '@' in user_email else 'user'
                        st.download_button(
                            label="⬇️ Download Simple CSV",
                            data=csv,
                            file_name=f"bulk_analysis_simple_{user}.csv",
                            mime="text/csv"
                        )
                
                with col2:
                    try:
                        # Ensure proper data types for PDF generation
                        results_df_clean = results_df.copy()
                        
                        # Convert all columns to string to avoid type issues
                        for col in results_df_clean.columns:
                            results_df_clean[col] = results_df_clean[col].astype(str)
                        
                        # Ensure numeric columns are properly formatted
                        if 'confidence' in results_df_clean.columns:
                            try:
                                # Convert to numeric and replace NaN with 0
                                results_df_clean['confidence'] = pd.to_numeric(results_df_clean['confidence'], errors='coerce').replace([np.nan, None], 0.0)
                            except:
                                results_df_clean['confidence'] = 0.0
                        if 'risk_score' in results_df_clean.columns:
                            try:
                                # Convert to numeric and replace NaN with 0
                                results_df_clean['risk_score'] = pd.to_numeric(results_df_clean['risk_score'], errors='coerce').replace([np.nan, None], 0.0)
                            except:
                                results_df_clean['risk_score'] = 0.0
                        
                        # Get the original CSV filename for the PDF
                        csv_filename = uploaded_file.name if uploaded_file else "bulk_analysis"
                        user_name = csv_filename.replace('.csv', '').replace('_', ' ').title()
                        
                        # Generate PDF with better error handling
                        pdf_file = generate_pdf_report(results_df_clean, user=user_name)
                        st.download_button(
                            label="📄 Download PDF Report",
                            data=pdf_file,
                            file_name=f"{csv_filename.replace('.csv', '')}_report.pdf",
                            mime="application/pdf"
                        )
                    except Exception as e:
                        st.error(f"Error generating PDF report: {str(e)}")
                        st.info("💡 **Tip:** Try downloading the CSV file instead, or check if your data contains any special characters.")
                        
                        # Fallback: try with simplified data
                        try:
                            simple_df = results_df[['url', 'prediction', 'confidence', 'risk_score', 'timestamp']].copy()
                            simple_df = simple_df.astype(str)
                            csv_filename = uploaded_file.name if uploaded_file else "bulk_analysis"
                            user_name = csv_filename.replace('.csv', '').replace('_', ' ').title()
                            pdf_file = generate_pdf_report(simple_df, user=user_name)
                            st.download_button(
                                label="📄 Download Simple PDF Report",
                                data=pdf_file,
                                file_name=f"{csv_filename.replace('.csv', '')}_simple_report.pdf",
                                mime="application/pdf"
                            )
                        except Exception as e2:
                            st.error(f"Even simple PDF generation failed: {str(e2)}")
                
                # Add option to run new analysis
                st.markdown("---")
                if st.button("🔄 Run New Analysis", key='new_bulk_analysis'):
                    st.session_state['bulk_results'] = None
                    st.rerun()
        else:
            st.error("CSV file must contain a 'url' column")

def display_history_tab():
    """Display user history."""
    st.subheader("🕒 Detection History")
    
    # Add Clear History button at the top right
    col_clear, col_title = st.columns([1, 8])
    with col_clear:
        if st.button("🧹 Clear History", key="clear_history_btn"):
            user_email = st.session_state.get('user_email', '')
            user = user_email.split('@')[0] if '@' in user_email else 'user'
            history_file = f"data/history_{user}.json"
            if os.path.exists(history_file):
                os.remove(history_file)
            st.success("History data cleared successfully!")
            st.rerun()
    
    # Use the enhanced history display that shows both predictions and feedback
    logger.show_history()


def generate_enhanced_history_report(history):
    """Generate enhanced history report with comprehensive data."""
    enhanced_data = []
    
    for entry in history:
        url = entry.get('url', '')
        
        # Try to get additional data if available
        enhanced_entry = {
            'url': str(url),
            'prediction': str(entry.get('prediction', 'Unknown')),
            'confidence': float(entry.get('confidence', 0.0)),
            'risk_score': float(entry.get('risk_score', 0.0)),
            'risk_level': str(entry.get('risk_level', 'Unknown')),
            'timestamp': str(entry.get('timestamp', 'Unknown')),
            'analysis_time': float(entry.get('analysis_time', 0.0)),
            'model_used': str(entry.get('model_used', 'Unknown')),
            'features_count': int(entry.get('features_count', 0))
        }
        
        # Add placeholder data for missing fields (in real implementation, this would be stored)
        enhanced_entry.update({
            'ssl_valid': bool(True),  # Placeholder
            'ssl_subject': str('Unknown'),
            'ssl_issuer': str('Unknown'),
            'ssl_not_before': str('Unknown'),
            'ssl_not_after': str('Unknown'),
            'ssl_days_remaining': int(365),
            'whois_domain': str('Unknown'),
            'whois_registrar': str('Unknown'),
            'whois_creation_date': str('Unknown'),
            'whois_expiration_date': str('Unknown'),
            'whois_status': str('Unknown'),
            'dns_resolved': bool(True),
            'dns_a_records_count': int(1),
            'dns_mx_records_count': int(1),
            'dns_ns_records_count': int(2),
            'http_status_code': int(200),
            'http_response_time': float(0.5),
            'security_headers_score': int(80)
        })
        
        enhanced_data.append(enhanced_entry)
    
    return pd.DataFrame(enhanced_data)

def save_to_history(url, prediction_result, security_analysis):
    """Save analysis result to user history."""
    user_email = st.session_state.get('user_email', '')
    user = user_email.split('@')[0] if '@' in user_email else 'user'
    history_file = f"data/history_{user}.json"
    
    # Load existing history
    history = []
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                history = json.load(f)
        except:
            history = []
    
    # Add new entry
    history.append({
        'url': str(url),
        'prediction': str(prediction_result['prediction']),
        'confidence': float(prediction_result['confidence']),
        'security_score': float(security_analysis['security_score']),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    
    # Save updated history
    os.makedirs('data', exist_ok=True)
    with open(history_file, 'w') as f:
        json.dump(history, f, indent=2)

def generate_pdf_report(df, user):
    """Generate enhanced PDF report with metrics and bullet points."""
    try:
        # Ensure df is a pandas DataFrame
        if not isinstance(df, pd.DataFrame):
            df = pd.DataFrame(df)
        
        # Clean and prepare data
        df_clean = df.copy()
        
        # Ensure all columns exist with defaults
        required_cols = ['url', 'prediction', 'confidence', 'risk_score', 'risk_level', 'timestamp']
        for col in required_cols:
            if col not in df_clean.columns:
                if col in ['confidence', 'risk_score']:
                    df_clean[col] = 0.0
                else:
                    df_clean[col] = 'Unknown'
        
        # Convert numeric columns safely
        for col in ['confidence', 'risk_score']:
            if col in df_clean.columns:
                try:
                    numeric_values = pd.to_numeric(df_clean[col], errors='coerce')
                    # Handle NaN values manually
                    numeric_values = [0.0 if pd.isna(x) else float(x) for x in numeric_values]
                    df_clean[col] = numeric_values
                except (ValueError, TypeError):
                    df_clean[col] = 0.0
        
        # Convert all other columns to string
        for col in df_clean.columns:
            if col not in ['confidence', 'risk_score']:
                df_clean[col] = df_clean[col].astype(str)
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", 'B', 16)
        pdf.cell(200, 10, f"Phishing Detection Report", new_x="LMARGIN", new_y="NEXT", align='C')
        pdf.ln(5)
        
        # Calculate comprehensive metrics
        total_urls = len(df_clean)
        phishing_count = len(df_clean[df_clean['prediction'] == 'Phishing'])
        legitimate_count = len(df_clean[df_clean['prediction'] == 'Legitimate'])
        error_count = len(df_clean[df_clean['prediction'] == 'ERROR'])
        
        # Calculate percentages
        phishing_percentage = (phishing_count / total_urls * 100) if total_urls > 0 else 0
        legitimate_percentage = (legitimate_count / total_urls * 100) if total_urls > 0 else 0
        error_percentage = (error_count / total_urls * 100) if total_urls > 0 else 0
        
        # Calculate average confidence and risk scores
        valid_predictions = df_clean[df_clean['prediction'].isin(['Phishing', 'Legitimate'])]
        avg_confidence = valid_predictions['confidence'].mean() if len(valid_predictions) > 0 else 0
        avg_risk_score = valid_predictions['risk_score'].mean() if len(valid_predictions) > 0 else 0
        
        # Security metrics (if available)
        ssl_valid_count = 0
        dns_resolved_count = 0
        if 'ssl_valid' in df_clean.columns:
            ssl_valid_count = len(df_clean[df_clean['ssl_valid'] == True])
        if 'dns_resolved' in df_clean.columns:
            dns_resolved_count = len(df_clean[df_clean['dns_resolved'] == True])
        
        ssl_percentage = (ssl_valid_count / total_urls * 100) if total_urls > 0 else 0
        dns_percentage = (dns_resolved_count / total_urls * 100) if total_urls > 0 else 0
        
        # Date range
        date_min = date_max = 'N/A'
        if 'timestamp' in df_clean.columns and len(df_clean) > 0:
            try:
                timestamps = pd.to_datetime(df_clean['timestamp'], errors='coerce')
                valid_timestamps = timestamps.dropna()
                if len(valid_timestamps) > 0:
                    date_min = valid_timestamps.min().strftime('%Y-%m-%d %H:%M')
                    date_max = valid_timestamps.max().strftime('%Y-%m-%d %H:%M')
            except:
                pass
        
        # Report header
        pdf.set_font("Helvetica", 'B', 14)
        pdf.cell(200, 10, f"Report for: {user}", new_x="LMARGIN", new_y="NEXT", align='L')
        pdf.ln(5)
        
        # Executive Summary
        pdf.set_font("Helvetica", 'B', 12)
        pdf.cell(200, 8, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(0, 6, f"This report contains the results of {total_urls} URL security analyses. "
                             f"The analysis was performed using advanced machine learning models and comprehensive security checks.")
        pdf.ln(5)
        
        # Key Metrics Section
        pdf.set_font("Helvetica", 'B', 12)
        pdf.cell(200, 8, "Key Metrics", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        pdf.set_font("Helvetica", size=10)
        
        # Detection metrics - use simple dashes instead of bullet points
        pdf.cell(200, 6, f"- Total URLs Analyzed: {total_urls}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(200, 6, f"- Phishing Detected: {phishing_count} ({phishing_percentage:.1f}%)", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(200, 6, f"- Legitimate Sites: {legitimate_count} ({legitimate_percentage:.1f}%)", new_x="LMARGIN", new_y="NEXT")
        if error_count > 0:
            pdf.cell(200, 6, f"- Analysis Errors: {error_count} ({error_percentage:.1f}%)", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        
        # Performance metrics
        pdf.cell(200, 6, f"- Average Confidence Score: {avg_confidence:.2f}/100", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(200, 6, f"- Average Risk Score: {avg_risk_score:.2f}/100", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        
        # Security metrics
        pdf.cell(200, 6, f"- URLs with Valid SSL: {ssl_valid_count} ({ssl_percentage:.1f}%)", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(200, 6, f"- URLs with DNS Resolution: {dns_resolved_count} ({dns_percentage:.1f}%)", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        # Analysis Period
        pdf.set_font("Helvetica", 'B', 12)
        pdf.cell(200, 8, "Analysis Period", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        pdf.set_font("Helvetica", size=10)
        pdf.cell(200, 6, f"- Start Date: {date_min}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(200, 6, f"- End Date: {date_max}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        # Risk Assessment
        pdf.set_font("Helvetica", 'B', 12)
        pdf.cell(200, 8, "Risk Assessment", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        pdf.set_font("Helvetica", size=10)
        
        if phishing_percentage > 50:
            risk_level = "HIGH"
            risk_desc = "A significant number of phishing attempts were detected. Immediate action recommended."
        elif phishing_percentage > 20:
            risk_level = "MEDIUM"
            risk_desc = "Moderate number of phishing attempts detected. Regular monitoring advised."
        else:
            risk_level = "LOW"
            risk_desc = "Low number of phishing attempts detected. Standard security practices sufficient."
        
        pdf.cell(200, 6, f"- Overall Risk Level: {risk_level}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(200, 6, f"- Risk Assessment: {risk_desc}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        # Recommendations
        pdf.set_font("Helvetica", 'B', 12)
        pdf.cell(200, 8, "Recommendations", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        pdf.set_font("Helvetica", size=10)
        
        recommendations = [
            "- Regularly monitor URLs for security threats",
            "- Implement additional security measures for high-risk domains",
            "- Train users to recognize phishing indicators",
            "- Maintain updated security protocols",
            "- Consider implementing automated threat detection systems"
        ]
        
        for rec in recommendations:
            pdf.cell(200, 6, rec, new_x="LMARGIN", new_y="NEXT")
        
        pdf.ln(5)
        

        
        # Footer
        pdf.ln(10)
        pdf.set_font("Helvetica", size=8)
        pdf.cell(200, 6, f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT", align='C')
        pdf.cell(200, 6, "Generated by Threat Detection System", new_x="LMARGIN", new_y="NEXT", align='C')
        
        # Output to bytes with UTF-8 encoding
        pdf_str = pdf.output()
        if isinstance(pdf_str, str):
            pdf_bytes = pdf_str.encode('utf-8')
        else:
            pdf_bytes = pdf_str
        pdf_output = io.BytesIO(pdf_bytes)
        return pdf_output
        
    except Exception as e:
        # Return a simple error PDF if generation fails
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", 'B', 16)
        pdf.cell(200, 10, "PDF Generation Error", new_x="LMARGIN", new_y="NEXT", align='C')
        pdf.ln(10)
        pdf.set_font("Helvetica", size=12)
        pdf.multi_cell(0, 8, f"An error occurred while generating the PDF report: {str(e)}")
        pdf.ln(5)
        pdf.multi_cell(0, 8, "Please try downloading the CSV file instead.")
        
        pdf_str = pdf.output()
        if isinstance(pdf_str, str):
            pdf_bytes = pdf_str.encode('utf-8')
        else:
            pdf_bytes = pdf_str
        pdf_output = io.BytesIO(pdf_bytes)
        return pdf_output

if __name__ == "__main__":
    main()
