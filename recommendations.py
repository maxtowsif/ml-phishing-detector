# recommendations.py
# ---------------------------------------------------------
# Smart Recommendations Module
# Provides intelligent suggestions based on analysis results
# ---------------------------------------------------------

import streamlit as st
from datetime import datetime, timedelta
import json
import os


def get_security_recommendations(analysis_results: dict) -> list:
    """
    Generate security recommendations based on analysis results.
    
    Args:
        analysis_results (dict): Analysis results
        
    Returns:
        list: List of recommendations
    """
    recommendations = []
    
    # SSL Certificate recommendations
    ssl_info = analysis_results.get('ssl_certificate', {})
    if not ssl_info.get('valid', False):
        recommendations.append({
            'type': 'critical',
            'title': 'SSL Certificate Issue',
            'description': 'The website has an invalid SSL certificate. Avoid entering sensitive information.',
            'action': 'Do not proceed with this website'
        })
    elif ssl_info.get('days_remaining', 0) < 30:
        recommendations.append({
            'type': 'warning',
            'title': 'SSL Certificate Expiring Soon',
            'description': f"SSL certificate expires in {ssl_info['days_remaining']} days.",
            'action': 'Monitor certificate renewal'
        })
    
    # WHOIS recommendations
    whois_info = analysis_results.get('whois_data', {})
    if whois_info.get('registrar', 'Unknown') == 'Unknown':
        recommendations.append({
            'type': 'warning',
            'title': 'Unknown Domain Registrar',
            'description': 'Domain registrar information is not available.',
            'action': 'Exercise caution with this website'
        })
    
    # DNS recommendations
    dns_info = analysis_results.get('dns_resolution', {})
    if not dns_info.get('resolved', False):
        recommendations.append({
            'type': 'critical',
            'title': 'DNS Resolution Failed',
            'description': 'Domain name cannot be resolved.',
            'action': 'Avoid this website'
        })
    
    # HTTP recommendations
    http_info = analysis_results.get('http_response', {})
    if http_info.get('status_code') not in [200, 301, 302]:
        recommendations.append({
            'type': 'warning',
            'title': 'HTTP Error',
            'description': f"Website returned status code {http_info.get('status_code')}.",
            'action': 'Check if the website is accessible'
        })
    
    # Security headers recommendations
    security_headers = http_info.get('security_headers', {})
    missing_headers = []
    for header, value in security_headers.items():
        if value == 'Not Set':
            missing_headers.append(header)
    
    if missing_headers:
        recommendations.append({
            'type': 'info',
            'title': 'Missing Security Headers',
            'description': f"Website is missing security headers: {', '.join(missing_headers)}.",
            'action': 'Consider using additional security measures'
        })
    
    # Risk-based recommendations
    risk_assessment = analysis_results.get('risk_assessment', {})
    risk_score = risk_assessment.get('risk_score', 0)
    
    if risk_score >= 80:
        recommendations.append({
            'type': 'critical',
            'title': 'High Risk Website',
            'description': 'This website has multiple security concerns.',
            'action': 'Strongly recommend avoiding this website'
        })
    elif risk_score >= 60:
        recommendations.append({
            'type': 'warning',
            'title': 'Moderate Risk Website',
            'description': 'This website has some security concerns.',
            'action': 'Exercise caution and verify legitimacy'
        })
    
    return recommendations


def get_user_recommendations(user_email: str) -> list:
    """
    Generate personalized recommendations based on user history.
    
    Args:
        user_email (str): User email
        
    Returns:
        list: List of personalized recommendations
    """
    recommendations = []
    
    # Load user history
    user = user_email.split("@")[0]
    history_file = f"data/history_{user}.json"
    
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                history = json.load(f)
            
            # Analyze user patterns
            total_scans = len(history)
            threats_detected = sum(1 for entry in history if entry.get('prediction') == 'Phishing')
            threat_ratio = (threats_detected / total_scans) * 100 if total_scans > 0 else 0
            
            # Generate recommendations based on patterns
            if total_scans < 5:
                recommendations.append({
                    'type': 'info',
                    'title': 'Getting Started',
                    'description': 'You\'re new to the platform. Try analyzing different types of URLs.',
                    'action': 'Explore various URL patterns'
                })
            
            if threat_ratio > 50:
                recommendations.append({
                    'type': 'warning',
                    'title': 'High Threat Detection Rate',
                    'description': f'You\'ve detected threats in {threat_ratio:.1f}% of your scans.',
                    'action': 'Review your browsing habits and sources'
                })
            
            if total_scans > 20:
                recommendations.append({
                    'type': 'success',
                    'title': 'Active User',
                    'description': f'You\'ve performed {total_scans} scans. Great job staying vigilant!',
                    'action': 'Continue monitoring URLs regularly'
                })
                
        except Exception:
            pass
    
    return recommendations


def get_general_security_tips() -> list:
    """
    Provide general cybersecurity tips.
    
    Returns:
        list: List of security tips
    """
    return [
        {
            'type': 'tip',
            'title': 'Check URL Carefully',
            'description': 'Look for typos, extra characters, or suspicious domains.',
            'action': 'Always verify the URL before clicking'
        },
        {
            'type': 'tip',
            'title': 'Use HTTPS',
            'description': 'Ensure websites use HTTPS encryption for sensitive data.',
            'action': 'Look for the padlock icon in your browser'
        },
        {
            'type': 'tip',
            'title': 'Verify Domain Age',
            'description': 'Newly registered domains are often used for phishing.',
            'action': 'Check domain registration dates'
        },
        {
            'type': 'tip',
            'title': 'Beware of Urgency',
            'description': 'Phishing often creates false urgency to bypass security.',
            'action': 'Take time to verify before acting'
        },
        {
            'type': 'tip',
            'title': 'Check Email Senders',
            'description': 'Verify email addresses match the claimed organization.',
            'action': 'Look for slight variations in email addresses'
        }
    ]


def display_recommendations(analysis_results: dict = None, user_email: str = None):
    """
    Display all relevant recommendations.
    
    Args:
        analysis_results (dict): Analysis results (optional)
        user_email (str): User email (optional)
    """
    st.subheader("Smart Recommendations")
    
    all_recommendations = []
    
    # Get analysis-based recommendations
    if analysis_results:
        analysis_recs = get_security_recommendations(analysis_results)
        all_recommendations.extend(analysis_recs)
    
    # Get user-based recommendations
    if user_email:
        user_recs = get_user_recommendations(user_email)
        all_recommendations.extend(user_recs)
    
    # Get general tips
    general_tips = get_general_security_tips()
    
    # Display recommendations
    if all_recommendations:
        st.markdown("#### Analysis-Based Recommendations")
        for rec in all_recommendations:
            if rec['type'] == 'critical':
                st.error(f"**{rec['title']}**")
            elif rec['type'] == 'warning':
                st.warning(f"**{rec['title']}**")
            elif rec['type'] == 'info':
                st.info(f"**{rec['title']}**")
            elif rec['type'] == 'success':
                st.success(f"**{rec['title']}**")
            else:
                st.write(f"**{rec['title']}**")
            
            st.write(f"{rec['description']}")
            st.write(f"**Action:** {rec['action']}")
            st.markdown("---")
    
    # Display general tips
    st.markdown("#### General Security Tips")
    for tip in general_tips:
        st.info(f"**{tip['title']}**")
        st.write(f"{tip['description']}")
        st.write(f"**Action:** {tip['action']}")
        st.markdown("---")


def generate_recommendations(url: str, prediction_result: dict, security_analysis: dict) -> list:
    """
    Generate comprehensive recommendations based on URL analysis.
    
    Args:
        url (str): URL that was analyzed
        prediction_result (dict): ML model prediction results
        security_analysis (dict): Security analysis results
        
    Returns:
        list: List of recommendations
    """
    recommendations = []
    
    # Prediction-based recommendations
    prediction = prediction_result.get('prediction', 'Unknown')
    confidence = prediction_result.get('confidence', 0)
    risk_level = prediction_result.get('risk_level', 'Unknown')
    
    if prediction == 'Phishing':
        if confidence > 0.9:
            recommendations.append("🚨 HIGH RISK: This URL is highly likely to be a phishing attempt. Avoid at all costs.")
        elif confidence > 0.7:
            recommendations.append("⚠️ MODERATE RISK: This URL shows suspicious characteristics. Proceed with extreme caution.")
        else:
            recommendations.append("⚠️ LOW RISK: This URL has some concerning features. Verify before proceeding.")
    else:
        if confidence > 0.9:
            recommendations.append("✅ SAFE: This URL appears to be legitimate with high confidence.")
        elif confidence > 0.7:
            recommendations.append("✅ LIKELY SAFE: This URL appears legitimate but verify before entering sensitive data.")
        else:
            recommendations.append("⚠️ UNCERTAIN: This URL has mixed signals. Exercise caution.")
    
    # Security analysis recommendations
    if security_analysis:
        ssl_info = security_analysis.get('ssl_info', {})
        whois_info = security_analysis.get('whois_info', {})
        dns_info = security_analysis.get('dns_info', {})
        http_info = security_analysis.get('http_info', {})
        
        # SSL recommendations
        if not ssl_info.get('valid', False):
            recommendations.append("🔒 SSL Certificate: Invalid or missing SSL certificate. Avoid entering sensitive information.")
        elif ssl_info.get('days_remaining', 0) < 30:
            recommendations.append("⚠️ SSL Certificate: Expires soon. Monitor for renewal.")
        
        # Domain age recommendations
        if whois_info.get('creation_date') != 'Unknown':
            try:
                creation_date = datetime.strptime(whois_info['creation_date'], '%Y-%m-%d')
                domain_age = (datetime.now() - creation_date).days
                if domain_age < 30:
                    recommendations.append("🆕 New Domain: This domain was registered recently. Verify legitimacy.")
                elif domain_age < 365:
                    recommendations.append("📅 Relatively New Domain: Domain is less than a year old. Exercise caution.")
            except:
                pass
        
        # DNS recommendations
        if not dns_info.get('resolved', False):
            recommendations.append("🌐 DNS Issue: Domain cannot be resolved. Avoid this website.")
        
        # HTTP recommendations
        status_code = http_info.get('status_code', 0)
        if status_code not in [200, 301, 302]:
            recommendations.append(f"⚠️ HTTP Error: Website returned status code {status_code}. Check accessibility.")
        
        # Security headers recommendations
        security_headers = http_info.get('security_headers', {})
        missing_headers = [k for k, v in security_headers.items() if v == 'Not Set']
        if missing_headers:
            recommendations.append(f"🛡️ Missing Security Headers: {', '.join(missing_headers)}. Consider additional precautions.")
    
    return recommendations


def get_learning_resources() -> dict:
    """
    Get cybersecurity learning resources.
    
    Returns:
        dict: Learning resources organized by category
    """
    return {
        "beginner": [
            {
                "title": "What is Phishing?",
                "description": "Learn the basics of phishing attacks and how to identify them.",
                "url": "https://www.phishing.org/what-is-phishing"
            },
            {
                "title": "URL Analysis Guide",
                "description": "Step-by-step guide to analyzing suspicious URLs.",
                "url": "https://www.sans.org/security-awareness-training/"
            }
        ],
        "intermediate": [
            {
                "title": "Advanced Phishing Detection",
                "description": "Advanced techniques for detecting sophisticated phishing attempts.",
                "url": "https://www.cisa.gov/phishing"
            },
            {
                "title": "Security Headers Guide",
                "description": "Understanding HTTP security headers and their importance.",
                "url": "https://owasp.org/www-project-secure-headers/"
            }
        ],
        "advanced": [
            {
                "title": "Machine Learning in Cybersecurity",
                "description": "How AI and ML are used in threat detection.",
                "url": "https://www.mitre.org/publications/technical-papers"
            },
            {
                "title": "DNS Security Best Practices",
                "description": "Advanced DNS security and monitoring techniques.",
                "url": "https://www.ietf.org/rfc/rfc4033.txt"
            }
        ]
    } 