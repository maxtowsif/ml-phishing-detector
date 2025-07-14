# url_analysis.py
# ---------------------------------------------------------
# Enhanced URL Analysis with Comprehensive Security Checks
# ---------------------------------------------------------

import streamlit as st
import requests
import socket
import ssl
import whois
import dns.resolver
import dns.reversename
from urllib.parse import urlparse
import re
from datetime import datetime, timedelta
import json
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd


def analyze_url_security(url):
    """Comprehensive URL security analysis."""
    
    # Initialize analysis results
    analysis = {
        'url': url,
        'parsed_url': parse_url(url),
        'ssl_info': analyze_ssl_certificate(url),
        'whois_info': analyze_whois_data(url),
        'dns_info': analyze_dns_records(url),
        'http_info': analyze_http_response(url),
        'security_score': 0,
        'risk_factors': [],
        'recommendations': []
    }
    
    # Calculate security score
    analysis['security_score'] = calculate_security_score(analysis)
    analysis['risk_factors'] = identify_risk_factors(analysis)
    analysis['recommendations'] = generate_recommendations(analysis)
    
    return analysis


def parse_url(url):
    """Parse URL and extract components."""
    try:
        parsed = urlparse(url)
        return {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'path': parsed.path,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'domain': parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc,
            'port': parsed.port if parsed.port else (443 if parsed.scheme == 'https' else 80)
        }
    except Exception as e:
        return {'error': str(e)}


def analyze_ssl_certificate(url):
    """Analyze SSL certificate details."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
        port = parsed.port if parsed.port else 443
        
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                if not cert:
                    raise Exception("No certificate received")
                
                # Extract certificate details safely
                subject_name = 'Unknown'
                issuer_name = 'Unknown'
                
                # Extract subject common name
                if 'subject' in cert and cert['subject']:
                    for rdn in cert['subject']:
                        for name_type, value in rdn:
                            if name_type == 'commonName':
                                subject_name = value
                                break
                
                # Extract issuer common name
                if 'issuer' in cert and cert['issuer']:
                    for rdn in cert['issuer']:
                        for name_type, value in rdn:
                            if name_type == 'commonName':
                                issuer_name = value
                                break
                
                # Parse dates safely
                not_before_date = 'Unknown'
                not_after_date = 'Unknown'
                days_remaining = 0
                
                try:
                    if 'notBefore' in cert and isinstance(cert['notBefore'], str):
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        not_before_date = not_before.strftime('%Y-%m-%d')
                    
                    if 'notAfter' in cert and isinstance(cert['notAfter'], str):
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        not_after_date = not_after.strftime('%Y-%m-%d')
                        days_remaining = (not_after - datetime.now()).days
                except Exception:
                    pass
                
                # Get SAN (Subject Alternative Names) safely
                san_list = cert.get('subjectAltName', [])
                san_count = len(san_list) if san_list else 0
                
                return {
                    'valid': True,
                    'subject': subject_name,
                    'issuer': issuer_name,
                    'not_before': not_before_date,
                    'not_after': not_after_date,
                    'days_remaining': days_remaining,
                    'serial_number': str(cert.get('serialNumber', 'Unknown')),
                    'version': str(cert.get('version', 'Unknown')),
                    'signature_algorithm': str(cert.get('signatureAlgorithm', 'Unknown')),
                    'key_size': len(str(cert.get('serialNumber', ''))),
                    'san_count': san_count,
                    'ocsp_stapling': False,  # Simplified for now
                    'hsts': False  # Simplified for now
                }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e),
            'subject': 'Unknown',
            'issuer': 'Unknown',
            'not_before': 'Unknown',
            'not_after': 'Unknown',
            'days_remaining': 0,
            'serial_number': 'Unknown',
            'version': 'Unknown',
            'signature_algorithm': 'Unknown',
            'key_size': 0,
            'san_count': 0,
            'ocsp_stapling': False,
            'hsts': False
        }


def analyze_whois_data(url):
    """Analyze WHOIS data for domain information."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
        
        w = whois.whois(domain)
        
        return {
            'domain': domain,
            'registrar': w.registrar or 'Unknown',
            'creation_date': w.creation_date[0].strftime('%Y-%m-%d') if w.creation_date and isinstance(w.creation_date, list) else 
                           (w.creation_date.strftime('%Y-%m-%d') if w.creation_date else 'Unknown'),
            'expiration_date': w.expiration_date[0].strftime('%Y-%m-%d') if w.expiration_date and isinstance(w.expiration_date, list) else 
                             (w.expiration_date.strftime('%Y-%m-%d') if w.expiration_date else 'Unknown'),
            'updated_date': w.updated_date[0].strftime('%Y-%m-%d') if w.updated_date and isinstance(w.updated_date, list) else 
                          (w.updated_date.strftime('%Y-%m-%d') if w.updated_date else 'Unknown'),
            'status': w.status[0] if w.status and isinstance(w.status, list) else (w.status or 'Unknown'),
            'name_servers': w.name_servers if w.name_servers else [],
            'emails': w.emails if w.emails else [],
            'org': w.org or 'Unknown',
            'country': w.country or 'Unknown'
        }
    except Exception as e:
        return {
            'domain': domain if 'domain' in locals() else 'Unknown',
            'registrar': 'Unknown',
            'creation_date': 'Unknown',
            'expiration_date': 'Unknown',
            'updated_date': 'Unknown',
            'status': 'Unknown',
            'name_servers': [],
            'emails': [],
            'org': 'Unknown',
            'country': 'Unknown',
            'error': str(e)
        }


def analyze_dns_records(url):
    """Analyze DNS records for domain."""
    domain = 'Unknown'
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
        
        dns_info = {
            'domain': domain,
            'resolved': True,
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'soa_record': None,
            'ptr_records': []
        }
        
        # A Records
        try:
            answers = dns.resolver.resolve(domain, 'A')
            dns_info['a_records'] = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        # AAAA Records
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            dns_info['aaaa_records'] = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        # MX Records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            dns_info['mx_records'] = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        # NS Records
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            dns_info['ns_records'] = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        # TXT Records
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            dns_info['txt_records'] = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        # CNAME Records
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            dns_info['cname_records'] = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        # SOA Record
        try:
            answers = dns.resolver.resolve(domain, 'SOA')
            dns_info['soa_record'] = str(answers[0])
        except Exception:
            pass
        
        return dns_info
        
    except Exception as e:
        return {
            'domain': domain,
            'resolved': False,
            'error': str(e),
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'soa_record': None,
            'ptr_records': []
        }


def analyze_http_response(url):
    """Analyze HTTP response and headers."""
    try:
        start_time = datetime.now()
        response = requests.get(url, timeout=10, allow_redirects=True)
        response_time = (datetime.now() - start_time).total_seconds()
        
        # Count redirects
        redirect_count = len(response.history)
        
        # Analyze security headers
        security_headers = {
            'x_frame_options': response.headers.get('X-Frame-Options', 'Not Set'),
            'x_content_type_options': response.headers.get('X-Content-Type-Options', 'Not Set'),
            'x_xss_protection': response.headers.get('X-XSS-Protection', 'Not Set'),
            'strict_transport_security': response.headers.get('Strict-Transport-Security', 'Not Set'),
            'content_security_policy': response.headers.get('Content-Security-Policy', 'Not Set'),
            'referrer_policy': response.headers.get('Referrer-Policy', 'Not Set'),
            'permissions_policy': response.headers.get('Permissions-Policy', 'Not Set')
        }
        
        return {
            'status_code': response.status_code,
            'status_text': response.reason,
            'server': response.headers.get('Server', 'Unknown'),
            'content_type': response.headers.get('Content-Type', 'Unknown'),
            'content_length': response.headers.get('Content-Length', 'Unknown'),
            'response_time': response_time,
            'redirect_count': redirect_count,
            'final_url': response.url,
            'security_headers': security_headers,
            'all_headers': dict(response.headers),
            'cookies': dict(response.cookies),
            'encoding': response.encoding,
            'is_redirect': response.is_redirect,
            'is_permanent_redirect': response.is_permanent_redirect
        }
        
    except Exception as e:
        return {
            'status_code': 0,
            'status_text': 'Error',
            'server': 'Unknown',
            'content_type': 'Unknown',
            'content_length': 'Unknown',
            'response_time': 0,
            'redirect_count': 0,
            'final_url': url,
            'security_headers': {},
            'all_headers': {},
            'cookies': {},
            'encoding': 'Unknown',
            'is_redirect': False,
            'is_permanent_redirect': False,
            'error': str(e)
        }


def calculate_security_score(analysis):
    """Calculate overall security score (0-100)."""
    score = 100
    
    # SSL Certificate (30 points)
    if analysis['ssl_info']['valid']:
        if analysis['ssl_info']['days_remaining'] > 90:
            score += 0
        elif analysis['ssl_info']['days_remaining'] > 30:
            score -= 10
        else:
            score -= 30
    else:
        score -= 30
    
    # Domain Age (20 points)
    if analysis['whois_info']['creation_date'] != 'Unknown':
        try:
            creation_date = datetime.strptime(analysis['whois_info']['creation_date'], '%Y-%m-%d')
            domain_age = (datetime.now() - creation_date).days
            if domain_age < 30:
                score -= 20
            elif domain_age < 365:
                score -= 10
        except:
            score -= 10
    else:
        score -= 20
    
    # DNS Resolution (15 points)
    if not analysis['dns_info']['resolved']:
        score -= 15
    
    # HTTP Response (15 points)
    if analysis['http_info']['status_code'] not in [200, 301, 302]:
        score -= 15
    
    # Security Headers (20 points)
    security_headers = analysis['http_info']['security_headers']
    missing_headers = sum(1 for v in security_headers.values() if v == 'Not Set')
    score -= (missing_headers * 3)  # -3 points per missing header
    
    return max(0, score)


def identify_risk_factors(analysis):
    """Identify specific risk factors."""
    risk_factors = []
    
    # SSL Certificate risks
    if not analysis['ssl_info']['valid']:
        risk_factors.append("Invalid SSL Certificate")
    elif analysis['ssl_info']['days_remaining'] < 30:
        risk_factors.append("SSL Certificate Expiring Soon")
    
    # Domain age risks
    if analysis['whois_info']['creation_date'] != 'Unknown':
        try:
            creation_date = datetime.strptime(analysis['whois_info']['creation_date'], '%Y-%m-%d')
            domain_age = (datetime.now() - creation_date).days
            if domain_age < 30:
                risk_factors.append("New Domain (< 30 days)")
            elif domain_age < 365:
                risk_factors.append("Relatively New Domain (< 1 year)")
        except:
            risk_factors.append("Unknown Domain Age")
    else:
        risk_factors.append("Unknown Domain Age")
    
    # DNS risks
    if not analysis['dns_info']['resolved']:
        risk_factors.append("DNS Resolution Failed")
    
    # HTTP risks
    if analysis['http_info']['status_code'] not in [200, 301, 302]:
        risk_factors.append(f"HTTP Error: {analysis['http_info']['status_code']}")
    
    # Security headers risks
    security_headers = analysis['http_info']['security_headers']
    missing_headers = [k for k, v in security_headers.items() if v == 'Not Set']
    if missing_headers:
        risk_factors.append(f"Missing Security Headers: {', '.join(missing_headers)}")
    
    # Redirect risks
    if analysis['http_info']['redirect_count'] > 3:
        risk_factors.append("Excessive Redirects")
    
    return risk_factors


def generate_recommendations(analysis):
    """Generate security recommendations."""
    recommendations = []
    
    # SSL recommendations
    if not analysis['ssl_info']['valid']:
        recommendations.append("Avoid this site - SSL certificate is invalid")
    elif analysis['ssl_info']['days_remaining'] < 30:
        recommendations.append("SSL certificate expires soon - proceed with caution")
    
    # Domain recommendations
    if analysis['whois_info']['creation_date'] != 'Unknown':
        try:
            creation_date = datetime.strptime(analysis['whois_info']['creation_date'], '%Y-%m-%d')
            domain_age = (datetime.now() - creation_date).days
            if domain_age < 30:
                recommendations.append("New domain detected - verify legitimacy before proceeding")
        except:
            pass
    
    # Security headers recommendations
    security_headers = analysis['http_info']['security_headers']
    if security_headers.get('x_frame_options') == 'Not Set':
        recommendations.append("Site lacks clickjacking protection")
    if security_headers.get('content_security_policy') == 'Not Set':
        recommendations.append("Site lacks Content Security Policy")
    
    # General recommendations
    if analysis['security_score'] < 50:
        recommendations.append("High risk site - avoid entering sensitive information")
    elif analysis['security_score'] < 70:
        recommendations.append("Moderate risk site - proceed with caution")
    else:
        recommendations.append("Site appears secure - standard precautions apply")
    
    return recommendations


def display_security_analysis(analysis):
    """Display comprehensive security analysis with enhanced visualization."""
    st.subheader("🔒 Security Analysis")
    
    # Overall security score - left aligned
    score = analysis['security_score']
    if score >= 80:
        color = "green"
        status = "Secure"
    elif score >= 60:
        color = "orange"
        status = "Moderate"
    else:
        color = "red"
        status = "High Risk"
    
    # Left-aligned security score and status
    st.markdown(f"### Security Score: {score}/100")
    st.markdown(f"**Status:** {status}")
    
    # Progress bar
    st.progress(score / 100)
    
    # Risk factors
    if analysis['risk_factors']:
        st.markdown("### ⚠️ Risk Factors")
        for risk in analysis['risk_factors']:
            st.error(f"• {risk}")
    
    # Detailed analysis tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "SSL Certificate", "Domain Info", "DNS Analysis", "HTTP Security"
    ])
    
    with tab1:
        display_ssl_analysis(analysis['ssl_info'])
    
    with tab2:
        display_whois_analysis(analysis['whois_info'])
    
    with tab3:
        display_dns_analysis(analysis['dns_info'])
    
    with tab4:
        display_http_analysis(analysis['http_info'])
    
    # Recommendations
    st.markdown("### 💡 Security Recommendations")
    for rec in analysis['recommendations']:
        st.info(f"• {rec}")


def display_ssl_analysis(ssl_info):
    """Display SSL certificate analysis with enhanced visualization."""
    col1, col2 = st.columns(2)
    
    with col1:
        if ssl_info['valid']:
            st.success("**SSL Certificate Status: Valid**")
            
            # Certificate details
            details = {
                "Subject": ssl_info['subject'],
                "Issuer": ssl_info['issuer'],
                "Valid From": ssl_info['not_before'],
                "Valid Until": ssl_info['not_after'],
                "Serial Number": ssl_info['serial_number'],
                "Signature Algorithm": ssl_info['signature_algorithm']
            }
            
            for key, value in details.items():
                st.info(f"**{key}:** {value}")
        else:
            st.error("**SSL Certificate Status: Invalid**")
            st.error(f"**Error:** {ssl_info.get('error', 'Unknown error')}")
    
    with col2:
        if ssl_info['valid']:
            # Certificate expiry visualization
            days_remaining = ssl_info['days_remaining']
            
            if days_remaining > 90:
                color = "green"
                status = "Good"
            elif days_remaining > 30:
                color = "orange"
                status = "Warning"
            else:
                color = "red"
                status = "Critical"
            
            st.markdown(f"**Certificate Health: {status}**")
            
            # Gauge chart for certificate expiry
            fig = go.Figure(go.Indicator(
                mode = "gauge+number+delta",
                value = days_remaining,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Days Remaining"},
                delta = {'reference': 365},
                gauge = {
                    'axis': {'range': [None, 365]},
                    'bar': {'color': color},
                    'steps': [
                        {'range': [0, 30], 'color': "red"},
                        {'range': [30, 90], 'color': "orange"},
                        {'range': [90, 365], 'color': "green"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 30
                    }
                }
            ))
            st.plotly_chart(fig, use_container_width=True)


def display_whois_analysis(whois_info):
    """Display WHOIS analysis with enhanced visualization."""
    col1, col2 = st.columns(2)
    
    with col1:
        # Domain information
        details = {
            "Domain": whois_info['domain'],
            "Registrar": whois_info['registrar'],
            "Organization": whois_info['org'],
            "Country": whois_info['country'],
            "Status": whois_info['status']
        }
        
        for key, value in details.items():
            if value != 'Unknown':
                st.info(f"**{key}:** {value}")
            else:
                st.warning(f"**{key}:** {value}")
    
    with col2:
        # Domain age analysis
        if whois_info['creation_date'] != 'Unknown':
            try:
                creation_date = datetime.strptime(whois_info['creation_date'], '%Y-%m-%d')
                domain_age = (datetime.now() - creation_date).days
                
                st.markdown("**Domain Age Analysis**")
                
                if domain_age < 30:
                    st.error(f"**Age:** {domain_age} days (Suspicious - New Domain)")
                elif domain_age < 365:
                    st.warning(f"**Age:** {domain_age} days (Relatively New)")
                else:
                    st.success(f"**Age:** {domain_age} days (Established Domain)")
                
                # Domain age chart
                age_data = pd.DataFrame({
                    'Category': ['Domain Age'],
                    'Days': [domain_age]
                })
                
                fig = px.bar(age_data, x='Category', y='Days',
                           title="Domain Age in Days",
                           color_discrete_sequence=['blue'])
                st.plotly_chart(fig, use_container_width=True)
                
            except:
                st.warning("Could not calculate domain age")
        else:
            st.warning("Domain age information unavailable")


def display_dns_analysis(dns_info):
    """Display DNS analysis with enhanced visualization."""
    col1, col2 = st.columns(2)
    
    with col1:
        if dns_info['resolved']:
            st.success("**DNS Resolution: Successful**")
            
            # DNS record summary
            record_counts = {
                "A Records": len(dns_info['a_records']),
                "AAAA Records": len(dns_info['aaaa_records']),
                "MX Records": len(dns_info['mx_records']),
                "NS Records": len(dns_info['ns_records']),
                "TXT Records": len(dns_info['txt_records'])
            }
            
            for record_type, count in record_counts.items():
                if count > 0:
                    st.success(f"**{record_type}:** {count}")
                else:
                    st.info(f"**{record_type}:** {count}")
        else:
            st.error("**DNS Resolution: Failed**")
            st.error(f"**Error:** {dns_info.get('error', 'Unknown error')}")
    
    with col2:
        if dns_info['resolved']:
            # DNS record distribution chart
            record_data = pd.DataFrame({
                'Record Type': ['A', 'AAAA', 'MX', 'NS', 'TXT'],
                'Count': [
                    len(dns_info['a_records']),
                    len(dns_info['aaaa_records']),
                    len(dns_info['mx_records']),
                    len(dns_info['ns_records']),
                    len(dns_info['txt_records'])
                ]
            })
            
            fig = px.bar(record_data, x='Record Type', y='Count',
                       title="DNS Record Distribution",
                       color_discrete_sequence=['green'])
            st.plotly_chart(fig, use_container_width=True)


def display_http_analysis(http_info):
    """Display HTTP analysis with enhanced visualization."""
    col1, col2 = st.columns(2)
    
    with col1:
        # HTTP response details
        response_details = {
            "Status Code": http_info['status_code'],
            "Status Text": http_info['status_text'],
            "Server": http_info['server'],
            "Content Type": http_info['content_type'],
            "Response Time": f"{http_info['response_time']:.2f}s",
            "Redirect Count": http_info['redirect_count']
        }
        
        for key, value in response_details.items():
            if key == "Status Code" and str(value) in ['200', '301', '302']:
                st.success(f"**{key}:** {value}")
            elif key == "Status Code":
                st.error(f"**{key}:** {value}")
            else:
                st.info(f"**{key}:** {value}")
    
    with col2:
        # Security headers analysis
        st.markdown("**Security Headers Analysis**")
        
        security_headers = http_info.get('security_headers', {})
        header_status = {
            "X-Frame-Options": security_headers.get('x_frame_options', 'Not Set'),
            "X-Content-Type-Options": security_headers.get('x_content_type_options', 'Not Set'),
            "X-XSS-Protection": security_headers.get('x_xss_protection', 'Not Set'),
            "Strict-Transport-Security": security_headers.get('strict_transport_security', 'Not Set'),
            "Content-Security-Policy": security_headers.get('content_security_policy', 'Not Set')
        }
        
        # Calculate security score
        security_score = sum(1 for v in header_status.values() if v != 'Not Set')
        total_headers = len(header_status)
        security_percentage = (security_score / total_headers) * 100
        
        st.markdown(f"**Security Headers Score: {security_percentage:.1f}%**")
        st.progress(security_percentage / 100)
        
        # Display header status
        for header, value in header_status.items():
            if value == 'Not Set':
                st.warning(f"**{header}:** {value}")
            else:
                st.success(f"**{header}:** {value}") 