# logger.py
# ---------------------------------------------------------
# 📝 Logs predictions to user-specific JSON files
# ---------------------------------------------------------

import streamlit as st
from datetime import datetime
import os
import json
import pandas as pd


def _get_log_file():
    user = st.session_state.get("user_email", "anonymous").split("@")[0]
    return f"data/history_{user}.json"


def _load_log():
    file = _get_log_file()
    if os.path.exists(file):
        try:
            with open(file, "r") as f:
                content = f.read().strip()
                if not content:
                    return []
                return json.loads(content)
        except (json.JSONDecodeError, Exception) as e:
            # If JSON is corrupted, backup the file and return empty list
            backup_file = file.replace('.json', '_corrupted_backup.json')
            try:
                with open(file, "r") as f:
                    content = f.read()
                with open(backup_file, "w") as f:
                    f.write(content)
                print(f"Warning: Corrupted JSON file {file} backed up to {backup_file}")
            except:
                pass
            # Return empty list and recreate the file
            return []
    return []


def _save_log(log):
    file = _get_log_file()
    os.makedirs("data", exist_ok=True)
    with open(file, "w") as f:
        json.dump(log, f, indent=2)


def log_prediction(url: str, prediction: str, confidence: float):
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "prediction": prediction,
        "confidence": f"{confidence:.2%}"
    }
    log = _load_log()
    log.append(entry)
    _save_log(log)


def log_detection(url: str, prediction_result: dict, features_result: dict, security_analysis = None):
    """
    Log detection results with comprehensive information including security analysis.
    
    Args:
        url (str): URL that was analyzed
        prediction_result (dict): Prediction results from model
        features_result (dict): Feature extraction results
        security_analysis (dict): Security analysis results (optional)
    """
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "prediction": prediction_result.get('prediction', 'Unknown'),
        "confidence": prediction_result.get('confidence', 0),
        "risk_score": prediction_result.get('risk_score', 0),
        "risk_level": prediction_result.get('risk_level', 'Unknown'),
        "model_used": prediction_result.get('model_used', 'Unknown'),
        "features_count": len(features_result) if features_result else 0,
        "analysis_time": prediction_result.get('analysis_time', 0)
    }
    
    # Add security analysis fields if available
    if security_analysis:
        entry.update({
            'ssl_valid': security_analysis.get('ssl_info', {}).get('valid', False),
            'ssl_issuer': security_analysis.get('ssl_info', {}).get('issuer', 'Unknown'),
            'ssl_days_remaining': security_analysis.get('ssl_info', {}).get('days_remaining', 0),
            'whois_domain': security_analysis.get('whois_info', {}).get('domain', 'Unknown'),
            'whois_registrar': security_analysis.get('whois_info', {}).get('registrar', 'Unknown'),
            'whois_creation_date': security_analysis.get('whois_info', {}).get('creation_date', 'Unknown'),
            'whois_country': security_analysis.get('whois_info', {}).get('country', 'Unknown'),
            'dns_resolved': security_analysis.get('dns_info', {}).get('resolved', False),
            'dns_a_records_count': len(security_analysis.get('dns_info', {}).get('a_records', [])),
            'dns_mx_records_count': len(security_analysis.get('dns_info', {}).get('mx_records', [])),
            'dns_ns_records_count': len(security_analysis.get('dns_info', {}).get('ns_records', [])),
            'http_status_code': security_analysis.get('http_info', {}).get('status_code', 0),
            'http_response_time': security_analysis.get('http_info', {}).get('response_time', 0),
            'security_headers_score': sum(1 for v in security_analysis.get('http_info', {}).get('security_headers', {}).values() if v != 'Not Set')
        })
    else:
        # Add default values for security fields if not available
        entry.update({
            'ssl_valid': False,
            'ssl_issuer': 'Unknown',
            'ssl_days_remaining': 0,
            'whois_domain': 'Unknown',
            'whois_registrar': 'Unknown',
            'whois_creation_date': 'Unknown',
            'whois_country': 'Unknown',
            'dns_resolved': False,
            'dns_a_records_count': 0,
            'dns_mx_records_count': 0,
            'dns_ns_records_count': 0,
            'http_status_code': 0,
            'http_response_time': 0,
            'security_headers_score': 0
        })
    
    log = _load_log()
    log.append(entry)
    _save_log(log)


def log_bulk_detections(bulk_results: list):
    """
    Log multiple detection results from bulk analysis to user's history.
    
    Args:
        bulk_results (list): List of detection result dictionaries
    """
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
    
    # Filter out ERROR results and add successful ones
    successful_results = [r for r in bulk_results if r.get('prediction') != 'ERROR']
    
    # Ensure the results have the right format for history
    formatted_results = []
    for result in successful_results:
        formatted_result = {
            "timestamp": result.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "url": result.get('url', ''),
            "prediction": result.get('prediction', 'Unknown'),
            "confidence": result.get('confidence', 0),
            "risk_score": result.get('risk_score', 0),
            "risk_level": result.get('risk_level', 'Unknown'),
            "model_used": result.get('model_used', 'Unknown'),
            "features_count": result.get('features_count', 0),
            "analysis_time": result.get('analysis_time', 0),
            # Additional fields for bulk analysis
            "ssl_valid": result.get('ssl_valid', False),
            "ssl_issuer": result.get('ssl_issuer', 'Unknown'),
            "ssl_days_remaining": result.get('ssl_days_remaining', 0),
            "whois_domain": result.get('whois_domain', 'Unknown'),
            "whois_registrar": result.get('whois_registrar', 'Unknown'),
            "whois_creation_date": result.get('whois_creation_date', 'Unknown'),
            "whois_country": result.get('whois_country', 'Unknown'),
            "dns_resolved": result.get('dns_resolved', False),
            "dns_a_records_count": result.get('dns_a_records_count', 0),
            "dns_mx_records_count": result.get('dns_mx_records_count', 0),
            "dns_ns_records_count": result.get('dns_ns_records_count', 0),
            "http_status_code": result.get('http_status_code', 0),
            "http_response_time": result.get('http_response_time', 0),
            "security_headers_score": result.get('security_headers_score', 0)
        }
        formatted_results.append(formatted_result)
    
    # Add to history
    history.extend(formatted_results)
    
    # Save updated history
    os.makedirs('data', exist_ok=True)
    with open(history_file, 'w') as f:
        json.dump(history, f, indent=2)
    
    return len(formatted_results)


def show_history():
    log = _load_log()
    if log:
        # Separate regular predictions from feedback entries
        predictions = [entry for entry in log if entry.get('entry_type') != 'feedback']
        feedback_entries = [entry for entry in log if entry.get('entry_type') == 'feedback']
        
        # Show Analysis History Table
        st.markdown("### 🔍 URL Analysis History")
        st.info("📋 **Synchronized Data**: This history includes both individual URL analyses and bulk analysis results with identical field structure for consistent CSV exports.")
        if predictions:
            # Show record count and scrolling info
            st.markdown(f"📊 **Showing {len(predictions)} analysis records** (Table is horizontally scrollable for all columns)")
            
            # Create DataFrame for predictions/analysis
            analysis_df = pd.DataFrame(predictions)
            
            # Define all possible columns that should be displayed (matching bulk analysis CSV structure)
            # Standard column order for both bulk analysis and user history exports
            all_columns = [
                'timestamp', 'url', 'prediction', 'confidence', 'risk_score', 'risk_level', 
                'analysis_time', 'model_used', 'features_count',
                'ssl_valid', 'ssl_issuer', 'ssl_days_remaining',
                'whois_domain', 'whois_registrar', 'whois_creation_date', 'whois_country',
                'dns_resolved', 'dns_a_records_count', 'dns_mx_records_count', 'dns_ns_records_count',
                'http_status_code', 'http_response_time', 'security_headers_score'
            ]
            
            # Add missing columns with default values to match bulk analysis structure
            for col in all_columns:
                if col not in analysis_df.columns:
                    if col in ['confidence', 'risk_score', 'analysis_time', 'features_count', 'ssl_days_remaining', 
                               'dns_a_records_count', 'dns_mx_records_count', 'dns_ns_records_count', 
                               'http_status_code', 'http_response_time', 'security_headers_score']:
                        analysis_df[col] = 0
                    elif col in ['ssl_valid', 'dns_resolved']:
                        analysis_df[col] = False
                    else:
                        analysis_df[col] = 'Unknown'
            
            # Select all columns for display (show all comprehensive data)
            display_columns = all_columns  # Use all available columns
            
            # Create display dataframe with all columns
            analysis_df_display = analysis_df[display_columns].copy()
            
            # Rename columns for better display
            column_mapping = {
                'timestamp': 'Timestamp',
                'url': 'URL',
                'prediction': 'Prediction',
                'confidence': 'Confidence',
                'risk_score': 'Risk Score',
                'risk_level': 'Risk Level',
                'analysis_time': 'Analysis Time (s)',
                'model_used': 'Model Used',
                'features_count': 'Features Count',
                'ssl_valid': 'SSL Valid',
                'ssl_issuer': 'SSL Issuer',
                'ssl_days_remaining': 'SSL Days Remaining',
                'whois_domain': 'WHOIS Domain',
                'whois_registrar': 'WHOIS Registrar',
                'whois_creation_date': 'WHOIS Creation Date',
                'whois_country': 'Country',
                'dns_resolved': 'DNS Resolved',
                'dns_a_records_count': 'DNS A Records',
                'dns_mx_records_count': 'DNS MX Records',
                'dns_ns_records_count': 'DNS NS Records',
                'http_status_code': 'HTTP Status',
                'http_response_time': 'HTTP Response Time (s)',
                'security_headers_score': 'Security Headers Score'
            }
            analysis_df_display = analysis_df_display.rename(columns=column_mapping)
            
            # Format numeric columns - keep confidence as decimal values
            if 'Confidence' in analysis_df_display.columns:
                analysis_df_display['Confidence'] = pd.to_numeric(analysis_df_display['Confidence'], errors='coerce')
                # Keep as decimal values, don't convert to percentage
                analysis_df_display['Confidence'] = analysis_df_display['Confidence'].apply(lambda x: x if pd.notnull(x) else 0)
            
            if 'Risk Score' in analysis_df_display.columns:
                analysis_df_display['Risk Score'] = pd.to_numeric(analysis_df_display['Risk Score'], errors='coerce')
                analysis_df_display['Risk Score'] = analysis_df_display['Risk Score'].apply(lambda x: x if pd.notnull(x) else 0)
            
            # Format other numeric columns
            numeric_columns = ['Analysis Time (s)', 'Features Count', 'SSL Days Remaining', 
                             'DNS A Records', 'DNS MX Records', 'DNS NS Records', 
                             'HTTP Status', 'HTTP Response Time (s)', 'Security Headers Score']
            
            for col in numeric_columns:
                if col in analysis_df_display.columns:
                    analysis_df_display[col] = pd.to_numeric(analysis_df_display[col], errors='coerce').fillna(0)
            
            # Sort by timestamp (newest first)
            if 'Timestamp' in analysis_df_display.columns:
                analysis_df_display = analysis_df_display.sort_values('Timestamp', ascending=False)
            
            # Display the enhanced table with all columns and horizontal scrolling
            st.dataframe(
                analysis_df_display, 
                use_container_width=False,  # Disable to allow horizontal scrolling
                key="analysis_history_table",
                column_config={
                    "URL": st.column_config.LinkColumn("URL", width="large"),
                    "Prediction": st.column_config.TextColumn("Prediction", width="small"),
                    "Confidence": st.column_config.NumberColumn("Confidence", width="small", format="%.2f"),
                    "Risk Score": st.column_config.NumberColumn("Risk Score", width="small", format="%.1f"),
                    "Risk Level": st.column_config.TextColumn("Risk Level", width="small"),
                    "Analysis Time (s)": st.column_config.NumberColumn("Analysis Time (s)", width="small", format="%.2f"),
                    "Model Used": st.column_config.TextColumn("Model Used", width="medium"),
                    "Features Count": st.column_config.NumberColumn("Features Count", width="small"),
                    "SSL Valid": st.column_config.CheckboxColumn("SSL Valid", width="small"),
                    "SSL Issuer": st.column_config.TextColumn("SSL Issuer", width="medium"),
                    "SSL Days Remaining": st.column_config.NumberColumn("SSL Days Remaining", width="small"),
                    "WHOIS Domain": st.column_config.TextColumn("WHOIS Domain", width="medium"),
                    "WHOIS Registrar": st.column_config.TextColumn("WHOIS Registrar", width="medium"),
                    "WHOIS Creation Date": st.column_config.TextColumn("WHOIS Creation Date", width="medium"),
                    "Country": st.column_config.TextColumn("Country", width="small"),
                    "DNS Resolved": st.column_config.CheckboxColumn("DNS Resolved", width="small"),
                    "DNS A Records": st.column_config.NumberColumn("DNS A Records", width="small"),
                    "DNS MX Records": st.column_config.NumberColumn("DNS MX Records", width="small"),
                    "DNS NS Records": st.column_config.NumberColumn("DNS NS Records", width="small"),
                    "HTTP Status": st.column_config.NumberColumn("HTTP Status", width="small"),
                    "HTTP Response Time (s)": st.column_config.NumberColumn("HTTP Response Time (s)", width="small", format="%.2f"),
                    "Security Headers Score": st.column_config.NumberColumn("Security Headers Score", width="small"),
                    "Timestamp": st.column_config.TextColumn("Timestamp", width="medium")
                }
            )
            
            # Show analysis summary
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("🔢 Total Analyses", len(predictions))
            with col2:
                threats = sum(1 for entry in predictions if entry.get('prediction') == 'Phishing')
                st.metric("⚠️ Threats Found", threats)
            with col3:
                legitimate = len(predictions) - threats
                st.metric("✅ Legitimate Sites", legitimate)
            
            # Add export options for analysis history (using full dataframe with all columns for export)
            st.markdown("#### 📤 Export Analysis History")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("📋 Copy Analysis History", key="copy_analysis_btn"):
                    # Use full dataframe for export with all columns
                    full_export_df = analysis_df[all_columns].copy()
                    csv_data = full_export_df.to_csv(index=False)
                    st.session_state['copied_analysis_data'] = csv_data
                    st.success("✅ Analysis history copied to clipboard!")
            
            with col2:
                # Download CSV for analysis history (using full dataframe with all columns)
                full_export_df = analysis_df[all_columns].copy()
                csv = full_export_df.to_csv(index=False)
                user_email = st.session_state.get('user_email', 'user')
                user = user_email.split('@')[0] if '@' in user_email else 'user'
                st.download_button(
                    label="⬇️ Download Analysis CSV",
                    data=csv,
                    file_name=f"analysis_history_{user}.csv",
                    mime="text/csv"
                )
                
                with col3:
                    # Generate comprehensive PDF report for analysis history (similar to bulk detection)
                    try:
                        from fpdf import FPDF
                        import io
                        from datetime import datetime
                        
                        # Prepare data for comprehensive report
                        df_clean = analysis_df.copy()
                        
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
                                df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce').fillna(0)
                        
                        # Convert all other columns to string
                        for col in df_clean.columns:
                            if col not in ['confidence', 'risk_score']:
                                df_clean[col] = df_clean[col].astype(str)
                        
                        # Create comprehensive PDF report
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
                        pdf.multi_cell(0, 6, f"This report contains the results of {total_urls} URL security analyses from your detection history. "
                                             f"The analysis was performed using advanced machine learning models and comprehensive security checks.")
                        pdf.ln(5)
                        
                        # Key Metrics Section
                        pdf.set_font("Helvetica", 'B', 12)
                        pdf.cell(200, 8, "Key Metrics", new_x="LMARGIN", new_y="NEXT")
                        pdf.ln(3)
                        pdf.set_font("Helvetica", size=10)
                        
                        # Detection metrics
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
                        
                        # Convert to bytes for download
                        pdf_bytearray = pdf.output(dest='S')
                        pdf_bytes = bytes(pdf_bytearray)
                        st.download_button(
                            label="📄 Generate PDF Report",
                            data=pdf_bytes,
                            file_name=f"analysis_report_{user}.pdf",
                            mime="application/pdf"
                        )
                    except Exception as e:
                        st.error(f"PDF report could not be generated: {str(e)}")
                        st.info("💡 Tip: Try downloading the CSV file instead, or check if FPDF is properly installed.")
                        # Fallback: offer to download as text
                        try:
                            report_text = f"Analysis Report for {user}\n"
                            report_text += f"Total Analyses: {len(predictions)}\n"
                            threats = sum(1 for entry in predictions if entry.get('prediction') == 'Phishing')
                            report_text += f"Threats Found: {threats}\n"
                            legitimate = len(predictions) - threats
                            report_text += f"Legitimate Sites: {legitimate}\n\n"
                            report_text += analysis_df_display.to_string()
                            
                            st.download_button(
                                label="📄 Download as Text Report",
                                data=report_text,
                                file_name=f"analysis_report_{user}.txt",
                                mime="text/plain"
                            )
                        except:
                            pass
        else:
            st.info("No URL analyses logged yet.")
        
        st.markdown("---")
        
        # Show Feedback History Table
        st.markdown("### 💬 User Feedback History")
        if feedback_entries:
            # Create DataFrame for feedback
            feedback_df = pd.DataFrame(feedback_entries)
            
            # Select and order relevant columns for feedback
            feedback_columns = ['timestamp', 'url', 'prediction', 'user_feedback', 'user_comment']
            feedback_display_columns = []
            for col in feedback_columns:
                if col in feedback_df.columns:
                    feedback_display_columns.append(col)
            
            if feedback_display_columns:
                feedback_df_display = feedback_df[feedback_display_columns].copy()
                
                # Rename columns for better display
                feedback_column_mapping = {
                    'timestamp': 'Timestamp',
                    'url': 'URL',
                    'prediction': 'Original Prediction',
                    'user_feedback': 'Correct/Incorrect',
                    'user_comment': 'Comment'
                }
                feedback_df_display = feedback_df_display.rename(columns=feedback_column_mapping)
                
                # Clean up prediction column to remove "FEEDBACK: " prefix
                if 'Original Prediction' in feedback_df_display.columns:
                    feedback_df_display['Original Prediction'] = feedback_df_display['Original Prediction'].str.replace('FEEDBACK: ', '', regex=False)
                
                # Clean up feedback column to show just Correct/Incorrect
                if 'Correct/Incorrect' in feedback_df_display.columns:
                    feedback_df_display['Correct/Incorrect'] = feedback_df_display['Correct/Incorrect'].astype(str).str.replace('👍 ', '').str.replace('👎 ', '')
                
                # Sort by timestamp (newest first)
                if 'Timestamp' in feedback_df_display.columns:
                    feedback_df_display = feedback_df_display.sort_values('Timestamp', ascending=False)
                
                # Display the feedback table with horizontal scrolling
                st.dataframe(
                    feedback_df_display, 
                    use_container_width=False,  # Disable to allow horizontal scrolling
                    key="feedback_history_table"
                )
                
                # Add copy functionality for feedback table
                col1, col2 = st.columns([1, 1])
                with col1:
                    if st.button("📋 Copy Feedback Table", key="copy_feedback_btn"):
                        csv_data = feedback_df_display.to_csv(index=False)
                        st.session_state['copied_feedback_data'] = csv_data
                        st.success("✅ Feedback table copied to clipboard!")
                
                with col2:
                    # Download CSV for feedback
                    csv = feedback_df_display.to_csv(index=False)
                    st.download_button(
                        label="⬇️ Download Feedback CSV",
                        data=csv,
                        file_name=f"feedback_history_{st.session_state.get('user_email', 'user').split('@')[0]}.csv",
                        mime="text/csv"
                    )
                
                # Show feedback summary
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("💬 Total Feedback", len(feedback_entries))
                with col2:
                    # Count feedback types if available
                    if 'user_feedback' in feedback_df.columns:
                        feedback_types = feedback_df['user_feedback'].value_counts()
                        if len(feedback_types) > 0:
                            most_common = str(feedback_types.index[0]).replace('👍 ', '').replace('👎 ', '')
                            st.metric("📊 Most Common", f"{most_common} ({feedback_types.iloc[0]})")
                with col3:
                    # Count comments provided
                    comments_provided = sum(1 for entry in feedback_entries if entry.get('user_comment', '').strip())
                    st.metric("💭 Comments", f"{comments_provided}/{len(feedback_entries)}")
            else:
                st.dataframe(feedback_df, use_container_width=True, key="feedback_history_table_full")
        else:
            st.info("No user feedback logged yet.")
            
    else:
        st.info("No activity logged yet.")


def get_user_statistics():
    """
    Get statistics from user's detection history.
    
    Returns:
        dict: User statistics
    """
    log = _load_log()
    
    if not log:
        return {
            "total_scans": 0,
            "threats_detected": 0,
            "legitimate_sites": 0,
            "threat_ratio": 0,
            "avg_confidence": 0,
            "last_scan": "Never"
        }
    
    total_scans = len(log)
    threats_detected = sum(1 for entry in log if entry.get('prediction') == 'Phishing')
    legitimate_sites = total_scans - threats_detected
    threat_ratio = (threats_detected / total_scans) * 100 if total_scans > 0 else 0
    
    # Calculate average confidence
    confidences = [entry.get('confidence', 0) for entry in log]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0
    
    # Get last scan
    last_scan = log[-1].get('timestamp', 'Unknown') if log else 'Never'
    
    return {
        "total_scans": total_scans,
        "threats_detected": threats_detected,
        "legitimate_sites": legitimate_sites,
        "threat_ratio": threat_ratio,
        "avg_confidence": avg_confidence,
        "last_scan": last_scan
    }
