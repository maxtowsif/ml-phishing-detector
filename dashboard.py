# dashboard.py
# ---------------------------------------------------------
# Dashboard Components for Streamlit App
# Enhanced visualizations with color theory and feature analysis
# ---------------------------------------------------------

import matplotlib.pyplot as plt
import streamlit as st
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import json
import os
import re
from urllib.parse import urlparse

# Handle optional imports with error handling
try:
    import plotly.express as px
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    st.warning("Plotly not available - charts will be disabled")

# Country coordinates mapping for geographic visualization
COUNTRY_COORDINATES = {
    'United States': {'lat': 39.8283, 'lon': -98.5795, 'code': 'US'},
    'United Kingdom': {'lat': 55.3781, 'lon': -3.4360, 'code': 'GB'},
    'Germany': {'lat': 51.1657, 'lon': 10.4515, 'code': 'DE'},
    'France': {'lat': 46.2276, 'lon': 2.2137, 'code': 'FR'},
    'Canada': {'lat': 56.1304, 'lon': -106.3468, 'code': 'CA'},
    'China': {'lat': 35.8617, 'lon': 104.1954, 'code': 'CN'},
    'Russia': {'lat': 61.5240, 'lon': 105.3188, 'code': 'RU'},
    'Brazil': {'lat': -14.2350, 'lon': -51.9253, 'code': 'BR'},
    'India': {'lat': 20.5937, 'lon': 78.9629, 'code': 'IN'},
    'Japan': {'lat': 36.2048, 'lon': 138.2529, 'code': 'JP'},
    'Australia': {'lat': -25.2744, 'lon': 133.7751, 'code': 'AU'},
    'Italy': {'lat': 41.8719, 'lon': 12.5674, 'code': 'IT'},
    'Spain': {'lat': 40.4637, 'lon': -3.7492, 'code': 'ES'},
    'Netherlands': {'lat': 52.1326, 'lon': 5.2913, 'code': 'NL'},
    'South Korea': {'lat': 35.9078, 'lon': 127.7669, 'code': 'KR'},
    'Mexico': {'lat': 23.6345, 'lon': -102.5528, 'code': 'MX'},
    'Turkey': {'lat': 38.9637, 'lon': 35.2433, 'code': 'TR'},
    'Poland': {'lat': 51.9194, 'lon': 19.1451, 'code': 'PL'},
    'Sweden': {'lat': 60.1282, 'lon': 18.6435, 'code': 'SE'},
    'Norway': {'lat': 60.4720, 'lon': 8.4689, 'code': 'NO'},
    'Argentina': {'lat': -38.4161, 'lon': -63.6167, 'code': 'AR'},
    'Belgium': {'lat': 50.5039, 'lon': 4.4699, 'code': 'BE'},
    'Switzerland': {'lat': 46.8182, 'lon': 8.2275, 'code': 'CH'},
    'South Africa': {'lat': -30.5595, 'lon': 22.9375, 'code': 'ZA'},
    'Romania': {'lat': 45.9432, 'lon': 24.9668, 'code': 'RO'},
    'Unknown': {'lat': 0, 'lon': 0, 'code': 'XX'}
}

# Create reverse mapping from country codes to full country names
COUNTRY_CODE_TO_NAME = {v['code']: k for k, v in COUNTRY_COORDINATES.items()}

# TLD to country mapping
TLD_COUNTRY_MAP = {
    '.us': 'United States', '.com': 'United States', '.net': 'United States', '.org': 'United States',
    '.uk': 'United Kingdom', '.co.uk': 'United Kingdom',
    '.de': 'Germany',
    '.fr': 'France',
    '.ca': 'Canada',
    '.cn': 'China',
    '.ru': 'Russia',
    '.br': 'Brazil',
    '.in': 'India',
    '.jp': 'Japan',
    '.au': 'Australia',
    '.it': 'Italy',
    '.es': 'Spain',
    '.nl': 'Netherlands',
    '.kr': 'South Korea',
    '.mx': 'Mexico',
    '.tr': 'Turkey',
    '.pl': 'Poland',
    '.se': 'Sweden',
    '.no': 'Norway',
    '.ar': 'Argentina',
    '.be': 'Belgium',
    '.ch': 'Switzerland',
    '.za': 'South Africa'
}


def get_dashboard_data() -> dict:
    """
    Get comprehensive dashboard data for analytics.
    
    Returns:
        dict: Dashboard data with metrics, trends, and visualizations
    """
    # Load user history data to calculate real statistics
    total_scans = 0
    threats_detected = 0
    active_users = 0
    
    # Calculate statistics from user history files
    data_dir = "data"
    if os.path.exists(data_dir):
        for filename in os.listdir(data_dir):
            if filename.startswith("history_") and filename.endswith(".json"):
                try:
                    with open(os.path.join(data_dir, filename), 'r') as f:
                        history = json.load(f)
                        
                        # Only count actual URL analyses, not feedback entries
                        analysis_entries = [entry for entry in history if entry.get('entry_type') != 'feedback']
                        
                        total_scans += len(analysis_entries)
                        threats_detected += sum(1 for entry in analysis_entries 
                                              if entry.get('prediction') == 'Phishing' or 
                                              (isinstance(entry.get('prediction'), str) and 
                                               'Phishing' in entry.get('prediction', '')))
                        active_users += 1
                except:
                    continue
    
    # If no real data, use sample data
    if total_scans == 0:
        total_scans = 1250
        threats_detected = 189
        active_users = 3
    
    # Calculate success rate
    success_rate = ((total_scans - threats_detected) / max(total_scans, 1)) * 100
    
    # Generate trends data
    trends_df = generate_trends_data(total_scans, threats_detected)
    
    # Generate threat distribution
    threat_distribution = pd.DataFrame({
        'Category': ['Legitimate', 'Threats'],
        'Count': [total_scans - threats_detected, threats_detected]
    })
    
    # Generate daily stats
    daily_stats = generate_daily_stats(total_scans, threats_detected)
    
    return {
        'total_scans': total_scans,
        'threats_detected': threats_detected,
        'success_rate': success_rate,
        'active_users': active_users,
        'trends_df': trends_df,
        'threat_distribution': threat_distribution,
        'daily_stats': daily_stats
    }


def generate_trends_data(total_scans: int, threats_detected: int) -> pd.DataFrame:
    """
    Generate sample trends data for visualization.
    """
    # Generate 30 days of data
    dates = pd.date_range(start='2025-01-01', periods=30, freq='D')
    
    # Calculate daily averages
    avg_daily_scans = total_scans // 30
    avg_daily_threats = threats_detected // 30
    
    # Generate realistic daily data with some variation
    np.random.seed(42)  # For reproducible results
    daily_scans = [max(0, int(avg_daily_scans + np.random.normal(0, avg_daily_scans * 0.3))) for _ in range(30)]
    daily_threats = [max(0, int(avg_daily_threats + np.random.normal(0, avg_daily_threats * 0.4))) for _ in range(30)]
    
    return pd.DataFrame({
        'Date': dates,
        'Scans': daily_scans,
        'Threats': daily_threats
    })


def generate_daily_stats(total_scans: int, threats_detected: int) -> list:
    """
    Generate daily statistics for the last 7 days.
    """
    stats = []
    for i in range(7):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        # Generate realistic daily data
        daily_scans = max(0, int(total_scans // 30 + np.random.normal(0, 5)))
        daily_threats = max(0, int(threats_detected // 30 + np.random.normal(0, 2)))
        
        stats.append({
            'date': date,
            'scans': daily_scans,
            'threats': daily_threats
        })
    
    return list(reversed(stats))


def get_feature_importance(features: dict) -> dict:
    """
    Calculate feature importance scores based on feature values.
    This is a simplified version - in a real implementation, 
    you would use the actual model's feature importance.
    
    Args:
        features (dict): Feature dictionary
        
    Returns:
        dict: Feature importance scores
    """
    # Define importance weights for different feature types
    importance_weights = {
        'length_url': 0.15,
        'length_hostname': 0.12,
        'nb_dots': 0.10,
        'nb_hyphens': 0.08,
        'nb_at': 0.20,  # High importance for @ symbol
        'nb_qm': 0.08,
        'nb_and': 0.08,
        'nb_or': 0.08,
        'nb_slash': 0.06,
        'nb_www': 0.05,
        'ratio_digits_url': 0.10,
        'google_index': 0.05,
        'page_rank': 0.05
    }
    
    # Calculate weighted importance
    feature_importance = {}
    for feature, value in features.items():
        weight = importance_weights.get(feature, 0.05)
        # Normalize the value and multiply by weight
        normalized_value = min(value / 100, 1.0) if value > 0 else 0
        feature_importance[feature] = normalized_value * weight
    
    return feature_importance


def show_feature_importance(feature_scores: dict, top_n: int = 10):
    """
    Plots the top-N feature importances using Plotly.

    Args:
        feature_scores (dict): Feature importance scores as {feature_name: score}
        top_n (int): Number of top features to show
    """
    sorted_feats = sorted(feature_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
    labels, scores = zip(*sorted_feats)

    # Create horizontal bar chart with color gradient
    fig = go.Figure(data=[
        go.Bar(
            x=scores,
            y=labels,
            orientation='h',
            marker=dict(
                color=scores,
                colorscale='RdYlBu_r',
                showscale=True,
                colorbar=dict(title="Importance Score")
            ),
            text=[f'{score:.3f}' for score in scores],
            textposition='auto',
        )
    ])
    
    fig.update_layout(
        title="Feature Importance Analysis",
        xaxis_title="Importance Score",
        yaxis_title="Features",
        height=400,
        showlegend=False,
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)'
    )
    
    st.plotly_chart(fig, use_container_width=True)


def show_prediction_distribution(proba: list[float]):
    """
    Plots a horizontal bar to show predicted class probabilities using Plotly.

    Args:
        proba (list): [prob_legit, prob_phishing]
    """
    classes = ["Legitimate", "Phishing"]
    colors = ["#28a745", "#dc3545"]  # Green for legitimate, red for phishing

    fig = go.Figure(data=[
        go.Bar(
            x=proba,
            y=classes,
            orientation='h',
            marker=dict(color=colors),
            text=[f'{p:.2%}' for p in proba],
            textposition='auto',
        )
    ])
    
    fig.update_layout(
        title="Model Confidence Distribution",
        xaxis_title="Probability",
        xaxis=dict(range=[0, 1]),
        height=200,
        showlegend=False,
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)'
    )
    
    st.plotly_chart(fig, use_container_width=True)


def show_risk_meter(confidence: float, risk_level: str):
    """
    Display a risk meter visualization.
    
    Args:
        confidence (float): Confidence score (0-1)
        risk_level (str): Risk level (Low/Medium/High/Critical)
    """
    # Define colors based on risk level
    risk_colors = {
        'Low': '#28a745',
        'Medium': '#ffc107', 
        'High': '#fd7e14',
        'Critical': '#dc3545'
    }
    
    color = risk_colors.get(risk_level, '#6c757d')
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=confidence * 100,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"Risk Level: {risk_level}"},
        number={'font': {'size': 40}, 'valueformat': '.1f', 'suffix': '%'},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 25], 'color': "#28a745"},
                {'range': [25, 50], 'color': "#ffc107"},
                {'range': [50, 75], 'color': "#fd7e14"},
                {'range': [75, 100], 'color': "#dc3545"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=40, b=20),
        font=dict(color="black", family="Arial")
    )
    st.plotly_chart(fig, use_container_width=True)


def show_url_breakdown(url: str):
    """
    Visualize URL components breakdown.
    
    Args:
        url (str): URL to analyze
    """
    parsed = urlparse(url)
    
    components = {
        'Protocol': parsed.scheme or 'http',
        'Domain': parsed.netloc or url,
        'Path': parsed.path or '/',
        'Query': parsed.query or '',
        'Fragment': parsed.fragment or ''
    }
    
    # Create a simple visualization
    fig = go.Figure(data=[
        go.Bar(
            x=list(components.keys()),
            y=[len(str(v)) for v in components.values()],
            text=[str(v) for v in components.values()],
            textposition='auto',
            marker_color=['#007bff', '#28a745', '#ffc107', '#17a2b8', '#6c757d']
        )
    ])
    
    fig.update_layout(
        title="URL Component Analysis",
        xaxis_title="Components",
        yaxis_title="Length",
        height=300,
        showlegend=False
    )
    
    st.plotly_chart(fig, use_container_width=True)


def show_analytics_dashboard(analytics_data: dict):
    """
    Display comprehensive analytics dashboard.
    
    Args:
        analytics_data (dict): Analytics data dictionary
    """
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Scans", analytics_data.get('total_scans', 0))
    with col2:
        st.metric("Threats Detected", analytics_data.get('threats_detected', 0))
    with col3:
        threat_ratio = (analytics_data.get('threats_detected', 0) / 
                       max(analytics_data.get('total_scans', 1), 1)) * 100
        st.metric("Threat Ratio", f"{threat_ratio:.1f}%")
    with col4:
        st.metric("Success Rate", f"{(100 - threat_ratio):.1f}%")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        # Detection trends over time
        if 'daily_stats' in analytics_data and analytics_data['daily_stats']:
            dates = [stat['date'] for stat in analytics_data['daily_stats']]
            scans = [stat['scans'] for stat in analytics_data['daily_stats']]
            threats = [stat['threats'] for stat in analytics_data['daily_stats']]
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=dates, y=scans, name='Total Scans', line=dict(color='#007bff')))
            fig.add_trace(go.Scatter(x=dates, y=threats, name='Threats', line=dict(color='#dc3545')))
            
            fig.update_layout(
                title="Daily Detection Activity",
                xaxis_title="Date",
                yaxis_title="Count",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Threat distribution pie chart
        if 'threat_distribution' in analytics_data:
            df = analytics_data['threat_distribution']
            fig = px.pie(df, values='Count', names='Category',
                        title="Threat vs Legitimate Distribution",
                        color_discrete_map={'Legitimate': '#28a745', 'Threats': '#dc3545'})
            st.plotly_chart(fig, use_container_width=True)


def show_model_performance():
    """
    Display model performance metrics.
    """
    # Sample performance metrics
    metrics = {
        'Accuracy': 94.2,
        'Precision': 91.8,
        'Recall': 96.5,
        'F1-Score': 94.1
    }
    
    # Create performance visualization
    fig = go.Figure(data=[
        go.Bar(
            x=list(metrics.keys()),
            y=list(metrics.values()),
            marker_color=['#007bff', '#28a745', '#ffc107', '#17a2b8'],
            text=[f'{v:.1f}%' for v in metrics.values()],
            textposition='auto'
        )
    ])
    
    fig.update_layout(
        title="Model Performance Metrics",
        xaxis_title="Metrics",
        yaxis_title="Score (%)",
        yaxis=dict(range=[0, 100]),
        height=400,
        showlegend=False
    )
    
    st.plotly_chart(fig, use_container_width=True)


def extract_country_from_url(url):
    """
    Extract country information from URL based on TLD or domain patterns.
    
    Args:
        url (str): URL to analyze
        
    Returns:
        str: Country name or 'Unknown'
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Check for country-specific TLDs
        for tld, country in TLD_COUNTRY_MAP.items():
            if domain.endswith(tld):
                return country
        
        # Check for common patterns
        if any(x in domain for x in ['.gov', '.mil']):
            return 'United States'
        
        # Default for common global domains
        if any(domain.endswith(x) for x in ['.com', '.net', '.org', '.edu', '.info']):
            return 'United States'
            
        return 'Unknown'
    except:
        return 'Unknown'


def get_geographic_threat_data():
    """
    Extract real geographic threat data from user history files using actual WHOIS country data.
    
    Returns:
        pd.DataFrame: Geographic threat data with countries, threat counts, and coordinates
    """
    country_threats = {}
    country_total = {}
    
    # Load data from all user history files
    data_dir = "data"
    if os.path.exists(data_dir):
        for filename in os.listdir(data_dir):
            if filename.startswith("history_") and filename.endswith(".json"):
                try:
                    with open(os.path.join(data_dir, filename), 'r') as f:
                        history = json.load(f)
                        
                        # Process URL analysis entries
                        for entry in history:
                            if (entry.get('entry_type') != 'feedback' and 
                                'url' in entry and 'prediction' in entry):
                                
                                prediction = entry.get('prediction', '')
                                
                                # Get country from WHOIS data first, fallback to URL extraction
                                country_code = entry.get('whois_country', 'Unknown')
                                if country_code == 'Unknown' or not country_code:
                                    # Fallback to URL-based extraction if WHOIS country not available
                                    country = extract_country_from_url(entry['url'])
                                else:
                                    # Convert country code to full country name
                                    country = COUNTRY_CODE_TO_NAME.get(country_code, country_code)
                                
                                # Skip if still unknown
                                if country == 'Unknown':
                                    continue
                                
                                # Initialize counters
                                if country not in country_threats:
                                    country_threats[country] = 0
                                    country_total[country] = 0
                                
                                # Count total analyses
                                country_total[country] += 1
                                
                                # Count threats
                                if (prediction == 'Phishing' or 
                                    (isinstance(prediction, str) and 'Phishing' in prediction)):
                                    country_threats[country] += 1
                                    
                except Exception as e:
                    continue
    
    # If no real data, generate sample data
    if not country_threats:
        country_threats = {
            'United States': 150,
            'United Kingdom': 89,
            'Germany': 67,
            'France': 45,
            'Canada': 34,
            'China': 78,
            'Russia': 56,
            'Brazil': 43,
            'India': 39,
            'Japan': 28
        }
        country_total = {k: v + np.random.randint(50, 200) for k, v in country_threats.items()}
    
    # Create DataFrame with geographic data
    geo_data = []
    for country, threats in country_threats.items():
        if country in COUNTRY_COORDINATES:
            coords = COUNTRY_COORDINATES[country]
            total_scans = country_total.get(country, threats + np.random.randint(10, 100))
            threat_percentage = (threats / max(total_scans, 1)) * 100
            
            geo_data.append({
                'Country': country,
                'Threats': threats,
                'Total_Scans': total_scans,
                'Legitimate': total_scans - threats,
                'Threat_Percentage': round(threat_percentage, 1),
                'Latitude': coords['lat'],
                'Longitude': coords['lon'],
                'Country_Code': coords['code']
            })
    
    return pd.DataFrame(geo_data).sort_values('Threats', ascending=False)


def display_geographic_threats():
    """
    Display enhanced geographic threat visualization with real data and exportable table.
    """
    st.markdown("### 🌍 Geographic Threat Distribution")
    
    # Get real geographic data
    geo_data = get_geographic_threat_data()
    
    if geo_data.empty:
        # Create informative display when no data is available
        st.info("📍 No geographic threat data available yet.")
        
        # Show sample visualization to demonstrate functionality
        st.markdown("#### 🎯 Sample Geographic Visualization")
        st.markdown("Analyze some URLs to see real data! Here's what the interface will look like:")
        
        # Create sample data for demonstration
        sample_geo_data = pd.DataFrame({
            'Country': ['United States', 'United Kingdom', 'Germany', 'France', 'Canada'],
            'Threats': [15, 8, 6, 4, 3],
            'Total_Scans': [75, 40, 30, 20, 15],
            'Legitimate': [60, 32, 24, 16, 12],
            'Threat_Percentage': [20.0, 20.0, 20.0, 20.0, 20.0],
            'Latitude': [39.8283, 55.3781, 51.1657, 46.2276, 56.1304],
            'Longitude': [-98.5795, -3.4360, 10.4515, 2.2137, -106.3468],
            'Country_Code': ['US', 'GB', 'DE', 'FR', 'CA']
        })
        
        if PLOTLY_AVAILABLE:
            fig = px.scatter_geo(
                sample_geo_data, 
                lat='Latitude', 
                lon='Longitude', 
                size='Threats',
                hover_name='Country',
                hover_data={
                    'Threats': True,
                    'Total_Scans': True,
                    'Threat_Percentage': True,
                    'Latitude': False,
                    'Longitude': False
                },
                size_max=50,
                projection="natural earth",
                title="Sample: Global Threat Distribution Map"
            )
            
            fig.update_layout(
                geo=dict(
                    showframe=False,
                    showcoastlines=True,
                    projection_type='natural earth'
                ),
                height=400,
                title_x=0.5
            )
            
            fig.update_traces(
                marker=dict(
                    color=sample_geo_data['Threat_Percentage'],
                    colorscale='Reds',
                    showscale=True,
                    colorbar=dict(title="Threat %"),
                    line=dict(width=1, color='darkblue')
                )
            )
            
            st.plotly_chart(fig, use_container_width=True, key="sample_geo_map")
        
        st.markdown("**💡 Tip:** Start analyzing URLs in the Detection tab to populate this map with real data!")
        return
    
    # Create two columns for map and statistics
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if PLOTLY_AVAILABLE:
            # Create enhanced scatter geo plot
            fig = px.scatter_geo(
                geo_data, 
                lat='Latitude', 
                lon='Longitude', 
                size='Threats',
                hover_name='Country',
                hover_data={
                    'Threats': True,
                    'Total_Scans': True,
                    'Threat_Percentage': True,
                    'Latitude': False,
                    'Longitude': False
                },
                size_max=50,
                projection="natural earth",
                title="Global Threat Distribution Map"
            )
            
            # Update layout for better visibility
            fig.update_layout(
                geo=dict(
                    showframe=False,
                    showcoastlines=True,
                    projection_type='natural earth'
                ),
                height=500,
                title_x=0.5
            )
            
            # Color scale based on threat levels
            fig.update_traces(
                marker=dict(
                    color=geo_data['Threat_Percentage'],
                    colorscale='Reds',
                    showscale=True,
                    colorbar=dict(title="Threat %"),
                    line=dict(width=1, color='darkblue')
                )
            )
            
            st.plotly_chart(fig, use_container_width=True, key="real_geo_map")
        else:
            st.info("Plotly not available for geographic visualization.")
    
    with col2:
        st.markdown("#### 📊 Top Threat Countries")
        
        # Display top countries by threat count
        top_countries = geo_data.head(5)[['Country', 'Threats', 'Threat_Percentage']]
        
        for idx, row in top_countries.iterrows():
            with st.container():
                st.markdown(f"""
                **{row['Country']}**  
                🚨 {row['Threats']} threats ({row['Threat_Percentage']}%)
                """)
        
        # Summary statistics
        st.markdown("#### 📈 Global Summary")
        total_threats = geo_data['Threats'].sum()
        total_scans = geo_data['Total_Scans'].sum()
        avg_threat_rate = (total_threats / max(total_scans, 1)) * 100
        
        st.metric("Total Global Threats", total_threats)
        st.metric("Global Threat Rate", f"{avg_threat_rate:.1f}%")
        st.metric("Countries Monitored", len(geo_data))
    
    # Geographic threat data table
    st.markdown("#### 📋 Detailed Geographic Threat Analysis")
    
    # Create display dataframe
    display_df = geo_data[['Country', 'Threats', 'Total_Scans', 'Legitimate', 'Threat_Percentage']].copy()
    display_df.columns = ['Country', 'Threats Detected', 'Total Scans', 'Legitimate Sites', 'Threat Rate (%)']
    
    # Display the table
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True
    )
    
    # Export options
    st.markdown("#### 📥 Export Geographic Data")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        # CSV download
        csv_data = display_df.to_csv(index=False)
        st.download_button(
            label="📊 Download CSV",
            data=csv_data,
            file_name=f"geographic_threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    
    with col2:
        # JSON download
        json_data = geo_data.to_json(orient='records', indent=2)
        st.download_button(
            label="📋 Download JSON",
            data=json_data,
            file_name=f"geographic_threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
    
    with col3:
        # PDF download
        pdf_data = generate_geographic_pdf_report()
        if pdf_data:
            st.download_button(
                label="📄 Download PDF Report",
                data=pdf_data,
                file_name=f"geographic_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf"
            )
        else:
            st.button("📄 PDF Report", disabled=True, help="PDF generation unavailable")
    
    with col4:
        # Copy to clipboard button
        if st.button("📋 Copy Table Data"):
            st.session_state['copied_geo_data'] = csv_data
            st.success("✅ Table data copied to session!")
    
    # Show additional insights
    if len(geo_data) > 0:
        st.markdown("#### 💡 Geographic Insights")
        
        # Find patterns
        highest_threat_country = geo_data.loc[geo_data['Threat_Percentage'].idxmax()]
        most_active_country = geo_data.loc[geo_data['Total_Scans'].idxmax()]
        
        insights_col1, insights_col2 = st.columns(2)
        
        with insights_col1:
            st.info(f"""
            **Highest Threat Rate:** {highest_threat_country['Country']}  
            {highest_threat_country['Threat_Percentage']}% of scans detected threats
            """)
        
        with insights_col2:
            st.info(f"""
            **Most Active Region:** {most_active_country['Country']}  
            {most_active_country['Total_Scans']} total URL analyses
            """)


def generate_geographic_pdf_report():
    """
    Generate a comprehensive PDF report for geographic threat analysis.
    
    Returns:
        bytes: PDF report data
    """
    try:
        from fpdf import FPDF
        
        # Get geographic data
        geo_data = get_geographic_threat_data()
        
        if geo_data.empty:
            return None
        
        # Create PDF with Latin-1 encoding support
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", 'B', 16)
        pdf.cell(200, 10, "Geographic Threat Analysis Report", new_x="LMARGIN", new_y="NEXT", align='C')
        pdf.ln(10)
        
        # Report metadata
        pdf.set_font("Helvetica", '', 10)
        pdf.cell(200, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(200, 8, f"Total Countries Analyzed: {len(geo_data)}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(10)
        
        # Executive Summary
        pdf.set_font("Helvetica", 'B', 14)
        pdf.cell(200, 10, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", '', 10)
        
        total_threats = geo_data['Threats'].sum()
        total_scans = geo_data['Total_Scans'].sum()
        avg_threat_rate = (total_threats / max(total_scans, 1)) * 100
        highest_threat_country = geo_data.loc[geo_data['Threat_Percentage'].idxmax()]
        
        # Use ASCII-compatible characters and handle special characters
        summary_text = [
            f"- Total global threats detected: {total_threats}",
            f"- Total URLs analyzed: {total_scans}",
            f"- Global threat rate: {avg_threat_rate:.1f}%",
            f"- Highest threat rate: {highest_threat_country['Country']} ({highest_threat_country['Threat_Percentage']}%)",
            f"- Countries with threats detected: {len(geo_data[geo_data['Threats'] > 0])}"
        ]
        
        for line in summary_text:
            # Encode to handle any special characters
            safe_line = line.encode('ascii', 'replace').decode('ascii')
            pdf.cell(200, 6, safe_line, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(10)
        
        # Top Threat Countries
        pdf.set_font("Helvetica", 'B', 12)
        pdf.cell(200, 8, "Top 10 Countries by Threat Count", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", '', 9)
        
        # Table headers
        pdf.cell(50, 6, "Country", border=1, align='C')
        pdf.cell(25, 6, "Threats", border=1, align='C')
        pdf.cell(25, 6, "Total", border=1, align='C')
        pdf.cell(30, 6, "Rate (%)", border=1, align='C')
        pdf.cell(30, 6, "Legitimate", border=1, align='C', new_x="LMARGIN", new_y="NEXT")
        
        # Table data
        top_10 = geo_data.head(10)
        for _, row in top_10.iterrows():
            # Handle country names with special characters
            safe_country = str(row['Country'])[:20].encode('ascii', 'replace').decode('ascii')
            pdf.cell(50, 6, safe_country, border=1)
            pdf.cell(25, 6, str(row['Threats']), border=1, align='C')
            pdf.cell(25, 6, str(row['Total_Scans']), border=1, align='C')
            pdf.cell(30, 6, f"{row['Threat_Percentage']:.1f}%", border=1, align='C')
            pdf.cell(30, 6, str(row['Legitimate']), border=1, align='C', new_x="LMARGIN", new_y="NEXT")
        
        pdf.ln(10)
        
        # Geographic Insights
        pdf.set_font("Helvetica", 'B', 12)
        pdf.cell(200, 8, "Geographic Insights", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", '', 10)
        
        # Calculate insights
        high_risk_countries = geo_data[geo_data['Threat_Percentage'] > avg_threat_rate]
        
        # Safe country name extraction
        most_active_country = geo_data.loc[geo_data['Total_Scans'].idxmax(), 'Country']
        safest_country = geo_data.loc[geo_data['Threat_Percentage'].idxmin(), 'Country']
        
        insights = [
            f"- {len(high_risk_countries)} countries have above-average threat rates",
            f"- Average threats per country: {geo_data['Threats'].mean():.1f}",
            f"- Most active region: {most_active_country}",
            f"- Safest region: {safest_country}"
        ]
        
        for insight in insights:
            # Encode to handle any special characters
            safe_insight = insight.encode('ascii', 'replace').decode('ascii')
            pdf.cell(200, 6, safe_insight, new_x="LMARGIN", new_y="NEXT")
        
        # Footer
        pdf.ln(20)
        pdf.set_font("Helvetica", 'I', 8)
        pdf.cell(200, 5, "Report generated by Threat Detection System - Geographic Analysis Module", 
                new_x="LMARGIN", new_y="NEXT", align='C')
        
        # Return as bytes for Streamlit compatibility
        return bytes(pdf.output())
        
    except ImportError:
        st.error("FPDF library required for PDF generation. Please install: pip install fpdf2")
        return None
    except Exception as e:
        st.error(f"Error generating PDF report: {str(e)}")
        return None


def test_geographic_analysis():
    """
    Test function for geographic analysis - can be called from the app for debugging.
    """
    st.markdown("### 🧪 Geographic Analysis Test")
    
    # Test URL to country extraction
    test_urls = [
        "https://example.com",
        "https://test.co.uk", 
        "https://sample.de",
        "https://demo.fr",
        "https://phishing-site.ru"
    ]
    
    st.markdown("#### URL to Country Mapping Test")
    for url in test_urls:
        country = extract_country_from_url(url)
        st.write(f"🌐 `{url}` → **{country}**")
    
    # Test data extraction
    st.markdown("#### Geographic Data Test")
    geo_data = get_geographic_threat_data()
    
    if not geo_data.empty:
        st.success(f"✅ Successfully extracted data for {len(geo_data)} countries")
        st.dataframe(geo_data.head())
    else:
        st.warning("⚠️ No geographic data found. Add some URL analyses first!")
    
    # Test sample data generation
    st.markdown("#### Sample Data Structure")
    sample_data = pd.DataFrame({
        'Country': ['United States', 'United Kingdom', 'Germany'],
        'Threats': [10, 5, 3],
        'Total_Scans': [50, 25, 15],
        'Threat_Percentage': [20.0, 20.0, 20.0]
    })
    st.dataframe(sample_data)


def test_pdf_generation():
    """
    Test function to verify PDF generation works without Unicode errors and returns correct data type.
    
    Returns:
        bool: True if PDF generation successful, False otherwise
    """
    try:
        pdf_data = generate_geographic_pdf_report()
        if pdf_data:
            if isinstance(pdf_data, bytes):
                print(f"✅ PDF generation successful - {len(pdf_data)} bytes, correct data type")
                return True
            else:
                print(f"⚠️ PDF generation returned wrong type: {type(pdf_data)}")
                return False
        else:
            print("⚠️ PDF generation returned None - no data available")
            return False
    except Exception as e:
        print(f"❌ PDF generation failed: {str(e)}")
        return False
