# 🛡️ Threat Detection & Resilience Framework - MSc Project 2025

![Threat Detection Banner](1721182567770.jpeg)

## 🔍 Overview

The Threat Detection and Resilience Framework is a sophisticated phishing detection system powered by machine learning. Designed for real-time threat analysis and comprehensive security assessments, it features an intuitive web interface built with Streamlit. This allows both cybersecurity professionals and end-users to efficiently analyze URLs and detect potential phishing threats.

## 🚀 Quick Start

### Try Online Instantly
You can try the deployed Streamlit app without any installation:

[Launch the App Online](https://ml-phishing-detector-9fnjjbmpunudnfpjycgnq8.streamlit.app/)

### Prerequisites
- Python 3.8 or higher
- `pip` package manager
- An active internet connection for real-time analysis

### Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/maxtowsif/ml-phishing-detector.git
    cd ml-phishing-detector
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Launch the Application**
    ```bash
    streamlit run app.py
    ```

4.  **User Management (Admin Only)**
    - To manage users (add, edit, or remove accounts), run the following command in a separate terminal:
      ```bash
      streamlit run User_Management.py
      ```
    - This will launch a dedicated user management interface for administrators.

5.  **Access the System**
    - Open your web browser and navigate to `http://localhost:8501`.
    - Use the following demo credentials to log in:
      - **Admin**: `admin@mscproject.com` / `admin2025`
      - **Analyst**: `analyst@example.com` / `analyst123`
      - **User**: `user@example.com` / `password123`

## ⚙️ Technical Specifications

### Machine Learning Pipeline
- **Algorithm**: Random Forest Classifier with 100 estimators.
- **Features**: 30+ engineered features derived from URL structure and domain properties.
- **Training Data**: A dataset of over 10,000 labeled phishing and legitimate URLs.
- **Performance**: Achieves over 85% accuracy and 90% precision in phishing detection.
- **Feature Selection**: Utilizes Recursive Feature Elimination with Cross-Validation (RFECV).

### Security Analysis Engine
- **SSL Validation**: Certificate chain verification, expiration tracking, and security extension analysis.
- **DNS Analysis**: Multi-record resolution with a comprehensive security scoring model.
- **WHOIS Intelligence**: Domain registration analysis and age-based risk assessment.
- **HTTP Security**: In-depth header analysis, redirect tracking, and response validation.

### Performance Metrics
- **Response Time**: Less than 2 seconds for a single URL analysis.
- **Throughput**: Capable of processing over 100 URLs per minute in bulk analysis mode.
- **Availability**: Designed for 99.9% uptime with robust error recovery mechanisms.
- **Scalability**: Supports concurrent users with secure session isolation.

## 🛡️ Security Features

### Data Protection
- **Secure Authentication**: Implements Bcrypt password hashing with unique salts.
- **Session Security**: Employs encrypted session storage with automated timeout management.
- **Input Validation**: Enforces comprehensive sanitization and validation on all user inputs.
- **Error Handling**: Provides secure error messages that prevent information disclosure.

### Privacy Compliance
- **Data Minimization**: Adheres to data minimization principles, collecting only essential data.
- **User Control**: Grants users complete control over their personal data and analysis history.
- **Secure Storage**: Uses local JSON storage with strict user data isolation.
- **No External Tracking**: All analysis is performed locally to ensure user privacy.

## 🎯 Usage Scenarios

### For Cybersecurity Professionals
- Conduct real-time threat assessments for incident response.
- Perform bulk URL analysis for threat hunting and investigations.
- Analyze trends for building actionable threat intelligence.
- Generate detailed reports for security audits and documentation.

### For IT Administrators
- Verify URLs to enforce security policies and block malicious sites.
- Use as a tool for security awareness training with real-world examples.
- Implement proactive threat prevention and continuous monitoring.
- Integrate with existing security workflows via API (future goal).

### For End-Users
- Verify the safety of URLs before clicking on suspicious links.
- Use as an educational tool to learn about phishing techniques.
- Gain security insights through detailed, easy-to-understand analysis.
- Develop safer browsing habits and enhance personal cybersecurity posture.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

**Author**: Towsif Ahmed  
**Last Updated**: July 2025  
**Repository**: [ml-phishing-detector](https://github.com/maxtowsif/ml-phishing-detector)