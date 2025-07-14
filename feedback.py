# feedback.py
import streamlit as st
import json
import os
from datetime import datetime
import logger  # Import logger to add feedback to history

def _get_feedback_file():
    user = st.session_state.get("user_email", "anonymous").split("@")[0]
    return f"data/feedback_{user}.json"

def _load_feedback():
    file = _get_feedback_file()
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return []

def _save_feedback(feedback_list):
    file = _get_feedback_file()
    os.makedirs("data", exist_ok=True)
    with open(file, "w") as f:
        json.dump(feedback_list, f, indent=2)

def collect_feedback(url: str, predicted_label: str, confidence: float):
    key_prefix = url.replace("https://", "").replace("http://", "").replace("/", "_")

    # Initialise session feedback cache
    if f"{key_prefix}_choice" not in st.session_state:
        st.session_state[f"{key_prefix}_choice"] = "👍 Correct"
    if f"{key_prefix}_comment" not in st.session_state:
        st.session_state[f"{key_prefix}_comment"] = ""

    with st.expander("💡 Give Feedback", expanded=True):
        choice = st.radio(
            "How would you rate this prediction?",
            ["👍 Correct", "👎 Incorrect"],
            key=f"{key_prefix}_choice"
        )
        comment = st.text_area(
            "Additional comments (optional):",
            key=f"{key_prefix}_comment",
            placeholder="Share your thoughts about this prediction..."
        )

        if st.button("Submit Feedback 📨", key=f"{key_prefix}_submit"):
            # Check if feedback was already submitted for this URL
            if st.session_state.get(f"{key_prefix}_feedback_submitted", False):
                st.warning("💬 Feedback already submitted for this URL.")
                return
                
            feedback_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "url": url,
                "predicted_label": predicted_label,
                "confidence": f"{confidence:.2%}",
                "user_feedback": choice,
                "user_comment": comment.strip(),
                "feedback_type": "Correct" if choice == "👍 Correct" else "Incorrect"
            }

            feedback_log = _load_feedback()
            feedback_log.append(feedback_entry)
            _save_feedback(feedback_log)

            # ✅ NEW: Also add feedback to history for unified view
            _add_feedback_to_history(url, predicted_label, confidence, choice, comment.strip())

            # Store feedback submission status in session state
            st.session_state[f"{key_prefix}_feedback_submitted"] = True
            st.success("✅ Feedback submitted successfully!")
        
        # Show confirmation message only if feedback was submitted but button wasn't just clicked
        elif st.session_state.get(f"{key_prefix}_feedback_submitted", False):
            st.info("💬 Feedback already submitted for this URL.")

def display_feedback_log():
    feedback_log = _load_feedback()
    if feedback_log:
        st.markdown("### 🗂️ Your Submitted Feedback")
        st.dataframe(feedback_log, use_container_width=True)
    else:
        st.info("No feedback submitted yet.")

def _add_feedback_to_history(url: str, predicted_label: str, confidence: float, user_feedback: str, user_comment: str):
    """
    Add feedback entry to user's history for unified view.
    
    Args:
        url (str): The URL that was analyzed
        predicted_label (str): The prediction made by the model
        confidence (float): The confidence score
        user_feedback (str): User's feedback choice
        user_comment (str): User's comment
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
    
    # Create feedback entry for history
    feedback_history_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "prediction": f"FEEDBACK: {predicted_label}",
        "confidence": confidence,
        "risk_score": 0,
        "risk_level": "Feedback",
        "model_used": "User Feedback",
        "features_count": 0,
        "analysis_time": 0,
        "user_feedback": user_feedback,
        "user_comment": user_comment,
        "feedback_type": "Correct" if user_feedback == "👍 Correct" else "Incorrect",
        "entry_type": "feedback"  # Mark as feedback entry
    }
    
    # Add to history
    history.append(feedback_history_entry)
    
    # Save updated history
    os.makedirs('data', exist_ok=True)
    with open(history_file, 'w') as f:
        json.dump(history, f, indent=2)
