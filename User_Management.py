# User_Management.py
# ---------------------------------------------------------
# User Management System for Phishing Detection Application
# Provides functionality to manage users including deletion
# ---------------------------------------------------------

import json
import os
import hashlib
import streamlit as st
from datetime import datetime
import shutil
import glob

# File paths
USERS_FILE = "data/users.json"
DATA_DIR = "data"

class UserManager:
    """
    User management class for handling user operations including deletion.
    """
    
    def __init__(self):
        self.users_file = USERS_FILE
        self.data_dir = DATA_DIR
        
    def load_users(self):
        """
        Load users from the JSON file.
        
        Returns:
            dict: User data dictionary
        """
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                st.error("Error: Users file is corrupted.")
                return {}
        else:
            st.warning("Users file not found.")
            return {}
    
    def save_users(self, users_data):
        """
        Save users data to the JSON file.
        
        Args:
            users_data (dict): Updated users dictionary
        """
        try:
            # Create backup before saving
            if os.path.exists(self.users_file):
                backup_file = f"{self.users_file}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(self.users_file, backup_file)
            
            # Ensure data directory exists
            os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
            
            with open(self.users_file, 'w') as f:
                json.dump(users_data, f, indent=2)
            return True
        except Exception as e:
            st.error(f"Error saving users: {str(e)}")
            return False
    
    def get_user_list(self):
        """
        Get a list of all users with their basic information.
        
        Returns:
            list: List of user dictionaries
        """
        users = self.load_users()
        user_list = []
        
        for email, user_data in users.items():
            user_list.append({
                'email': email,
                'role': user_data.get('role', 'user'),
                'status': user_data.get('status', 'active'),
                'created_at': user_data.get('created_at', 'Unknown'),
                'last_login': user_data.get('last_login', 'Never')
            })
        
        return user_list
    
    def delete_user(self, email):
        """
        Delete a user and all associated data.
        
        Args:
            email (str): Email of the user to delete
            
        Returns:
            bool: True if deletion successful, False otherwise
        """
        try:
            # Load current users
            users = self.load_users()
            
            if email not in users:
                st.error(f"User {email} not found.")
                return False
            
            # Get username for file operations
            username = email.split('@')[0]
            
            # Remove user from users.json
            del users[email]
            
            # Save updated users file
            if not self.save_users(users):
                return False
            
            # Delete associated data files
            self._delete_user_files(email, username)
            
            st.success(f"✅ User {email} and all associated data deleted successfully.")
            return True
            
        except Exception as e:
            st.error(f"Error deleting user {email}: {str(e)}")
            return False
    
    def _delete_user_files(self, email, username):
        """
        Delete all files associated with a user.
        
        Args:
            email (str): User email
            username (str): Username (part before @)
        """
        try:
            # Files to delete based on username/email patterns
            file_patterns = [
                f"history_{username}.json",
                f"feedback_{username}.json",
                f"analysis_{username}.json",
                f"session_{username}.json"
            ]
            
            deleted_files = []
            
            for pattern in file_patterns:
                file_path = os.path.join(self.data_dir, pattern)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    deleted_files.append(pattern)
            
            # Also check for any files containing the email address
            for filename in os.listdir(self.data_dir):
                file_path = os.path.join(self.data_dir, filename)
                if os.path.isfile(file_path) and filename.endswith('.json'):
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            if email in content and filename not in ['users.json']:
                                # Create backup before deletion
                                backup_path = f"{file_path}.deleted_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                                shutil.copy2(file_path, backup_path)
                                os.remove(file_path)
                                deleted_files.append(filename)
                    except:
                        continue
            
            if deleted_files:
                st.info(f"📁 Deleted files: {', '.join(deleted_files)}")
            else:
                st.info("ℹ️ No additional user files found to delete.")
                
        except Exception as e:
            st.warning(f"Warning: Some user files could not be deleted: {str(e)}")
    
    def deactivate_user(self, email):
        """
        Deactivate a user without deleting their data.
        
        Args:
            email (str): Email of the user to deactivate
            
        Returns:
            bool: True if deactivation successful, False otherwise
        """
        try:
            users = self.load_users()
            
            if email not in users:
                st.error(f"User {email} not found.")
                return False
            
            users[email]['status'] = 'inactive'
            users[email]['deactivated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            if self.save_users(users):
                st.success(f"✅ User {email} deactivated successfully.")
                return True
            return False
            
        except Exception as e:
            st.error(f"Error deactivating user {email}: {str(e)}")
            return False
    
    def reactivate_user(self, email):
        """
        Reactivate a deactivated user.
        
        Args:
            email (str): Email of the user to reactivate
            
        Returns:
            bool: True if reactivation successful, False otherwise
        """
        try:
            users = self.load_users()
            
            if email not in users:
                st.error(f"User {email} not found.")
                return False
            
            users[email]['status'] = 'active'
            if 'deactivated_at' in users[email]:
                del users[email]['deactivated_at']
            users[email]['reactivated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            if self.save_users(users):
                st.success(f"✅ User {email} reactivated successfully.")
                return True
            return False
            
        except Exception as e:
            st.error(f"Error reactivating user {email}: {str(e)}")
            return False
    
    def change_user_role(self, email, new_role):
        """
        Change a user's role.
        
        Args:
            email (str): Email of the user
            new_role (str): New role (admin, analyst, user)
            
        Returns:
            bool: True if role change successful, False otherwise
        """
        valid_roles = ['admin', 'analyst', 'user']
        
        if new_role not in valid_roles:
            st.error(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
            return False
        
        try:
            users = self.load_users()
            
            if email not in users:
                st.error(f"User {email} not found.")
                return False
            
            old_role = users[email].get('role', 'user')
            users[email]['role'] = new_role
            users[email]['role_changed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            if self.save_users(users):
                st.success(f"✅ User {email} role changed from {old_role} to {new_role}")
                return True
            return False
            
        except Exception as e:
            st.error(f"Error changing role for user {email}: {str(e)}")
            return False
    
    def get_user_stats(self):
        """
        Get statistics about users.
        
        Returns:
            dict: User statistics
        """
        users = self.load_users()
        
        stats = {
            'total_users': len(users),
            'active_users': len([u for u in users.values() if u.get('status') == 'active']),
            'inactive_users': len([u for u in users.values() if u.get('status') == 'inactive']),
            'admin_users': len([u for u in users.values() if u.get('role') == 'admin']),
            'analyst_users': len([u for u in users.values() if u.get('role') == 'analyst']),
            'regular_users': len([u for u in users.values() if u.get('role') == 'user'])
        }
        
        return stats
    
    def export_users(self):
        """
        Export user data for backup or analysis.
        
        Returns:
            str: CSV formatted user data
        """
        users = self.load_users()
        csv_lines = ['Email,Role,Status,Created At,Last Login']
        
        for email, data in users.items():
            line = f"{email},{data.get('role', 'user')},{data.get('status', 'active')},{data.get('created_at', 'Unknown')},{data.get('last_login', 'Never')}"
            csv_lines.append(line)
        
        return '\n'.join(csv_lines)


def main():
    """
    Main function to run the user management interface.
    """
    st.set_page_config(
        page_title="User Management System",
        page_icon="👥",
        layout="wide"
    )
    
    st.title("👥 User Management System")
    st.markdown("---")
    
    # Initialize user manager
    user_manager = UserManager()
    
    # Sidebar for navigation
    st.sidebar.title("🛠️ Management Options")
    operation = st.sidebar.selectbox(
        "Select Operation",
        ["View Users", "Delete User", "Deactivate User", "Reactivate User", "Change Role", "User Statistics", "Export Users"]
    )
    
    if operation == "View Users":
        st.header("👀 View All Users")
        
        users_list = user_manager.get_user_list()
        
        if not users_list:
            st.warning("No users found.")
            return
        
        # Display users in a table
        st.dataframe(users_list, use_container_width=True)
        
        # Show user count
        st.info(f"📊 Total Users: {len(users_list)}")
    
    elif operation == "Delete User":
        st.header("🗑️ Delete User")
        st.warning("⚠️ **WARNING**: This action will permanently delete the user and ALL associated data including history, feedback, and analysis records.")
        
        users_list = user_manager.get_user_list()
        
        if not users_list:
            st.error("No users found.")
            return
        
        # Select user to delete
        user_emails = [user['email'] for user in users_list]
        selected_email = st.selectbox("Select User to Delete", user_emails)
        
        if selected_email:
            # Show user details
            selected_user = next(user for user in users_list if user['email'] == selected_email)
            
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"""
                **User Details:**
                - Email: {selected_user['email']}
                - Role: {selected_user['role']}
                - Status: {selected_user['status']}
                - Created: {selected_user['created_at']}
                - Last Login: {selected_user['last_login']}
                """)
            
            # Confirmation
            confirm = st.checkbox(f"I confirm I want to DELETE user {selected_email} and ALL their data")
            
            if confirm:
                if st.button("🗑️ DELETE USER", type="primary"):
                    if user_manager.delete_user(selected_email):
                        st.balloons()
                        st.rerun()
    
    elif operation == "Deactivate User":
        st.header("⏸️ Deactivate User")
        st.info("ℹ️ Deactivating a user will prevent them from logging in but preserve their data.")
        
        users_list = user_manager.get_user_list()
        active_users = [user for user in users_list if user['status'] == 'active']
        
        if not active_users:
            st.warning("No active users found.")
            return
        
        user_emails = [user['email'] for user in active_users]
        selected_email = st.selectbox("Select User to Deactivate", user_emails)
        
        if selected_email and st.button("⏸️ Deactivate User"):
            if user_manager.deactivate_user(selected_email):
                st.rerun()
    
    elif operation == "Reactivate User":
        st.header("▶️ Reactivate User")
        
        users_list = user_manager.get_user_list()
        inactive_users = [user for user in users_list if user['status'] == 'inactive']
        
        if not inactive_users:
            st.info("No inactive users found.")
            return
        
        user_emails = [user['email'] for user in inactive_users]
        selected_email = st.selectbox("Select User to Reactivate", user_emails)
        
        if selected_email and st.button("▶️ Reactivate User"):
            if user_manager.reactivate_user(selected_email):
                st.rerun()
    
    elif operation == "Change Role":
        st.header("🔄 Change User Role")
        
        users_list = user_manager.get_user_list()
        
        if not users_list:
            st.warning("No users found.")
            return
        
        user_emails = [user['email'] for user in users_list]
        selected_email = st.selectbox("Select User", user_emails)
        
        if selected_email:
            current_user = next(user for user in users_list if user['email'] == selected_email)
            st.info(f"Current Role: **{current_user['role']}**")
            
            new_role = st.selectbox("New Role", ["admin", "analyst", "user"])
            
            if new_role != current_user['role']:
                if st.button("🔄 Change Role"):
                    if user_manager.change_user_role(selected_email, new_role):
                        st.rerun()
    
    elif operation == "User Statistics":
        st.header("📊 User Statistics")
        
        stats = user_manager.get_user_stats()
        
        # Display statistics in columns
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Users", stats['total_users'])
            st.metric("Active Users", stats['active_users'])
        
        with col2:
            st.metric("Inactive Users", stats['inactive_users'])
            st.metric("Admin Users", stats['admin_users'])
        
        with col3:
            st.metric("Analyst Users", stats['analyst_users'])
            st.metric("Regular Users", stats['regular_users'])
        
        # Visual chart
        if stats['total_users'] > 0:
            import pandas as pd
            
            role_data = pd.DataFrame({
                'Role': ['Admin', 'Analyst', 'User'],
                'Count': [stats['admin_users'], stats['analyst_users'], stats['regular_users']]
            })
            
            status_data = pd.DataFrame({
                'Status': ['Active', 'Inactive'],
                'Count': [stats['active_users'], stats['inactive_users']]
            })
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.bar_chart(role_data.set_index('Role'))
            
            with col2:
                st.bar_chart(status_data.set_index('Status'))
    
    elif operation == "Export Users":
        st.header("📥 Export Users")
        
        csv_data = user_manager.export_users()
        
        st.download_button(
            label="📊 Download User Data (CSV)",
            data=csv_data,
            file_name=f"users_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        
        st.text_area("CSV Preview", csv_data, height=200)


if __name__ == "__main__":
    main()
