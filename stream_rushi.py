import os
import streamlit as st
from pymongo import MongoClient
import bcrypt
import re
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from validate_email import validate_email
import phonenumbers
import logging
from typing import Optional, Dict, Any
import pytz
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        # Retrieve credentials from environment variables
        username = os.getenv('MONGODB_USERNAME')
        password = os.getenv('MONGODB_PASSWORD')
        
        if not username or not password:
            raise ValueError("MongoDB credentials not configured")
        
        self.connection_string = f"mongodb+srv://{username}:{password}@cluster0.uu8yq.mongodb.net/?retryWrites=true&w=majority"
        self.client = None
        self.db = None
        self.users_collection = None
        self.activity_collection = None
        self.connect()

    def connect(self):
        try:
            self.client = MongoClient(self.connection_string)
            self.db = self.client["abhi"]
            self.users_collection = self.db["a"]
            self.activity_collection = self.db["activity_logs"]
            
            # Create indexes
            self.users_collection.create_index("email", unique=True)
            self.users_collection.create_index("mobile", unique=True)
            
            logger.info("Successfully connected to MongoDB")
        except Exception as e:
            logger.error(f"Database connection error: {str(e)}")
            st.error("Database connection failed. Please try again later.")

class Utils:
    @staticmethod
    def is_email_valid(email: str) -> bool:
        try:
            return validate_email(email)
        except Exception as e:
            logger.warning(f"Email validation error: {e}")
            return False

    @staticmethod
    def is_mobile_valid(mobile: str) -> bool:
        try:
            parsed_number = phonenumbers.parse(mobile, "IN")
            return phonenumbers.is_valid_number(parsed_number)
        except Exception as e:
            logger.warning(f"Mobile validation error: {e}")
            return False

    @staticmethod
    def hash_password(password: str) -> bytes:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    @staticmethod
    def verify_password(password: str, hashed: bytes) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed)

    @staticmethod
    def log_activity(db: DatabaseManager, user_id: str, action: str):
        ist = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(ist)
        
        db.activity_collection.insert_one({
            "user_id": user_id,
            "action": action,
            "timestamp": current_time
        })

    @staticmethod
    def validate_password_strength(password: str) -> list:
        """Enhanced password strength validation"""
        validations = []
        if len(password) < 12:
            validations.append("Must be at least 12 characters long")
        if not any(c.isupper() for c in password):
            validations.append("Must contain at least one uppercase letter")
        if not any(c.islower() for c in password):
            validations.append("Must contain at least one lowercase letter")
        if not any(c.isdigit() for c in password):
            validations.append("Must contain at least one number")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            validations.append("Must contain at least one special character")
        
        return validations

class AuthenticationSystem:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.utils = Utils()
        self.logger = logging.getLogger(__name__)

    def handle_registration(self):
        # Session state initialization (same as original code)
        if 'registration_form' not in st.session_state:
            st.session_state.registration_form = {
                'first_name': '',
                'last_name': '',
                'email': '',
                'mobile': '',
                'password': '',
                'confirm_password': ''
            }
        
        form_key = f"register_form_{uuid.uuid4().hex}"
        
        with st.form(form_key, clear_on_submit=True):
            # Form inputs (same as original code)
            col1, col2 = st.columns(2)
            with col1:
                first_name = st.text_input("First Name", 
                    value=st.session_state.registration_form['first_name'])
            with col2:
                last_name = st.text_input("Last Name",
                    value=st.session_state.registration_form['last_name'])
            
            col3, col4 = st.columns(2)
            with col3:
                email = st.text_input("Email",
                    value=st.session_state.registration_form['email'])
            with col4:
                mobile = st.text_input("Mobile Number",
                    value=st.session_state.registration_form['mobile'])
            
            col5, col6 = st.columns(2)
            with col5:
                password = st.text_input("Password", 
                    type="password",
                    value=st.session_state.registration_form['password'])
            with col6:
                confirm_password = st.text_input("Confirm Password",
                    type="password",
                    value=st.session_state.registration_form['confirm_password'])

            st.session_state.registration_form.update({
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'mobile': mobile,
                'password': password,
                'confirm_password': confirm_password
            })

            # Enhanced password validation
            password_validations = self.utils.validate_password_strength(password)

            if password_validations:
                st.warning("Password requirements:")
                for validation in password_validations:
                    st.warning(validation)

            terms = st.checkbox("I agree to the Terms and Conditions")
            submitted = st.form_submit_button("Register")

            if submitted:
                validation_errors = []

                # Validation checks (same as original code)
                if not first_name or len(first_name.strip()) < 2:
                    validation_errors.append("First name must be at least 2 characters long")
                if not last_name or len(last_name.strip()) < 2:
                    validation_errors.append("Last name must be at least 2 characters long")
                if not self.utils.is_email_valid(email):
                    validation_errors.append("Invalid email format")
                if not self.utils.is_mobile_valid(mobile):
                    validation_errors.append("Invalid mobile number format")
                if password != confirm_password:
                    validation_errors.append("Passwords do not match")
                if password_validations:
                    validation_errors.append("Password does not meet requirements")
                if not terms:
                    validation_errors.append("Please accept the Terms and Conditions")

                if validation_errors:
                    for error in validation_errors:
                        st.error(error)
                else:
                    try:
                        ist = pytz.timezone('Asia/Kolkata')
                        current_time = datetime.now(ist)
                        
                        hashed_password = self.utils.hash_password(password)
                        self.db.users_collection.insert_one({
                            "first_name": first_name,
                            "last_name": last_name,
                            "email": email,
                            "mobile": mobile,
                            "password": hashed_password,
                            "status": "no",
                            "created_at": current_time,
                            "last_login": None
                        })
                        st.success("Registration successful! Please wait for admin approval.")
                        
                        st.session_state.registration_form = {
                            'first_name': '', 'last_name': '', 
                            'email': '', 'mobile': '', 
                            'password': '', 'confirm_password': ''
                        }
                        
                        st.session_state.page = "login"
                    except Exception as e:
                        if "duplicate key error" in str(e):
                            st.error("Email or mobile number already registered.")
                        else:
                            self.logger.error(f"Registration error: {str(e)}")
                            st.error("Registration failed. Please try again.")

    def handle_login(self):
        # Login method remains the same as in original code
        st.title("Login")

        with st.form("login_form"):
            identifier = st.text_input("Email or Mobile Number")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")

            if submitted:
                user = self.db.users_collection.find_one({
                    "$or": [
                        {"email": identifier},
                        {"mobile": identifier}
                    ]
                })

                if not user:
                    st.error("Account not found.")
                elif not self.utils.verify_password(password, user['password']):
                    st.error("Incorrect password.")
                elif user['status'] == "no":
                    st.error("Your account is not active. Contact admin.")
                else:
                    ist = pytz.timezone('Asia/Kolkata')
                    current_time = datetime.now(ist)
                    
                    self.db.users_collection.update_one(
                        {"_id": user['_id']},
                        {"$set": {"last_login": current_time}}
                    )
                    self.utils.log_activity(self.db, str(user['_id']), "login")
                    st.success(f"Welcome {user['first_name']} {user['last_name']}!")
                    st.session_state['logged_in'] = True
                    st.session_state['user'] = user
                    st.rerun()
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.utils = Utils()
        self.logger = logging.getLogger(__name__)

    def handle_registration(self):
        # Initialize session state for form fields if not exists
        if 'registration_form' not in st.session_state:
            st.session_state.registration_form = {
                'first_name': '',
                'last_name': '',
                'email': '',
                'mobile': '',
                'password': '',
                'confirm_password': ''
            }
        
        # Use a unique form key to prevent duplicate form errors
        form_key = f"register_form_{uuid.uuid4().hex}"
        
        with st.form(form_key, clear_on_submit=True):
            # First Name and Last Name in the same row
            col1, col2 = st.columns(2)
            with col1:
                first_name = st.text_input("First Name", 
                    value=st.session_state.registration_form['first_name'],
                    key=f"first_name_input_{uuid.uuid4().hex}")
            with col2:
                last_name = st.text_input("Last Name",
                    value=st.session_state.registration_form['last_name'],
                    key=f"last_name_input_{uuid.uuid4().hex}")
            
            # Email and Mobile in the same row
            col3, col4 = st.columns(2)
            with col3:
                email = st.text_input("Email",
                    value=st.session_state.registration_form['email'],
                    key=f"email_input_{uuid.uuid4().hex}")
            with col4:
                mobile = st.text_input("Mobile Number",
                    value=st.session_state.registration_form['mobile'],
                    key=f"mobile_input_{uuid.uuid4().hex}")
            
            # Password and Confirm Password in the same row
            col5, col6 = st.columns(2)
            with col5:
                password = st.text_input("Password", 
                    type="password",
                    value=st.session_state.registration_form['password'],
                    key=f"password_input_{uuid.uuid4().hex}")
            with col6:
                confirm_password = st.text_input("Confirm Password",
                    type="password",
                    value=st.session_state.registration_form['confirm_password'],
                    key=f"confirm_password_input_{uuid.uuid4().hex}")

            # Update session state
            st.session_state.registration_form.update({
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'mobile': mobile,
                'password': password,
                'confirm_password': confirm_password
            })

            # Comprehensive Password Validation
            password_validations = []
            if password:
                if len(password) < 8:
                    password_validations.append("Must be at least 8 characters long")
                if not any(c.isupper() for c in password):
                    password_validations.append("Must contain at least one uppercase letter")
                if not any(c.isdigit() for c in password):
                    password_validations.append("Must contain at least one number")
                if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                    password_validations.append("Must contain at least one special character")

            # Display password validation warnings
            if password_validations:
                st.warning("Password requirements:")
                for validation in password_validations:
                    st.warning(validation)

            terms = st.checkbox("I agree to the Terms and Conditions")
            submitted = st.form_submit_button("Register")

            if submitted:
                # Comprehensive Form Validation
                validation_errors = []

                # First Name and Last Name Validation
                if not first_name or len(first_name.strip()) < 2:
                    validation_errors.append("First name must be at least 2 characters long")
                if not last_name or len(last_name.strip()) < 2:
                    validation_errors.append("Last name must be at least 2 characters long")

                # Email Validation
                if not self.utils.is_email_valid(email):
                    validation_errors.append("Invalid email format")

                # Mobile Number Validation
                if not self.utils.is_mobile_valid(mobile):
                    validation_errors.append("Invalid mobile number format")

                # Password Validation
                if password != confirm_password:
                    validation_errors.append("Passwords do not match")
                if password_validations:
                    validation_errors.append("Password does not meet requirements")

                # Terms and Conditions
                if not terms:
                    validation_errors.append("Please accept the Terms and Conditions")

                # Display or Process Registration
                if validation_errors:
                    for error in validation_errors:
                        st.error(error)
                else:
                    try:
                        ist = pytz.timezone('Asia/Kolkata')
                        current_time = datetime.now(ist)
                        
                        hashed_password = self.utils.hash_password(password)
                        self.db.users_collection.insert_one({
                            "first_name": first_name,
                            "last_name": last_name,
                            "email": email,
                            "mobile": mobile,
                            "password": hashed_password,
                            "status": "no",
                            "created_at": current_time,
                            "last_login": None
                        })
                        st.success("Registration successful! Please wait for admin approval.")
                        
                        # Reset registration form in session state
                        st.session_state.registration_form = {
                            'first_name': '',
                            'last_name': '',
                            'email': '',
                            'mobile': '',
                            'password': '',
                            'confirm_password': ''
                        }
                        
                        # Redirect to login page
                        st.session_state.page = "login"
                    except Exception as e:
                        if "duplicate key error" in str(e):
                            st.error("Email or mobile number already registered.")
                        else:
                            self.logger.error(f"Registration error: {str(e)}")
                            st.error("Registration failed. Please try again.")

    def handle_login(self):
        st.title("Login")

        with st.form("login_form"):
            identifier = st.text_input("Email or Mobile Number", key="login_identifier")
            password = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("Login")

            if submitted:
                user = self.db.users_collection.find_one({
                    "$or": [
                        {"email": identifier},
                        {"mobile": identifier}
                    ]
                })

                if not user:
                    st.error("Account not found.")
                elif not self.utils.verify_password(password, user['password']):
                    st.error("Incorrect password.")
                elif user['status'] == "no":
                    st.error("Your account is not active. Contact admin.")
                else:
                    ist = pytz.timezone('Asia/Kolkata')
                    current_time = datetime.now(ist)
                    
                    self.db.users_collection.update_one(
                        {"_id": user['_id']},
                        {"$set": {"last_login": current_time}}
                    )
                    self.utils.log_activity(self.db, str(user['_id']), "login")
                    st.success(f"Welcome {user['first_name']} {user['last_name']}!")
                    st.session_state['logged_in'] = True
                    st.session_state['user'] = user
                    st.rerun()
class AdminPanel:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.utils = Utils()

    def render(self):
        st.title("Admin Dashboard")
        
        if not self._verify_admin():
            return

        tabs = st.tabs(["📊 Analytics", "👥 User Management", "📝 Activity Logs"])
        
        with tabs[0]:
            self._analytics()
        with tabs[1]:
            self._user_management()
        with tabs[2]:
            self._activity_logs()

    def _verify_admin(self) -> bool:
        if "logged_in" in st.session_state and st.session_state.get('user', {}).get('status') == "admin":
            return True
        st.error("Access denied. Only admin can access this page.")
        return False

    def _user_management(self):
        st.subheader("User Management")
        
        users = list(self.db.users_collection.find())
        user_df = pd.DataFrame(users)
        
        col1, col2 = st.columns([2, 3])
        with col1:
            status_filter = st.multiselect("Filter by Status", ["yes", "no", "admin"])
        with col2:
            search = st.text_input("🔍 Search by name or email")

        if status_filter:
            user_df = user_df[user_df['status'].isin(status_filter)]
        if search:
            mask = (
                user_df['first_name'].str.contains(search, case=False, na=False) |
                user_df['last_name'].str.contains(search, case=False, na=False) |
                user_df['email'].str.contains(search, case=False, na=False)
            )
            user_df = user_df[mask]

        for _, user in user_df.iterrows():
            with st.container():
                with st.expander(f"👤 {user['first_name']} {user['last_name']} ({user['email']})"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"📱 Mobile: {user['mobile']}")
                        st.write(f"🔵 Status: {user['status']}")
                        # Convert timestamps to IST
                        ist = pytz.timezone('Asia/Kolkata')
                        created_at = user['created_at'].astimezone(ist)
                        last_login = user.get('last_login')
                        if last_login:
                            last_login = last_login.astimezone(ist)
                        
                        st.write(f"📅 Created: {created_at.strftime('%Y-%m-%d %H:%M:%S IST')}")
                        st.write(f"🕒 Last Login: {last_login.strftime('%Y-%m-%d %H:%M:%S IST') if last_login else 'Never'}")
                    
                    with col2:
                        if user['status'] == "no":
                            if st.button("✅ Activate", key=f"activate_{user['_id']}"):
                                self.db.users_collection.update_one(
                                    {"_id": user['_id']},
                                    {"$set": {"status": "yes"}}
                                )
                                self.utils.log_activity(self.db, str(user['_id']), "user_activated")
                                st.success("User activated!")
                                st.rerun()
                        
                        if user['status'] != "admin":
                            if st.button("👑 Make Admin", key=f"admin_{user['_id']}"):
                                self.db.users_collection.update_one(
                                    {"_id": user['_id']},
                                    {"$set": {"status": "admin"}}
                                )
                                self.utils.log_activity(self.db, str(user['_id']), "made_admin")
                                st.success("User promoted!")
                                st.rerun()

                        if st.button("🗑️ Delete", key=f"delete_{user['_id']}"):
                            self.db.users_collection.delete_one({"_id": user['_id']})
                            self.utils.log_activity(self.db, str(user['_id']), "user_deleted")
                            st.success("User deleted!")
                            st.rerun()

    def _analytics(self):
        st.subheader("Analytics Dashboard")
        
        users = list(self.db.users_collection.find())
        df = pd.DataFrame(users)
        
        col1, col2, col3, col4 = st.columns(4)
        total_users = len(users)
        active_users = len([u for u in users if u['status'] == "yes"])
        pending_users = len([u for u in users if u['status'] == "no"])
        admin_users = len([u for u in users if u['status'] == "admin"])
        
        col1.metric("👥 Total Users", total_users)
        col2.metric("✅ Active Users", active_users)
        col3.metric("⏳ Pending", pending_users)
        col4.metric("👑 Admins", admin_users)
        
        st.subheader("User Growth Analysis")
        
        # Convert timestamps to IST
        ist = pytz.timezone('Asia/Kolkata')
        df['created_at'] = pd.to_datetime(df['created_at']).apply(lambda x: x.astimezone(ist))
        df['date'] = df['created_at'].dt.date
        
        daily_registrations = df.groupby('date').size().reset_index(name='count')
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=daily_registrations['date'],
            y=daily_registrations['count'],
            mode='lines+markers',
            name='Registrations',
            line=dict(color='#1f77b4'),
            fill='tozeroy'
        ))
        fig.update_layout(
            title='Daily Registration Trend',
            xaxis_title='Date',
            yaxis_title='Number of Registrations',
            hovermode='x unified'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        status_dist = df['status'].value_counts()
        fig_pie = px.pie(
            values=status_dist.values,
            names=status_dist.index,
            title='User Status Distribution',
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    def _activity_logs(self):
        st.subheader("Activity Logs")
        
        logs = list(self.db.activity_collection.find().sort("timestamp", -1).limit(100))
        if logs:
            log_df = pd.DataFrame(logs)
            
            # Convert timestamps to IST
            ist = pytz.timezone('Asia/Kolkata')
            log_df['timestamp'] = pd.to_datetime(log_df['timestamp']).apply(lambda x: x.astimezone(ist))
            
            # Activity Visualization
            fig = px.scatter(
                log_df,
                x="timestamp",
                y="action",
                title="Recent Activity Visualization",
                color="action",
                size=[10] * len(log_df),
                template="plotly_white"
            )
            
            fig.update_traces(marker=dict(symbol='circle'))
            fig.update_layout(
                showlegend=True,
                xaxis_title="Time",
                yaxis_title="Activity Type",
                height=400,
                yaxis={'categoryorder': 'category ascending'}
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Activity Summary
            st.subheader("Activity Summary")
            activity_counts = log_df['action'].value_counts()
            
            fig_bar = px.bar(
                x=activity_counts.index,
                y=activity_counts.values,
                title="Activity Distribution",
                labels={'x': 'Activity Type', 'y': 'Count'},
                color=activity_counts.values,
                color_continuous_scale='Viridis'
            )
            
            st.plotly_chart(fig_bar, use_container_width=True)
            
            # Detailed Log Table
            st.subheader("Detailed Activity Log")
            styled_df = log_df.copy()
            styled_df['timestamp'] = styled_df['timestamp'].dt.strftime("%Y-%m-%d %H:%M:%S IST")
            
            st.dataframe(
                styled_df[['timestamp', 'user_id', 'action']].sort_values(by='timestamp', ascending=False),
                column_config={
                    "timestamp": st.column_config.Column(
                        "Time",
                        width="medium",
                    ),
                    "user_id": st.column_config.Column(
                        "User ID",
                        width="medium",
                    ),
                    "action": st.column_config.Column(
                        "Action",
                        width="medium",
                    )
                },
                hide_index=True,
                use_container_width=True
            )
        else:
            st.info("No activity logs found")

class UserDashboard:
    def __init__(self, db: DatabaseManager, user):
        self.db = db
        self.user = user
        self.utils = Utils()

    def render(self):
        st.title(f"Welcome, {self.user['first_name']}!")
        
        tabs = st.tabs(["📊 Dashboard", "👤 Profile", "⚙️ Settings", "🔢 Table of 10"])
        
        with tabs[0]:
            self._show_dashboard()
        with tabs[1]:
            self._show_profile()
        with tabs[2]:
            self._show_settings()
        with tabs[3]:
            self._show_multiplication_table()

    def _show_dashboard(self):
        st.subheader("Your Activity")
        
        logs = list(self.db.activity_collection.find({"user_id": str(self.user['_id'])}).sort("timestamp", -1))
        
        if logs:
            log_df = pd.DataFrame(logs)
            
            # Convert timestamps to IST
            ist = pytz.timezone('Asia/Kolkata')
            log_df['timestamp'] = pd.to_datetime(log_df['timestamp']).apply(lambda x: x.astimezone(ist))
            
            # Activity Summary
            col1, col2 = st.columns(2)
            
            with col1:
                activity_counts = log_df['action'].value_counts()
                fig = px.pie(
                    values=activity_counts.values,
                    names=activity_counts.index,
                    title='Your Activity Distribution',
                    color_discrete_sequence=px.colors.qualitative.Set3
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                fig = px.scatter(
                    log_df,
                    x='timestamp',
                    y='action',
                    title='Your Activity Timeline',
                    color='action'
                )
                st.plotly_chart(fig, use_container_width=True)
            
            st.subheader("Recent Activities")
            for _, log in log_df.head(5).iterrows():
                st.write(f"🔹 {log['action']} - {log['timestamp'].strftime('%Y-%m-%d %H:%M:%S IST')}")
        else:
            st.info("No activity recorded yet")

    def _show_profile(self):
        st.subheader("My Profile")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
                <div style='padding: 15px; border: 1px solid #f0f2f6; border-radius: 5px;'>
                    <h4>Personal Information</h4>
                </div>
            """, unsafe_allow_html=True)
            st.write(f"**Full Name:** {self.user['first_name']} {self.user['last_name']}")
            st.write(f"**Email:** {self.user['email']}")
            st.write(f"**Mobile:** {self.user['mobile']}")
            
        with col2:
            st.markdown("""
                <div style='padding: 15px; border: 1px solid #f0f2f6; border-radius: 5px;'>
                    <h4>Account Information</h4>
                </div>
            """, unsafe_allow_html=True)
            st.write(f"**Account Status:** {self.user['status']}")
            
            # Convert timestamps to IST
            ist = pytz.timezone('Asia/Kolkata')
            last_login = self.user.get('last_login')
            if last_login:
                last_login = last_login.astimezone(ist)
            created_at = self.user['created_at'].astimezone(ist)
            
            st.write(f"**Last Login:** {last_login.strftime('%Y-%m-%d %H:%M:%S IST') if last_login else 'Never'}")
            st.write(f"**Account Created:** {created_at.strftime('%Y-%m-%d %H:%M:%S IST')}")

    def _show_settings(self):
        st.subheader("Settings")
        
        with st.form("settings_form"):
            st.markdown("### Personal Information")
            col1, col2 = st.columns(2)
            
            with col1:
                first_name = st.text_input("First Name", value=self.user['first_name'])
                email = st.text_input("Email", value=self.user['email'], disabled=True)
                
            with col2:
                last_name = st.text_input("Last Name", value=self.user['last_name'])
                mobile = st.text_input("Mobile", value=self.user['mobile'], disabled=True)
            
            st.markdown("### Change Password")
            col3, col4 = st.columns(2)
            
            with col3:
                current_password = st.text_input("Current Password", type="password")
                new_password = st.text_input("New Password (optional)", type="password")
                
            with col4:
                password_requirements = """
                Password Requirements:
                - At least 8 characters
                - One uppercase letter
                - One number
                """
                st.markdown(password_requirements)
            
            submitted = st.form_submit_button("Save Changes")
            
            if submitted:
                if current_password:
                    if not self.utils.verify_password(current_password, self.user['password']):
                        st.error("Current password is incorrect.")
                        return
                    
                    update_data = {
                        "first_name": first_name,
                        "last_name": last_name,
                    }
                    
                    if new_password:
                        if len(new_password) < 8:
                            st.error("New password must be at least 8 characters long")
                            return
                        if not any(c.isupper() for c in new_password):
                            st.error("New password must contain at least one uppercase letter")
                            return
                        if not any(c.isdigit() for c in new_password):
                            st.error("New password must contain at least one number")
                            return
                        
                        update_data["password"] = self.utils.hash_password(new_password)
                    
                    try:
                        self.db.users_collection.update_one(
                            {"_id": self.user['_id']},
                            {"$set": update_data}
                        )
                        self.utils.log_activity(self.db, str(self.user['_id']), "profile_updated")
                        st.success("Profile updated successfully!")
                        updated_user = self.db.users_collection.find_one({"_id": self.user['_id']})
                        st.session_state['user'] = updated_user
                        st.rerun()
                    except Exception as e:
                        logger.error(f"Profile update error: {str(e)}")
                        st.error("Failed to update profile. Please try again.")
                else:
                    st.error("Please enter your current password to save changes.")

    def _show_multiplication_table(self):
        st.subheader("Multiplication Table of 10")
        
        col1, col2 = st.columns([2, 3])
        
        with col1:
            st.markdown("### Numerical Table")
            table_data = [(i, i * 10) for i in range(1, 11)]
            table_df = pd.DataFrame(table_data, columns=['Number', 'Result'])
            
            st.dataframe(
                table_df,
                column_config={
                    "Number": st.column_config.NumberColumn(
                        "Number",
                        format="%d",
                        help="The multiplier"
                    ),
                    "Result": st.column_config.NumberColumn(
                        "10 ×",
                        format="%d",
                        help="The product of the number and 10"
                    )
                },
                hide_index=True,
                use_container_width=True
            )
            
            st.info("💡 Fun Fact: Multiplying by 10 is the same as adding a zero to the end of a number!")
        
        with col2:
            fig = px.bar(
                table_df,
                x='Number',
                y='Result',
                title='Visual Representation of 10\'s Table',
                labels={'Number': 'Multiplier', 'Result': 'Product'},
                text='Result'
            )
            
            fig.update_traces(
                textposition='outside',
                marker_color='rgb(255, 127, 80)',
                marker_line_color='rgb(205, 92, 92)',
                marker_line_width=1.5
            )
            
            fig.update_layout(
                showlegend=False,
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis_gridcolor='rgba(0,0,0,0.1)',
                yaxis_gridcolor='rgba(0,0,0,0.1)',
                title_x=0.5,
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("### Practice Section")
        col3, col4 = st.columns([1, 2])
        
        with col3:
            try:
                number = st.number_input(
                    "Enter a number to multiply by 10",
                    min_value=1,
                    max_value=100,
                    value=1,
                    help="Choose a number between 1 and 100"
                )
            except Exception as e:
                st.error(f"Please enter a valid number: {str(e)}")
                return
        
        with col4:
            result = number * 10
            st.markdown(
                f"<h3 style='color: #FF7F50;'>{number} × 10 = {result}</h3>",
                unsafe_allow_html=True
            )
        
        progress_value = number/100
        st.progress(
            progress_value,
            text=f"Progress: {int(progress_value * 100)}%"
        )

def main():
    st.set_page_config(
        page_title="User Authentication System",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.markdown("""
        <style>
        .stButton>button {
            width: 100%;
        }
        .stTextInput>div>div>input {
            color: #4F8BF9;
        }
        </style>
        """, unsafe_allow_html=True)
    
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'page' not in st.session_state:
        st.session_state.page = "login"
    
    db = DatabaseManager()
    auth_system = AuthenticationSystem(db)
    
    with st.sidebar:
        st.title("🔐 Navigation")
        if st.session_state.logged_in:
            user = st.session_state.user
            st.write(f"Welcome, {user['first_name']}!")
            if st.button("📤 Logout", key="logout"):
                st.session_state.logged_in = False
                st.session_state.user = None
                st.session_state.page = "login"
                st.rerun()
        else:
            page = st.radio("Choose Option", ["🔑 Login", "📝 Register"])
            st.session_state.page = page.split()[-1].lower()
    
    if st.session_state.logged_in:
        user = st.session_state.user
        if user['status'] == "admin":
            admin_panel = AdminPanel(db)
            admin_panel.render()
        else:
            user_dashboard = UserDashboard(db, user)
            user_dashboard.render()
    else:
        if st.session_state.page == "register":
            auth_system.handle_registration()
        else:
            auth_system.handle_login()

if __name__ == "__main__":
    main()    