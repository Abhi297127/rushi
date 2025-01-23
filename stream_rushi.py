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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB setup
class DatabaseManager:
    def __init__(self, username: str, password: str):
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
        except:
            return False

    @staticmethod
    def is_mobile_valid(mobile: str) -> bool:
        try:
            parsed_number = phonenumbers.parse(mobile, "IN")
            return phonenumbers.is_valid_number(parsed_number)
        except:
            return False

    @staticmethod
    def hash_password(password: str) -> bytes:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    @staticmethod
    def verify_password(password: str, hashed: bytes) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed)

    @staticmethod
    def log_activity(db: DatabaseManager, user_id: str, action: str):
        db.activity_collection.insert_one({
            "user_id": user_id,
            "action": action,
            "timestamp": datetime.utcnow()
        })

class AuthenticationSystem:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.utils = Utils()

    def handle_registration(self):
        st.title("Register")
        
        with st.form("register_form", clear_on_submit=True):
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


            # Password requirements
            if password:
                if len(password) < 8:
                    st.warning("Password must be at least 8 characters long")
                if not any(c.isupper() for c in password):
                    st.warning("Password must contain at least one uppercase letter")
                if not any(c.isdigit() for c in password):
                    st.warning("Password must contain at least one number")

            terms = st.checkbox("I agree to the Terms and Conditions")
            submitted = st.form_submit_button("Register")

            if submitted:
                if not all([first_name, last_name, email, mobile, password, confirm_password]):
                    st.error("All fields are required.")
                elif not self.utils.is_email_valid(email):
                    st.error("Invalid email format.")
                elif not self.utils.is_mobile_valid(mobile):
                    st.error("Invalid mobile number format.")
                elif password != confirm_password:
                    st.error("Passwords do not match.")
                elif not terms:
                    st.error("Please accept the Terms and Conditions.")
                else:
                    try:
                        hashed_password = self.utils.hash_password(password)
                        self.db.users_collection.insert_one({
                            "first_name": first_name,
                            "last_name": last_name,
                            "email": email,
                            "mobile": mobile,
                            "password": hashed_password,
                            "status": "no",
                            "created_at": datetime.utcnow(),
                            "last_login": None
                        })
                        st.success("Registration successful! Please wait for admin approval.")
                        st.session_state.page = "login"
                    except Exception as e:
                        if "duplicate key error" in str(e):
                            st.error("Email or mobile number already registered.")
                        else:
                            logger.error(f"Registration error: {str(e)}")
                            st.error("Registration failed. Please try again.")

    def handle_login(self):
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
                    self.db.users_collection.update_one(
                        {"_id": user['_id']},
                        {"$set": {"last_login": datetime.utcnow()}}
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


        # Improved navigation with tabs
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
        
        # Enhanced filter options
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

        # Display users in a modern card layout
        for _, user in user_df.iterrows():
            with st.container():
                st.markdown("""
                    <style>
                        .user-card {
                            border: 1px solid #e1e4e8;
                            border-radius: 6px;
                            padding: 16px;
                            margin: 8px 0;
                        }
                    </style>
                """, unsafe_allow_html=True)
                
                with st.expander(f"👤 {user['first_name']} {user['last_name']} ({user['email']})"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"📱 Mobile: {user['mobile']}")
                        st.write(f"🔵 Status: {user['status']}")
                        st.write(f"📅 Created: {user['created_at'].strftime('%Y-%m-%d %H:%M')}")
                        st.write(f"🕒 Last Login: {user.get('last_login', 'Never')}")
                    
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
        
        # Fetch user data
        users = list(self.db.users_collection.find())
        df = pd.DataFrame(users)
        
        # Key Metrics
        col1, col2, col3, col4 = st.columns(4)
        total_users = len(users)
        active_users = len([u for u in users if u['status'] == "yes"])
        pending_users = len([u for u in users if u['status'] == "no"])
        admin_users = len([u for u in users if u['status'] == "admin"])
        
        col1.metric("👥 Total Users", total_users)
        col2.metric("✅ Active Users", active_users)
        col3.metric("⏳ Pending", pending_users)
        col4.metric("👑 Admins", admin_users)
        
        # Time-based Analysis
        st.subheader("User Growth Analysis")
        
        df['created_at'] = pd.to_datetime(df['created_at'])
        df['date'] = df['created_at'].dt.date
        
        # Registration Trend
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
        
        # User Status Distribution
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
        
        # Fetch and prepare activity logs
        logs = list(self.db.activity_collection.find().sort("timestamp", -1).limit(100))
        if logs:
            log_df = pd.DataFrame(logs)
            log_df['timestamp'] = pd.to_datetime(log_df['timestamp'])
            
            # Activity Visualization
            # Using scatter plot instead of timeline
            fig = px.scatter(
                log_df,
                x="timestamp",
                y="action",
                title="Recent Activity Visualization",
                color="action",
                size=[10] * len(log_df),  # Constant size for all points
                template="plotly_white"
            )
            
            # Customize the layout
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
            
            # Create a bar chart for activity distribution
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
            styled_df['timestamp'] = styled_df['timestamp'].dt.strftime("%Y-%m-%d %H:%M:%S")
            
            # Enhanced table display
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

    def _show_multiplication_table(self):
        st.subheader("Multiplication Table of 10")
        
        # Create two columns for the main content
        col1, col2 = st.columns([2, 3])
        
        with col1:
            # Numerical representation
            st.markdown("### Numerical Table")
            # Create table data more efficiently using list comprehension
            table_data = [(i, i * 10) for i in range(1, 11)]
            table_df = pd.DataFrame(table_data, columns=['Number', 'Result'])
            
            # Improved dataframe display with better column configuration
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
            
            # Add a fun fact with better styling
            st.info("💡 Fun Fact: Multiplying by 10 is the same as adding a zero to the end of a number!")
        
        with col2:
            # Visual representation with improved styling
            fig = px.bar(
                table_df,
                x='Number',
                y='Result',
                title='Visual Representation of 10\'s Table',
                labels={'Number': 'Multiplier', 'Result': 'Product'},
                text='Result'
            )
            
            # Enhanced chart styling
            fig.update_traces(
                textposition='outside',
                marker_color='rgb(255, 127, 80)',  # Coral color
                marker_line_color='rgb(205, 92, 92)',  # Darker border
                marker_line_width=1.5
            )
            
            fig.update_layout(
                showlegend=False,
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis_gridcolor='rgba(0,0,0,0.1)',
                yaxis_gridcolor='rgba(0,0,0,0.1)',
                title_x=0.5,  # Center the title
                height=400  # Fixed height for better presentation
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Interactive Practice Section with improved layout
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
        
        # Progress bar with better styling and tooltip
        progress_value = number/100
        st.progress(
            progress_value,
            text=f"Progress: {int(progress_value * 100)}%"
        )
    def _show_dashboard(self):
        st.subheader("Your Activity")
        
        # Fetch user's activity logs
        logs = list(self.db.activity_collection.find({"user_id": str(self.user['_id'])}
        ).sort("timestamp", -1))
        
        if logs:
            log_df = pd.DataFrame(logs)
            log_df['timestamp'] = pd.to_datetime(log_df['timestamp'])
            
            # Activity Summary
            col1, col2 = st.columns(2)
            
            with col1:
                # Recent Activity Chart
                activity_counts = log_df['action'].value_counts()
                fig = px.pie(
                    values=activity_counts.values,
                    names=activity_counts.index,
                    title='Your Activity Distribution',
                    color_discrete_sequence=px.colors.qualitative.Set3
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Activity Timeline
                fig = px.scatter(
                    log_df,
                    x='timestamp',
                    y='action',
                    title='Your Activity Timeline',
                    color='action'
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Recent Activity List
            st.subheader("Recent Activities")
            for _, log in log_df.head(5).iterrows():
                st.write(f"🔹 {log['action']} - {log['timestamp'].strftime('%Y-%m-%d %H:%M')}")
        else:
            st.info("No activity recorded yet")

    def _show_profile(self):
        st.subheader("My Profile")
        
        # Profile Information
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
            st.write(f"**Last Login:** {self.user.get('last_login', 'Never')}")
            st.write(f"**Account Created:** {self.user['created_at'].strftime('%Y-%m-%d %H:%M')}")

    def _show_settings(self):
        st.subheader("Settings")
        
        with st.form("settings_form"):
            # Personal Information Section
            st.markdown("### Personal Information")
            col1, col2 = st.columns(2)
            
            with col1:
                first_name = st.text_input("First Name", value=self.user['first_name'])
                email = st.text_input("Email", value=self.user['email'], disabled=True)
                
            with col2:
                last_name = st.text_input("Last Name", value=self.user['last_name'])
                mobile = st.text_input("Mobile", value=self.user['mobile'], disabled=True)
            
            # Password Change Section
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
                        # Update session state
                        updated_user = self.db.users_collection.find_one({"_id": self.user['_id']})
                        st.session_state['user'] = updated_user
                        st.rerun()
                    except Exception as e:
                        logger.error(f"Profile update error: {str(e)}")
                        st.error("Failed to update profile. Please try again.")
                else:
                    st.error("Please enter your current password to save changes.")

def main():
    st.set_page_config(
        page_title="User Authentication System",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS
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
    
    # Initialize session state
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'page' not in st.session_state:
        st.session_state.page = "login"
    
    # Initialize database connection
    db = DatabaseManager(username="abhishelke297127", password="Abhi%402971")
    auth_system = AuthenticationSystem(db)
    
    # Sidebar navigation with improved styling
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
    
    # Main content
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