import streamlit as st
import mysql.connector
import bcrypt
from datetime import datetime
import plotly.express as px
import pandas as pd
import re

# Validate email format
def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

# Validate password strength
def is_valid_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

# Check if email already exists
def email_exists(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE Email=%s", (email,))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="1234#u",
        database="problem_reporting"
    )
conn = get_db_connection()
cursor = conn.cursor()

cursor.execute("SELECT Users_Id, Password FROM users")
users = cursor.fetchall()

for user_id, password in users:
    if not password.startswith("$2b$"):  # Only rehash if it's not already bcrypt
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("UPDATE users SET Password=%s WHERE Users_Id=%s", (hashed_password, user_id))

conn.commit()
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(input_password, stored_password):
    return bcrypt.checkpw(input_password.encode(), stored_password.encode() if isinstance(stored_password, str) else stored_password)


st.set_page_config(page_title="Issue Tracking System", page_icon="📌", layout="wide")
st.markdown(
    """
    <style>
    .big-font { font-size:30px !important; font-weight: bold; color: #2E86C1;}
    .stButton>button { background-color: #2E86C1; color: white; font-size: 18px; border-radius: 10px;}
    </style>
    """,
    unsafe_allow_html=True
)
def create_dashboard_metrics(issues):
    total_issues = len(issues)
    reported = len([i for i in issues if i['Status'] == 'reported'])
    in_process = len([i for i in issues if i['Status'] == 'in-process'])
    resolved = len([i for i in issues if i['Status'] == 'resolved'])
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Issues", total_issues)
    with col2:
        st.metric("Reported", reported, delta=f"{reported/total_issues*100:.1f}%" if total_issues else "0%")
    with col3:
        st.metric("In Process", in_process, delta=f"{in_process/total_issues*100:.1f}%" if total_issues else "0%")
    with col4:
        st.metric("Resolved", resolved, delta=f"{resolved/total_issues*100:.1f}%" if total_issues else "0%")

def create_issue_trends(issues):
    df = pd.DataFrame(issues)
    df['Reported_at'] = pd.to_datetime(df['Reported_at'])
    df['Date'] = df['Reported_at'].dt.date
    daily_issues = df.groupby('Date').size().reset_index(name='count')
    
    fig = px.line(daily_issues, x='Date', y='count', 
                  title='Daily Issue Trends',
                  labels={'count': 'Number of Issues', 'Date': 'Date'})
    st.plotly_chart(fig)

# User Authentication
def authenticate_user(identifier, password):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE Users_Id=%s OR Email=%s", (identifier, identifier))
    user = cursor.fetchone()
    conn.close()
    if user and verify_password(password, user["Password"]):
        return user
    return None

# Admin Authentication
def authenticate_admin(identifier, password):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE (Users_Id=%s OR Email=%s) AND Role='admin'", (identifier, identifier))
    admin = cursor.fetchone()
    conn.close()
    if admin and verify_password(password, admin["Password"]):
        return admin
    return None

# User Sign Up
def create_user(name, email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password).decode('utf-8')  # Decode before storing
    cursor.execute("INSERT INTO users (Name, Email, Password, Role) VALUES (%s, %s, %s, 'citizen')", 
                   (name, email, hashed_password))
    conn.commit()
    conn.close()


# Admin Sign Up
def create_admin(name, email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password).decode('utf-8')  # Decode before storing
    cursor.execute("INSERT INTO users (Name, Email, Password, Role) VALUES (%s, %s, %s, 'admin')", 
                   (name, email, hashed_password))
    conn.commit()
    conn.close()


# Logout Function
def logout():
    st.session_state.clear()
    st.rerun()

# Modified User Dashboard
def user_dashboard():
    user = st.session_state.user
    
    with st.sidebar:
        st.image("logo.png", width=100)
        st.markdown("<h1 class='big-font'>Welcome, {}!</h1>".format(user['Name']), unsafe_allow_html=True)
        
        # Add profile section
        with st.expander("📋 Your Profile"):
            st.write(f"**User ID:** {user['Users_Id']}")
            st.write(f"**Email:** {user['Email']}")
            st.write(f"**Role:** {user['Role']}")
        
        if st.button("Logout", key="sidebar_logout"):
            logout()
    
    st.title("Issue Tracking Dashboard")
    
    # Fetch user's issues
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM issues WHERE Users_Id=%s", (user['Users_Id'],))
    issues = cursor.fetchall()
    conn.close()
    
    # Add metrics at the top
    create_dashboard_metrics(issues)
    
    # Add tabs for different views
    tab1, tab2, tab3 = st.tabs(["📝 Report Issue", "📊 Your Issues", "📈 Analytics"])
    
    with tab1:
        st.write("### Report a New Issue")
        with st.form("issue_form"):
            category = st.selectbox("Issue Category", 
                                  ["Infrastructure", "Public Safety", "Environmental", "Other"])
            description = st.text_area("Issue Description")
            location = st.text_input("Location")
            priority = st.select_slider("Priority", options=["Low", "Medium", "High"])
            
            submitted = st.form_submit_button("Submit Issue")
        
        if submitted:
            if description and location:
                conn = get_db_connection()
                cursor = conn.cursor()
                reported_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute("""
                    INSERT INTO issues 
                    (Users_Id, Issue_Description, location, Status, Reported_at) 
                    VALUES (%s, %s, %s, 'reported', %s)
                """, (user['Users_Id'], description, location, reported_at))
                conn.commit()
                conn.close()
                st.success("Issue reported successfully!")
                st.balloons()
                st.rerun()
            else:
                st.error("Please fill in all required fields.")
    
    with tab2:
        st.write("### Your Issues")
        status_filter = st.multiselect("Filter by Status", 
                                     ["reported", "in-process", "resolved"],
                                     default=["reported", "in-process", "resolved"])
        
        filtered_issues = [issue for issue in issues if issue['Status'] in status_filter]
        
        for issue in filtered_issues:
            with st.expander(f"Issue #{issue['issues_Id']} - {issue['location']}"):
                status_color = {
                    "reported": "🟡",
                    "in-process": "🟠",
                    "resolved": "✅"
                }
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.write(f"{status_color[issue['Status']]} **Status:** {issue['Status'].title()}")
                    st.write(f"**Reported At:** {issue['Reported_at']}")
                    st.write(f"**Location:** {issue['location']}")
                    st.write(f"**Description:** {issue['Issue_Description']}")
                
                
                # Add comment section
                with st.form(f"comment_form_{issue['issues_Id']}"):
                    comment = st.text_area("Add a comment")
                    if st.form_submit_button("Submit Comment"):
                        # Add comment logic here
                        st.success("Comment added successfully!")
    with tab3:
        st.write("### Your Issue Analytics")
        
        # Convert issues to DataFrame for easier analysis
        df = pd.DataFrame(issues)
        if not df.empty:
            df['Reported_at'] = pd.to_datetime(df['Reported_at'])
            df['Month'] = df['Reported_at'].dt.strftime('%B %Y')
            
            # Create two columns for the first row of charts
            col1, col2 = st.columns(2)
            
            with col1:
                # Status Distribution Pie Chart
                status_counts = df['Status'].value_counts()
                fig_status = px.pie(
                    values=status_counts.values,
                    names=status_counts.index,
                    title='Your Issues by Status',
                    color_discrete_map={
                        'reported': '#FFD700',    # Yellow
                        'in-process': '#FFA500',  # Orange
                        'resolved': '#32CD32'     # Green
                    }
                )
                st.plotly_chart(fig_status, use_container_width=True)
            
            
            
        else:
            st.info("No issues reported yet. Start reporting issues to see your analytics!")            


# Modified Admin Dashboard
def admin_dashboard():
    admin = st.session_state.admin
    
    with st.sidebar:
        st.image("admin.png", width=100)
        st.markdown("<h1 class='big-font'>Welcome, {}!</h1>".format(admin['Name']), unsafe_allow_html=True)
        
        # Add admin controls
        with st.expander("🔧 Admin Controls"):
            if st.button("Export Data"):
                # Add export functionality
                st.download_button(
                    label="Download CSV",
                    data="Your data here",  # Replace with actual data
                    file_name="issues_export.csv",
                    mime="text/csv"
                )
        
        if st.button("Logout", key="sidebar_logout"):
            logout()
    
    st.title("Admin Dashboard")
    
    # Fetch all issues
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM issues")
    issues = cursor.fetchall()
    conn.close()
    
    # Add metrics at the top
    create_dashboard_metrics(issues)
    
    # Add tabs for different views
    tab1, tab2 = st.tabs(["📋 Issues Overview", "📊 Analytics"])
    
    with tab1:
        # Add filter options
        col1, col2 = st.columns(2)
        with col1:
            status_filter = st.multiselect("Filter by Status",
                                         ["reported", "in-process", "resolved"],
                                         default=["reported", "in-process", "resolved"])
        with col2:
            search = st.text_input("Search by Location or Description")
        
        filtered_issues = [
            issue for issue in issues 
            if issue['Status'] in status_filter
            and (search.lower() in issue['location'].lower() 
                 or search.lower() in issue['Issue_Description'].lower()
                 or not search)
        ]
        
        for issue in filtered_issues:
            with st.expander(f"Issue #{issue['issues_Id']} - {issue['location']}"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    status_map = {
                        "reported": "🟡 Reported",
                        "in-process": "🟠 In-Process",
                        "resolved": "✅ Resolved"
                    }
                    st.write(f"**Status:** {status_map[issue['Status']]}")
                    st.write(f"**User ID:** {issue['Users_Id']}")
                    st.write(f"**Location:** {issue['location']}")
                    st.write(f"**Description:** {issue['Issue_Description']}")
                    st.write(f"**Reported At:** {issue['Reported_at']}")
                
                with col2:
                    if issue['Status'] == 'reported':
                        if st.button("Mark In-Process", key=f"process_{issue['issues_Id']}"):
                            update_status(issue['issues_Id'], 'in-process')
                            st.success("Status updated!")
                            st.rerun()
                    elif issue['Status'] == 'in-process':
                        if st.button("Mark Resolved", key=f"resolve_{issue['issues_Id']}"):
                            update_status(issue['issues_Id'], 'resolved')
                            st.success("Status updated!")
                            st.rerun()
    
    with tab2:
        st.write("### Analytics")
        create_issue_trends(issues)
        
        col1, col2 = st.columns(2)
        with col1:
            # Status distribution
            status_counts = pd.DataFrame(issues)['Status'].value_counts()
            fig = px.pie(values=status_counts.values,
                        names=status_counts.index,
                        title='Issue Status Distribution')
            st.plotly_chart(fig)
        
        with col2:
            # Location-based analysis
            location_counts = pd.DataFrame(issues)['location'].value_counts().head(10)
            fig = px.bar(x=location_counts.index,
                        y=location_counts.values,
                        title='Top 10 Issue Locations')
            st.plotly_chart(fig)
    
    

# New helper function for updating issue status
def update_status(issue_id, status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE issues SET Status=%s WHERE issues_Id=%s", (status, issue_id))
    conn.commit()
    conn.close()
    st.rerun()

def main():
    # Add custom CSS
    st.markdown(
        """
        <style>
        .big-font { font-size:24px !important; font-weight: bold; color: #2E86C1;}
        .stButton>button { background-color: #2E86C1; color: white; font-size: 16px; border-radius: 5px;}
        section[data-testid="stSidebar"] {
            background-color: #f0f2f6;
            padding: 2rem 1rem;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
    
    if "user" in st.session_state:
        user_dashboard()
    elif "admin" in st.session_state:
        admin_dashboard()
    else:
        with st.sidebar:
            st.image("issue-tracker-logo.svg", width=100)
            st.title("Login")
            menu = ["User Login", "Admin Login", "User Sign Up", "Admin Sign Up"]
            choice = st.selectbox("Menu", menu)
        st.title("Crowdsourced Problem Reporting System")
        if choice == "User Login":
            with st.container():
                identifier = st.text_input("User ID or Email")
                password = st.text_input("Password", type="password")
                if st.button("Login"):
                    user = authenticate_user(identifier, password)
                    if user:
                        st.session_state.user = user
                        st.rerun()
                    else:
                        st.error("Invalid credentials")
        elif choice == "Admin Login":
            with st.container():
                identifier = st.text_input("Admin ID or Email")
                password = st.text_input("Password", type="password")
                if st.button("Login"):
                    admin = authenticate_admin(identifier, password)
                    if admin:
                        st.session_state.admin = admin
                        st.rerun()
                    else:
                        st.error("Invalid credentials")
        elif choice == "User Sign Up":
            with st.container():
                st.subheader("New User Registration")
                with st.form("user_registration_form", clear_on_submit=True):
                    name = st.text_input("Full Name")
                    email = st.text_input("Email")
                    password = st.text_input("Password", type="password")
                    confirm_password = st.text_input("Confirm Password", type="password")
                    submitted = st.form_submit_button("Register")
                    
                    if submitted:
                        if not name or not email or not password:
                            st.error("Please fill in all fields")
                        elif not is_valid_email(email):
                            st.error("Please enter a valid email address")
                        elif email_exists(email):
                            st.error("Email already registered")
                        elif password != confirm_password:
                            st.error("Passwords do not match")
                        else:
                            is_valid, msg = is_valid_password(password)
                            if not is_valid:
                                st.error(msg)
                            else:
                                try:
                                    create_user(name, email, password)
                                    st.success("Registration successful! Please login.")
                                    st.balloons()
                                except Exception as e:
                                    st.error(f"An error occurred: {str(e)}")

        elif choice == "Admin Sign Up":
            with st.container():
                st.subheader("New Admin Registration")
                with st.form("admin_registration_form", clear_on_submit=True):
                    name = st.text_input("Full Name")
                    email = st.text_input("Email")
                    password = st.text_input("Password", type="password")
                    confirm_password = st.text_input("Confirm Password", type="password")
                    submitted = st.form_submit_button("Register")
                    
                    if submitted:
                        if not name or not email or not password:
                            st.error("Please fill in all fields")
                        elif not is_valid_email(email):
                            st.error("Please enter a valid email address")
                        elif email_exists(email):
                            st.error("Email already registered")
                        elif password != confirm_password:
                            st.error("Passwords do not match")
                        else:
                            is_valid, msg = is_valid_password(password)
                            if not is_valid:
                                st.error(msg)
                            else:
                                try:
                                    create_admin(name, email, password)
                                    st.success("Admin registration successful! Please login.")
                                    st.balloons()
                                except Exception as e:
                                    st.error(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    main()

