# Crowdsourced-Problem-Reporting-System
Overview
The Issue Tracking System is a web-based application built using Streamlit and MySQL to help users report, track, and analyze issues efficiently. This system enables user authentication, issue submission, and an analytics dashboard to visualize trends using Plotly and Pandas.

Features
User Authentication (Registration, Login, and Logout)
Secure Password Storage (Bcrypt Hashing)
Issue Submission and Tracking
Status Management (Reported, In Progress, Resolved, Closed)
Issue Analytics Dashboard (Trends, Status Distribution, Issue Volume Over Time)
User Dashboard (View and Manage Reported Issues)
Commenting on Issues
Database Integration with MySQL

Tech Stack
Frontend: Streamlit
Backend: Python
Database: MySQL

Libraries Used:
streamlit
bcrypt
pandas
plotly
mysql.connector

Installation
Prerequisites
Ensure you have the following installed:
Python 3.8+
MySQL Server

Database Schema
The system consists of the following tables:
users (Stores user details and hashed passwords)
issues (Contains reported issues with status updates)
