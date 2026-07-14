import streamlit as st
from utils.api_client import api_client
from components.customer_portal import render_customer_portal
from components.analyst_portal import render_analyst_portal

# Premium Styling Override
st.set_page_config(
    page_title="FraudLens - Payment Security Portal",
    page_icon="security",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Sleek Theme Styles (only button adjustments, native theme handles contrast)
st.markdown("""
<style>
    /* Form & Button Overrides */
    div.stButton > button {
        background-color: #1e293b;
        color: white;
        border-radius: 8px;
        border: none;
        padding: 0.5rem 1rem;
        font-weight: 600;
        transition: all 0.2s ease;
    }
    div.stButton > button:hover {
        background-color: #334155;
        border: none;
        box-shadow: 0px 4px 10px rgba(0,0,0,0.1);
    }
</style>
""", unsafe_allow_html=True)

# Session State Initialization
if "token" not in st.session_state:
    st.session_state.token = None
if "role" not in st.session_state:
    st.session_state.role = None
if "user_profile" not in st.session_state:
    st.session_state.user_profile = {}
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "login"

# Sidebar Navigation Control
if st.session_state.token:
    st.sidebar.markdown("### FraudLens Core")
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Logged In As**:\n{st.session_state.user_profile.get('name')}")
    st.sidebar.markdown(f"**Role**: `{st.session_state.role.upper()}`")
    st.sidebar.markdown(f"**Email**: {st.session_state.user_profile.get('email')}")
    st.sidebar.markdown("---")
    
    # Logout action
    if st.sidebar.button("Logout Session", use_container_width=True):
        st.session_state.token = None
        st.session_state.role = None
        st.session_state.user_profile = {}
        st.session_state.auth_mode = "login"
        st.toast("Logged out successfully.")
        st.rerun()

# Main Application Core
if not st.session_state.token:
    st.title("FraudLens Platform")
    st.markdown("##### Real-Time AI Fraud Detection & Network Graph Analysis Gateway")
    st.markdown("---")
    
    col_l, col_r = st.columns([1.2, 1])
    
    with col_l:
        # Innovative Catchy Explainer Section (Emojis removed)
        st.markdown("""
        <div style="
            background: rgba(30, 41, 59, 0.75);
            border: 1px solid rgba(255, 255, 255, 0.08);
            padding: 1.75rem;
            border-radius: 16px;
            margin-top: 1.5rem;
            margin-bottom: 2.25rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        ">
            <h3 style="color: #38bdf8; font-family: 'Inter', sans-serif; font-weight: 700; margin-top: 0; margin-bottom: 0.75rem;">
                Your Smart Payment Guardian
            </h3>
            <p style="color: #94a3b8; font-family: 'Inter', sans-serif; font-size: 0.95rem; line-height: 1.6; margin-bottom: 1.25rem;">
                Welcome to <strong>FraudLens</strong>—a state-of-the-art payment screening platform. 
                We secure every transaction using real-time intelligent analysis:
            </p>
            <div style="display: grid; grid-template-columns: 1fr; gap: 1rem; color: #cbd5e1; font-family: 'Inter', sans-serif; font-size: 0.9rem;">
                <div style="display: flex; align-items: flex-start; gap: 8px;">
                    <span style="color: #38bdf8; font-weight: bold; font-size: 1.1rem; line-height: 1;">&bull;</span>
                    <span><strong>Real-time screening</strong> checks transactions in milliseconds.</span>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 8px;">
                    <span style="color: #38bdf8; font-weight: bold; font-size: 1.1rem; line-height: 1;">&bull;</span>
                    <span><strong>AI Risk Engine</strong> detects user behavior anomalies.</span>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 8px;">
                    <span style="color: #38bdf8; font-weight: bold; font-size: 1.1rem; line-height: 1;">&bull;</span>
                    <span><strong>Network Graphs</strong> trace connection link threats.</span>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 8px;">
                    <span style="color: #38bdf8; font-weight: bold; font-size: 1.1rem; line-height: 1;">&bull;</span>
                    <span><strong>Secure Portal</strong> keeps accounts safe.</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with col_r:
        if st.session_state.auth_mode == "login":
            st.subheader("Login Gateway")
            login_user = st.text_input("Email / Username", value="customer@fraudlens.com")
            login_pass = st.text_input("Password", type="password", value="password123")
            
            col_b1, col_b2 = st.columns(2)
            with col_b1:
                if st.button("Login", use_container_width=True):
                    try:
                        with st.spinner("Authorizing..."):
                            auth_res = api_client.login(login_user, login_pass)
                            
                        st.session_state.token = auth_res["access_token"]
                        # Fetch profile to retrieve role and user attributes
                        profile = api_client.get_profile(st.session_state.token)
                        st.session_state.role = profile["role"]
                        st.session_state.user_profile = profile
                        
                        st.success(f"Success! Logged in as {profile['name']}.")
                        st.rerun()
                    except Exception as e:
                        st.error("Invalid credentials or database connection failed.")
            
            with col_b2:
                if st.button("Switch to Sign Up", use_container_width=True):
                    st.session_state.auth_mode = "signup"
                    st.rerun()
                    
        else:
            st.subheader("Create Credentials")
            reg_name = st.text_input("Full Name")
            reg_email = st.text_input("Email Address")
            reg_pass = st.text_input("Password", type="password")
            reg_role = st.selectbox("Role", ["customer", "analyst"])
            
            col_b1, col_b2 = st.columns(2)
            with col_b1:
                if st.button("Register & Create Account", use_container_width=True):
                    if not reg_name or not reg_email or not reg_pass:
                        st.error("Please fill in all registration parameters.")
                    else:
                        try:
                            with st.spinner("Creating account..."):
                                api_client.register(reg_name, reg_email, reg_pass, reg_role)
                            st.success("Registration completed successfully! Switching to Login.")
                            st.session_state.auth_mode = "login"
                            st.rerun()
                        except Exception as e:
                            st.error(f"Registration failed: {e}")
            with col_b2:
                if st.button("Back to Login", use_container_width=True):
                    st.session_state.auth_mode = "login"
                    st.rerun()

else:
    # Route based on role
    if st.session_state.role == "analyst":
        render_analyst_portal(st.session_state.token, st.session_state.user_profile)
    else:
        render_customer_portal(st.session_state.token, st.session_state.user_profile)
