import streamlit as st



with st.form("signup_form"):
    st.write("Signup")
    firstname = st.text_input
    lastname = st.text_input
    email = st.text_input
    st.form_submit_button
    
with st.form("set_password_form"):
    st.write("Set your password")
    password = st.text_input
    confirm_password = st.text_input
    st.form_submit_button
    
    
with st.form("login_form"):
    st.write('Login')
    username_or_email = st.text_input("Usernamer")
    password = st.text_input("Password")
    st.form_submit_button