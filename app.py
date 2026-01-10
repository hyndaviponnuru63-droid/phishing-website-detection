import streamlit as st
import numpy as np
import joblib
from tensorflow.keras.models import load_model

# Load model and scaler
model = load_model("phishing_model.h5")
scaler = joblib.load("scaler.pkl")

st.set_page_config(page_title="Phishing Website Detection", layout="centered")

st.title("Phishing Website Detection")
st.write("Enter URL-based features to check whether a website is **Phishing** or **Legitimate**.")

st.subheader("Input Features")

# Input fields (match your dataset feature order)
url_length = st.number_input("URL Length", min_value=0)
valid_url = st.selectbox("Valid URL (0 = No, 1 = Yes)", [0, 1])
at_symbol = st.selectbox("@ Symbol Present (0 = No, 1 = Yes)", [0, 1])
sensitive_words_count = st.number_input("Sensitive Words Count", min_value=0)
path_length = st.number_input("Path Length", min_value=0)
isHttps = st.selectbox("HTTPS Used (0 = No, 1 = Yes)", [0, 1])
nb_dots = st.number_input("Number of Dots", min_value=0)
nb_hyphens = st.number_input("Number of Hyphens", min_value=0)
nb_and = st.number_input("Number of 'and'", min_value=0)
nb_or = st.number_input("Number of 'or'", min_value=0)
nb_www = st.number_input("Number of 'www'", min_value=0)
nb_com = st.number_input("Number of '.com'", min_value=0)
nb_underscore = st.number_input("Number of underscores", min_value=0)

# Predict button
if st.button("🔍 Predict"):
    features = np.array([[url_length, valid_url, at_symbol, sensitive_words_count,
                          path_length, isHttps, nb_dots, nb_hyphens, nb_and,
                          nb_or, nb_www, nb_com, nb_underscore]])

    features_scaled = scaler.transform(features)
    probability = model.predict(features_scaled)[0][0]
    result = int(probability >= 0.5)

    st.subheader(" Result")
    st.write(f"**Phishing Probability:** {probability:.4f}")

    if result == 1:
        st.error("This website is likely **PHISHING**")
    else:
        st.success("This website is **LEGITIMATE**")
