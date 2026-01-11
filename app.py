import streamlit as st
import numpy as np
import joblib
import os
import requests
from urllib.parse import urlparse
from tensorflow.keras.models import load_model

# --------------------------------------------------
# Load model and scaler (robust path handling)
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model = load_model(os.path.join(BASE_DIR, "phishing_model.h5"))
scaler = joblib.load(os.path.join(BASE_DIR, "scaler.pkl"))

# --------------------------------------------------
# Feature extraction function
# --------------------------------------------------
def extract_features(url):
    # URL length
    url_length = len(url)

    # Valid URL (check reachability)
    try:
        response = requests.get(url, timeout=3)
        valid_url = 1 if response.status_code == 200 else 0
    except:
        valid_url = 0

    # @ symbol
    at_symbol = 1 if "@" in url else 0

    # Sensitive words
    sensitive_words = ["login", "verify", "bank", "secure", "account", "update"]
    sensitive_words_count = sum(word in url.lower() for word in sensitive_words)

    # Parse URL
    parsed = urlparse(url)

    # Path length
    path_length = len(parsed.path)

    # HTTPS usage
    isHttps = 1 if parsed.scheme == "https" else 0

    # Character counts
    nb_dots = url.count(".")
    nb_hyphens = url.count("-")
    nb_and = url.lower().count("and")
    nb_or = url.lower().count("or")
    nb_www = url.lower().count("www")
    nb_com = url.lower().count(".com")
    nb_underscore = url.count("_")

    return [
        url_length,
        valid_url,
        at_symbol,
        sensitive_words_count,
        path_length,
        isHttps,
        nb_dots,
        nb_hyphens,
        nb_and,
        nb_or,
        nb_www,
        nb_com,
        nb_underscore
    ]

# --------------------------------------------------
# Streamlit UI
# --------------------------------------------------
st.set_page_config(page_title="Phishing Website Detection", layout="centered")

st.title(" Phishing Website Detection")
st.write(
    "Paste a website URL below. The system will **automatically extract features**, "
    "predict phishing probability, and **explain the decision**."
)

st.subheader("Enter Website URL")
url_input = st.text_input("Example: https://secure-login-paypal-update.com/verify")

# --------------------------------------------------
# Prediction
# --------------------------------------------------
if st.button("Predict"):
    if not url_input.strip():
        st.warning("Please enter a valid URL.")
    else:
        # Extract features
        features = extract_features(url_input)
        features_array = np.array([features])
        features_scaled = scaler.transform(features_array)

        # Model prediction
        probability = model.predict(features_scaled)[0][0]
        result = int(probability >= 0.5)

        # --------------------------------------------------
        # Display result
        # --------------------------------------------------
        st.subheader("📊 Prediction Result")
        st.write(f"**Phishing Probability:** {probability:.4f}")

        if result == 1:
            st.error("This website is likely **PHISHING**")
        else:
            st.success("This website is **LEGITIMATE**")

        # --------------------------------------------------
        # Simple Explainability
        # --------------------------------------------------
        st.subheader("🧠 Explanation (Why this result?)")
        reasons = []

        if features[2] == 1:
            reasons.append("URL contains '@' symbol")
        if features[5] == 0:
            reasons.append("Website does not use HTTPS")
        if features[3] > 0:
            reasons.append("Contains sensitive words like login/bank/verify")
        if features[1] == 0:
            reasons.append("URL is not reachable")
        if features[6] > 4:
            reasons.append("Too many dots in the URL")
        if features[7] > 2:
            reasons.append("Multiple hyphens in the URL")

        if reasons:
            for reason in reasons:
                st.write("•", reason)
        else:
            st.write("• No strong suspicious patterns detected")
