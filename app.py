import streamlit as st
import numpy as np
import joblib
import os
from urllib.parse import urlparse
from tensorflow.keras.models import load_model

# --------------------------------------------------
# Load model and scaler
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model = load_model(os.path.join(BASE_DIR, "phishing_model.h5"))
scaler = joblib.load(os.path.join(BASE_DIR, "scaler.pkl"))

# --------------------------------------------------
# Trusted domains (whitelist)
# --------------------------------------------------
TRUSTED_DOMAINS = [
    "google.com",
    "amazon.com",
    "wikipedia.org",
    "github.com",
    "streamlit.io",
    "microsoft.com",
    "apple.com",
    "linkedin.com"
]

# --------------------------------------------------
# Risk level function (STEP 1)
# --------------------------------------------------
def get_risk_level(prob):
    if prob < 0.3:
        return "LOW RISK"
    elif prob < 0.6:
        return "MEDIUM RISK"
    else:
        return "HIGH RISK"

# --------------------------------------------------
# Feature extraction function
# --------------------------------------------------
def extract_features(url):
    url_length = len(url)
    valid_url = 1 if url.startswith("http") else 0
    at_symbol = 1 if "@" in url else 0

    sensitive_words = ["login", "verify", "bank", "secure", "account", "update"]
    sensitive_words_count = sum(url.lower().count(w) for w in sensitive_words)

    parsed = urlparse(url)
    path_length = len(parsed.path)
    isHttps = 1 if parsed.scheme == "https" else 0

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

st.title("🔐 Phishing Website Detection")
st.write(
    "Paste a website URL below. The system estimates **phishing risk** "
    "using machine learning and explainable rules."
)

st.subheader("🌐 Enter Website URL")
url_input = st.text_input("Example: https://secure-login-paypal-update.com/verify")

# --------------------------------------------------
# Prediction
# --------------------------------------------------
if st.button("Predict"):
    if not url_input.strip():
        st.warning("Please enter a valid URL.")
    else:
        parsed = urlparse(url_input)
        domain = parsed.netloc.lower()

        # -------------------------------
        # TRUSTED DOMAIN WHITELIST
        # -------------------------------
        if any(td in domain for td in TRUSTED_DOMAINS):
            st.info("🛡️ Decision Path: Trusted-domain whitelist")

            st.subheader("📊 Prediction Result")
            st.success("✅ Low Risk: Trusted domain detected")

            st.subheader("🧠 Explanation")
            st.write("• Domain belongs to a globally trusted platform")
            st.write("• Whitelist-based safety check applied")

            st.stop()

        # -------------------------------
        # ML-BASED ANALYSIS
        # -------------------------------
        st.info("🔍 Decision Path: Machine Learning–based risk estimation")

        features = extract_features(url_input)
        features_array = np.array([features])
        features_scaled = scaler.transform(features_array)

        probability = model.predict(features_scaled)[0][0]

        # STEP 2: Risk level
        risk = get_risk_level(probability)

        # -------------------------------
        # Display result (STEP 3)
        # -------------------------------
        st.subheader("📊 Prediction Result")
        st.write(f"**Phishing Probability:** {probability:.4f}")
        st.write(f"**Risk Level:** {risk}")

        if risk == "HIGH RISK":
            st.error("🚨 High Risk: This website is potentially phishing")
        elif risk == "MEDIUM RISK":
            st.warning("⚠️ Medium Risk: This website requires caution")
        else:
            st.success("✅ Low Risk: This website appears safe")

        # -------------------------------
        # Explainability
        # -------------------------------
        st.subheader("🧠 Explanation (Why this result?)")
        reasons = []

        if features[2] == 1:
            reasons.append("URL contains '@' symbol")
        if features[5] == 0:
            reasons.append("Website does not use HTTPS")
        if features[3] > 0:
            reasons.append("Contains sensitive words")
        if features[6] > 4:
            reasons.append("Too many dots in the URL")
        if features[7] > 2:
            reasons.append("Multiple hyphens in the URL")

        if reasons:
            for r in reasons:
                st.write("•", r)
        else:
            st.write("• No strong suspicious patterns detected")
