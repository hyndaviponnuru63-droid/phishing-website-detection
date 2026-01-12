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
    "google.com", "youtube.com", "amazon.com", "wikipedia.org",
    "github.com", "streamlit.io", "microsoft.com",
    "apple.com", "linkedin.com"
]

# --------------------------------------------------
# Known platform domains
# --------------------------------------------------
PLATFORM_DOMAINS = [
    "youtube.com", "github.com", "twitter.com",
    "facebook.com", "instagram.com", "netflix.com"
]

# --------------------------------------------------
# FUTURE SCOPE FEATURE 1: Simulated Blacklist (PhishTank-like)
# --------------------------------------------------
LOCAL_PHISHING_BLACKLIST = [
    "secure-login-paypal-update.com",
    "bank-verification-alert-login.com",
    "account-security-check-now.com"
]

# --------------------------------------------------
# FUTURE SCOPE FEATURE 2: Simulated Domain Age Check (WHOIS-like)
# --------------------------------------------------
def is_new_domain(domain):
    """
    Simulated domain age check.
    In real systems, WHOIS APIs would be used.
    """
    suspicious_keywords = ["secure", "login", "verify", "update"]
    return any(k in domain for k in suspicious_keywords)

# --------------------------------------------------
# Risk level function (Binary for campus)
# --------------------------------------------------
def get_risk_level(prob):
    return "HIGH RISK" if prob >= 0.5 else "LOW RISK"

# --------------------------------------------------
# Feature extraction
# --------------------------------------------------
def extract_features(url):
    parsed = urlparse(url)

    url_length = len(url)
    valid_url = 1 if url.startswith("http") else 0
    at_symbol = 1 if "@" in url else 0

    sensitive_words = ["login", "verify", "bank", "secure", "account", "update"]
    sensitive_words_count = sum(url.lower().count(w) for w in sensitive_words)

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
        url_length, valid_url, at_symbol, sensitive_words_count,
        path_length, isHttps, nb_dots, nb_hyphens,
        nb_and, nb_or, nb_www, nb_com, nb_underscore
    ]

# --------------------------------------------------
# Streamlit UI
# --------------------------------------------------
st.set_page_config(page_title="Phishing Website Detection", layout="centered")
st.title("🔐 Phishing Website Detection")

st.write(
    "This application detects phishing websites using **machine learning**, "
    "along with **simulated real-time security checks**."
)

url_input = st.text_input("Enter Website URL")

# --------------------------------------------------
# Prediction
# --------------------------------------------------
if st.button("Predict"):
    if not url_input.strip():
        st.warning("Please enter a valid URL.")
    else:
        parsed = urlparse(url_input)
        domain = parsed.netloc.lower()

        # --------------------------------------------------
        # Layer 0: Local Blacklist Check (Future Scope)
        # --------------------------------------------------
        if any(bad in domain for bad in LOCAL_PHISHING_BLACKLIST):
            st.error("🚫 HIGH RISK – URL found in phishing blacklist")
            st.info("Decision Path: Local phishing blacklist (Future Scope)")
            st.stop()

        # --------------------------------------------------
        # Layer 1: Trusted-domain whitelist
        # --------------------------------------------------
        if any(td in domain for td in TRUSTED_DOMAINS):
            st.success("✅ LOW RISK – Trusted domain detected")
            st.info("Decision Path: Trusted-domain whitelist")
            st.stop()

        # --------------------------------------------------
        # Layer 2: Platform-domain detection
        # --------------------------------------------------
        if any(p in domain for p in PLATFORM_DOMAINS):
            st.success("✅ LOW RISK – Known platform domain")
            st.info("Decision Path: Platform-domain heuristic")
            st.stop()

        # --------------------------------------------------
        # Layer 2.5: Simulated Domain Age Check (Future Scope)
        # --------------------------------------------------
        if is_new_domain(domain):
            st.warning("⚠️ Domain appears newly registered (simulated check)")
            st.info("Future Scope: WHOIS-based domain age verification")

        # --------------------------------------------------
        # Layer 3: ML-based analysis
        # --------------------------------------------------
        st.info("Decision Path: Machine Learning–based analysis")

        features = extract_features(url_input)
        features_scaled = scaler.transform([features])

        probability = model.predict(features_scaled)[0][0]
        risk = get_risk_level(probability)

        st.subheader("Prediction Result")
        st.write(f"Phishing Probability: {probability:.4f}")

        if risk == "HIGH RISK":
            st.error("🚨 HIGH RISK – This website is potentially phishing")
        else:
            st.success("✅ LOW RISK – This website appears safe")

        # --------------------------------------------------
        # Explainability
        # --------------------------------------------------
        st.subheader("Why this result?")
        reasons = []

        if features[2]:
            reasons.append("Contains '@' symbol")
        if features[5] == 0:
            reasons.append("Does not use HTTPS")
        if features[3] > 0:
            reasons.append("Contains sensitive keywords")
        if features[6] > 4:
            reasons.append("Too many dots in URL")
        if features[7] > 2:
            reasons.append("Multiple hyphens detected")

        if reasons:
            for r in reasons:
                st.write("•", r)
        else:
            st.write("• No strong suspicious patterns detected")
