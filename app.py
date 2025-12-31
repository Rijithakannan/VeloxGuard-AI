import pandas as pd
import streamlit as st
import re
from sklearn.ensemble import RandomForestClassifier

# 1. Page Configuration
st.set_page_config(page_title="VeloxGuard AI", page_icon="🛡️", layout="wide")

# Modern Dark-Theme Design (Fixed the unsafe_allow_html error)
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stButton>button {
        width: 100%; border-radius: 5px; height: 3em;
        background-color: #ff4b4b; color: white; font-weight: bold;
    }
    h1 { color: #ff4b4b; text-align: center; }
    </style>
    """, unsafe_allow_html=True)

# 2. Feature Extraction (Strictly mapped to dataset.csv logic)
def extract_features(url):
    features = []
    
    # Feature 1: IP Address [-1 = IP present, 1 = No IP]
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(-1 if re.search(ip_pattern, url) else 1) 
    
    # Feature 2: URL Length [1: <54 characters, 0: 54-75, -1: >75]
    url_len = len(url)
    if url_len < 54: features.append(1)
    elif 54 <= url_len <= 75: features.append(0)
    else: features.append(-1)
        
    # Feature 3: At Symbol (@) [-1 if present, 1 if not]
    features.append(-1 if "@" in url else 1)
    
    # Feature 4: Sub-domain/Dot Count [1: One dot, 0: Two dots, -1: 3+ dots]
    dot_count = url.count('.')
    if dot_count <= 1: features.append(1)
    elif dot_count == 2: features.append(0)
    else: features.append(-1)
        
    return features

# 3. Model Training (Synchronized with uploaded dataset.csv)
@st.cache_resource
def train_velox_model():
    try:
        # Load your dataset
        df = pd.read_csv("dataset.csv")
        
        # Using the exact column names from your CSV file
        features_to_use = [
            'having_IPhaving_IP_Address', 
            'URLURL_Length', 
            'having_At_Symbol', 
            'having_Sub_Domain'
        ]
        
        X = df[features_to_use]
        y = df['Result'] # Result column: -1 (Safe), 1 (Phishing)
        
        # Training the classifier
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        return model
    except Exception as e:
        st.error(f"Setup Error: {e}")
        return None

# Initializing the model
model = train_velox_model()

# 4. Dashboard Interface
with st.sidebar:
    st.image("https://img.icons8.com/fluency/144/shield.png", width=80)
    st.title("VeloxGuard Control")
    st.write("---")
    st.success("📡 Neural Engine: ONLINE")
    st.info("📂 Source: dataset.csv")
    st.markdown("### Model Diagnostics")
    st.write("- **Algorithm:** Random Forest")
    st.write("- **Dataset:** UCI Repository")

st.markdown("<h1 style='text-align: center; color: #ff4b4b;'>🛡️ VELOXGUARD AI</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #808495;'>Next-Gen Cyber Threat Detection System</p>", unsafe_allow_html=True)

# Main Input Section
url_input = st.text_input("🔗 Enter URL for deep heuristic analysis:", placeholder="https://secure-login.com")

if st.button("EXECUTE SCAN"):
    if model is not None and url_input:
        with st.spinner("Processing feature vectors..."):
            user_features = extract_features(url_input)
            prediction = model.predict([user_features])[0]
            prob = model.predict_proba([user_features])[0]
            
            st.write("---")
            col1, col2 = st.columns(2)
            
            # Result Logic: -1 is Legitimate and 1 is Phishing
            if prediction == -1: 
                col1.metric("Status", "SECURE", delta="Normal")
                st.success("✅ **Legitimate Site.** No malicious patterns found.")
                st.balloons()
            else: 
                col1.metric("Status", "MALICIOUS", delta="-Danger", delta_color="inverse")
                st.error("🚨 **Warning: Phishing Link Detected!**")
                # prob[1] corresponds to the probability of class 1 (Phishing)
                st.info(f"**Threat Probability:** {prob[1]*100:.2f}%")
    elif not url_input:
        st.warning("Please provide a URL to scan.")

st.write("---")
st.caption("© 2025 VeloxGuard | Final Project Presentation Mode")