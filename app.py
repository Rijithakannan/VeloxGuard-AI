import pandas as pd
import streamlit as st
import re
from sklearn.ensemble import RandomForestClassifier

# 1. Page Configuration
st.set_page_config(page_title="VeloxGuard AI", page_icon="🛡️", layout="wide")

# Modern Dark-Theme Design
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
    """
    Values based on dataset.csv:
    1  = Legitimate/Safe
    0  = Suspicious
    -1 = Phishing/Malicious
    """
    features = []
    
    # Feature 1: IP Address (having_IPhaving_IP_Address)
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(-1 if re.search(ip_pattern, url) else 1) 
    
    # Feature 2: URL Length (URLURL_Length)
    url_len = len(url)
    if url_len < 54: features.append(1)
    elif 54 <= url_len <= 75: features.append(0)
    else: features.append(-1)
    
    # Feature 3: @ Symbol (having_At_Symbol)
    features.append(-1 if "@" in url else 1)
    
    # Feature 4: Sub Domain (having_Sub_Domain)
    dot_count = url.count('.')
    if dot_count <= 1: features.append(1)
    elif dot_count == 2: features.append(0)
    else: features.append(-1)
    
    return features

# 3. Model Training
@st.cache_resource
def train_velox_model():
    try:
        # Loading the provided dataset.csv
        df = pd.read_csv("dataset.csv")
        
        # Using specific columns found in the file
        features_to_use = [
            'having_IPhaving_IP_Address', 
            'URLURL_Length', 
            'having_At_Symbol', 
            'having_Sub_Domain'
        ]
        X = df[features_to_use]
        y = df['Result'] 
        
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        return model
    except Exception as e:
        st.error(f"Setup Error: {e}")
        return None

model = train_velox_model()

# 4. Sidebar & Presentation Info
with st.sidebar:
    st.image("https://img.icons8.com/fluency/144/shield.png", width=80)
    st.title("VeloxGuard Control")
    st.write("---")
    st.markdown("### 🚀 Deployment Status")
    st.success("Connected to GitHub")
    st.info("Branch: Main")
    st.write("---")
    st.markdown("### Model Diagnostics")
    st.write("- **Algorithm:** Random Forest")
    st.write("- **Dataset:** UCI Repository (dataset.csv)")

# 5. Main Interface
st.markdown("<h1 style='text-align: center; color: #ff4b4b;'>🛡️ VELOXGUARD AI</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #808495;'>Cloud-Integrated Cyber Threat Detection System</p>", unsafe_allow_html=True)

url_input = st.text_input("🔗 Enter URL for deep heuristic analysis:", placeholder="https://www.google.com")

if st.button("EXECUTE SCAN"):
    if model is not None and url_input:
        with st.spinner("Processing feature vectors..."):
            user_features = extract_features(url_input)
            prediction = model.predict([user_features])[0]
            prob = model.predict_proba([user_features])[0]
            
            st.write("---")
            col1, col2 = st.columns(2)
            
            # --- FIXED DETECTION LOGIC ---
            # Based on dataset.csv labels: 1 = Legitimate (SECURE), -1 = Phishing (MALICIOUS)
            if prediction == 1: 
                col1.metric("Status", "SECURE", delta="Normal")
                st.success("✅ **Legitimate Site.** No malicious patterns found.")
                st.balloons()
            else: 
                col1.metric("Status", "MALICIOUS", delta="-Danger", delta_color="inverse")
                st.error("🚨 **Warning: Phishing Link Detected!**")
                # Since classes are [-1, 1], index 0 is Phishing (-1) and index 1 is Legitimate (1)
                st.info(f"**Threat Probability:** {prob[0]*100:.2f}%")
    elif not url_input:
        st.warning("Please provide a URL to scan.")

st.write("---")
st.caption("© 2025 VeloxGuard | Project Presentation Mode | GitHub Sync Enabled")
