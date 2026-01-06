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

# 2. Feature Extraction Logic (Corrected to match dataset.csv)
def extract_features(url):
    """
    Values based on UCI Dataset:
    1  = Legitimate/Safe
    0  = Suspicious
    -1 = Phishing/Malicious
    """
    features = []
    
    # Feature 1: IP Address detection
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(-1 if re.search(ip_pattern, url) else 1) 
    
    # Feature 2: URL Length analysis
    url_len = len(url)
    if url_len < 54: features.append(1)
    elif 54 <= url_len <= 75: features.append(0)
    else: features.append(-1)
    
    # Feature 3: @ Symbol detection
    features.append(-1 if "@" in url else 1)
    
    # Feature 4: Sub Domain analysis (Dot count)
    dot_count = url.count('.')
    if dot_count <= 1: features.append(1)
    elif dot_count == 2: features.append(0)
    else: features.append(-1)
    
    return features

# 3. Model Training
@st.cache_resource
def train_velox_model():
    try:
        df = pd.read_csv("dataset.csv")
        # Using core heuristic features from your dataset
        features_to_use = ['having_IPhaving_IP_Address', 'URLURL_Length', 'having_At_Symbol', 'having_Sub_Domain']
        X = df[features_to_use]
        y = df['Result'] 
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        return model
    except Exception as e:
        st.error(f"Setup Error: {e}")
        return None

model = train_velox_model()

# 4. Sidebar Diagnostics
with st.sidebar:
    st.image("https://img.icons8.com/fluency/144/shield.png", width=80)
    st.title("VeloxGuard Control")
    st.write("---")
    st.info("Mode: Direct URL Heuristics")
    st.write("- **Model:** Random Forest")
    st.write("- **Input Features:** 4-Vector Heuristics")

# 5. Main Interface
st.markdown("<h1 style='text-align: center; color: #ff4b4b;'>🛡️ VELOXGUARD AI</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #808495;'>Cloud-Integrated Cyber Threat Detection System</p>", unsafe_allow_html=True)

url_input = st.text_input("🔗 Enter URL for deep heuristic analysis:", placeholder="https://secure-login-verify.net")

if st.button("EXECUTE SCAN"):
    if model is not None and url_input:
        with st.spinner("Analyzing URL patterns..."):
            user_features = extract_features(url_input)
            prediction = model.predict([user_features])[0]
            prob = model.predict_proba([user_features])[0]
            
            st.write("---")
            # --- CORRECTED DETECTION LOGIC ---
            # In your dataset, 1 is SECURE and -1 is MALICIOUS
            if prediction == 1: 
                st.success("✅ **Legitimate Site.** No malicious patterns found.")
                st.metric("Detection Status", "SECURE", delta="Safe")
                st.balloons()
            else: 
                st.error("🚨 **Warning: Phishing Link Detected!**")
                st.metric("Detection Status", "MALICIOUS", delta="-Danger", delta_color="inverse")
                # Class [-1, 1] means prob[0] is the probability of class -1 (Phishing)
                st.info(f"**Threat Confidence Score:** {prob[0]*100:.2f}%")
    elif not url_input:
        st.warning("Please provide a URL to scan.")

st.write("---")
st.caption("© 2026 VeloxGuard | Heuristic Analysis Engine v2.0")
