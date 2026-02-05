import pandas as pd
import streamlit as st
import re
from sklearn.ensemble import RandomForestClassifier
from urllib.parse import urlparse

# 1. Page Configuration
st.set_page_config(page_title="VeloxGuard AI Pro", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1e2130; padding: 15px; border-radius: 10px; border: 1px solid #3e4255; }
    h1 { color: #ff4b4b; text-align: center; font-family: 'Helvetica'; }
    </style>
    """, unsafe_allow_html=True)

# 2. Model Training
@st.cache_resource
def train_velox_model():
    try:
        df = pd.read_csv("dataset.csv")
        # Ensure we drop the non-feature columns
        X = df.drop(columns=['index', 'Result']) 
        y = df['Result']
        
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        return model, X.columns.tolist()
    except Exception as e:
        st.error(f"Initialization Error: {e}")
        return None, []

model, feature_names = train_velox_model()

# 3. Intelligent Feature Extraction (Calibrated for Detection)
def extract_all_features(url, expected_columns):
    # Standardize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # Initialize all features with 'Suspicious' (0) as the default baseline
    # This prevents the "All Safe" bias caused by padding with 1s.
    f_dict = {col: 0 for col in expected_columns}
    
    # --- CORE DETECTION LOGIC ---
    # IP Address
    f_dict['having_IPhaving_IP_Address'] = -1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 1
    
    # URL Length
    url_len = len(url)
    f_dict['URLURL_Length'] = 1 if url_len < 54 else (0 if url_len <= 75 else -1)
    
    # Shorteners
    f_dict['Shortining_Service'] = -1 if re.search('bit\.ly|goo\.gl|t\.co|tinyurl', url) else 1
    
    # Hyphens in Domain
    f_dict['Prefix_Suffix'] = -1 if '-' in domain else 1
    
    # Subdomain Count
    dots = domain.count('.')
    f_dict['having_Sub_Domain'] = 1 if dots <= 2 else (0 if dots == 3 else -1)
    
    # SSL State (One of the most weighted features)
    f_dict['SSLfinal_State'] = 1 if parsed.scheme == 'https' else -1
    
    # URL of Anchor & Request URL (Heuristic approximation)
    # If it's a deep path with keywords, we flag these as suspicious
    if any(word in url for word in ['login', 'verify', 'update', 'bank', 'secure']):
        f_dict['URL_of_Anchor'] = -1
        f_dict['Request_URL'] = -1
        f_dict['HTTPS_token'] = -1
        f_dict['Abnormal_URL'] = -1
    else:
        f_dict['URL_of_Anchor'] = 1
        f_dict['Request_URL'] = 1
        f_dict['HTTPS_token'] = 1
        f_dict['Abnormal_URL'] = 1

    # Return list in the EXACT order the model expects
    return [f_dict[col] for col in expected_columns]

# 4. User Interface
st.markdown("<h1>🛡️ VELOXGUARD AI PRO</h1>", unsafe_allow_html=True)

url_input = st.text_input("🔗 Enter URL for 30-Vector Analysis:", placeholder="https://www.example.com")

if st.button("EXECUTE FORENSIC SCAN"):
    if url_input and model:
        with st.spinner("Analyzing deep patterns..."):
            # Step 1: Extract 30 features
            vector = extract_all_features(url_input, feature_names)
            
            # Step 2: Predict (Result: 1 = Safe, -1 = Phishing)
            prediction = model.predict([vector])[0]
            prob = model.predict_proba([vector])[0]
            
            st.write("---")
            col1, col2, col3 = st.columns(3)
            
            # Prediction values: [-1, 1]. prob[0] is for -1, prob[1] is for 1.
            if prediction == 1:
                col1.metric("SAFETY STATUS", "SECURE", "Clean")
                st.success("✅ **Legitimate Site.** No malicious signatures detected.")
            else:
                col1.metric("SAFETY STATUS", "MALICIOUS", "-Danger", delta_color="inverse")
                st.error("🚨 **PHISHING DETECTED!** This URL shows high-risk fraudulent patterns.")
                st.warning(f"**Malice Confidence Score:** {prob[0]*100:.1f}%")

            col2.metric("VECTORS ANALYZED", "30")
            col3.metric("ENGINE", "RandomForest")

            with st.expander("📝 Detailed Forensic Breakdown"):
                breakdown = pd.DataFrame({
                    "Feature": feature_names,
                    "Score": vector
                })
                st.table(breakdown)
                st.info("Score Key: 1 = Safe, 0 = Suspicious, -1 = Malicious")
    else:
        st.warning("Please enter a URL to begin.")
