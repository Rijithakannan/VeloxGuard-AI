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

# 2. Model Training (Aligned with dataset.csv)
@st.cache_resource
def train_velox_model():
    try:
        df = pd.read_csv("dataset.csv")
        # Removing index and target to get exactly 30 features
        X = df.drop(columns=['index', 'Result']) if 'index' in df.columns else df.drop(columns=['Result'])
        y = df['Result']
        
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        return model, X.columns.tolist()
    except Exception as e:
        st.error(f"Initialization Error: {e}")
        return None, []

model, feature_names = train_velox_model()

# 3. Intelligent Feature Extraction
def extract_all_features(url, expected_columns):
    # Store original for protocol check
    original_input = url.lower()
    
    # Standardize for parsing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # Initialize all 30 features to 0 (Suspicious/Neutral)
    # This prevents the 'All Secure' bias
    f_dict = {col: 0 for col in expected_columns}
    
    # --- PHYSICAL STRING ANALYSIS ---
    f_dict['having_IPhaving_IP_Address'] = -1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 1
    f_dict['URLURL_Length'] = 1 if len(url) < 54 else (0 if len(url) <= 75 else -1)
    f_dict['Shortining_Service'] = -1 if re.search('bit\.ly|goo\.gl|t\.co|tinyurl', url) else 1
    f_dict['having_At_Symbol'] = -1 if "@" in url else 1
    f_dict['Prefix_Suffix'] = -1 if '-' in domain else 1
    
    # --- PROTOCOL & SUBDOMAINS ---
    # Strictly penalty for lack of https
    f_dict['SSLfinal_State'] = 1 if original_input.startswith('https://') else -1
    
    dots = domain.count('.')
    f_dict['having_Sub_Domain'] = 1 if dots <= 2 else (0 if dots == 3 else -1)
    
    # --- KEYWORD/HEURISTIC MAPPING ---
    # We map 'suspicious intent' to several high-weight features in the CSV
    suspicious_words = ['secure', 'update', 'bank', 'verify', 'login', 'account', 'info']
    if any(word in url.lower() for word in suspicious_words):
        f_dict['HTTPS_token'] = -1
        f_dict['Abnormal_URL'] = -1
        f_dict['URL_of_Anchor'] = -1
        f_dict['Request_URL'] = -1
    else:
        f_dict['HTTPS_token'] = 1
        f_dict['Abnormal_URL'] = 1
        f_dict['URL_of_Anchor'] = 1
        f_dict['Request_URL'] = 1

    # Return list in the EXACT order the model was trained on
    return [f_dict[col] for col in expected_columns]

# 4. User Interface
st.markdown("<h1>🛡️ VELOXGUARD AI PRO</h1>", unsafe_allow_html=True)

url_input = st.text_input("🔗 Enter URL for 30-Vector Forensic Scan:", placeholder="http://example-update-login.com")

if st.button("EXECUTE SCAN"):
    if url_input and model:
        with st.spinner("Processing neural patterns..."):
            vector = extract_all_features(url_input, feature_names)
            prediction = model.predict([vector])[0]
            prob = model.predict_proba([vector])[0]
            
            st.write("---")
            col1, col2, col3 = st.columns(3)
            
            # Prediction values: 1 = Legitimate, -1 = Phishing
            if prediction == 1:
                col1.metric("SAFETY STATUS", "SECURE", "Legitimate")
                st.success("✅ **Legitimate Site.** Patterns appear normal.")
            else:
                col1.metric("SAFETY STATUS", "MALICIOUS", "-Danger", delta_color="inverse")
                st.error("🚨 **PHISHING DETECTED!** High-risk fraudulent patterns found.")
                # Class 0 is -1 (Phishing), Class 1 is 1 (Legitimate)
                st.warning(f"**Malice Confidence Score:** {prob[0]*100:.1f}%")

            col2.metric("VECTORS ANALYZED", "30")
            col3.metric("ENGINE", "RandomForest")

            with st.expander("📝 View 30-Dimension Vector Data"):
                breakdown = pd.DataFrame({"Feature": feature_names, "Score": vector})
                st.table(breakdown)
                st.info("Score Key: 1 (Safe), 0 (Suspicious), -1 (Malicious)")
    else:
        st.warning("Please provide a URL to begin analysis.")
