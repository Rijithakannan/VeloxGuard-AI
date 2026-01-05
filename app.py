import pandas as pd
import streamlit as st
import re
import shutil
import pytesseract
from sklearn.ensemble import RandomForestClassifier
from PIL import Image

# 1. Tesseract OCR Configuration (Handle Local Windows vs Cloud/Linux)
tesseract_path = shutil.which("tesseract")
if not tesseract_path:
    # If not found in system PATH, try the default Windows path
    tesseract_path = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
pytesseract.pytesseract.tesseract_cmd = tesseract_path

# --- ADDED: OCR URL Extraction Logic ---
def extract_urls_from_text(text):
    """Detects URLs within text using Regex patterns."""
    url_pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    return re.findall(url_pattern, text)

# 2. Page Configuration
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

# 3. Feature Extraction (Strictly mapped to dataset.csv logic)
def extract_features(url):
    features = []
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(-1 if re.search(ip_pattern, url) else 1) 
    url_len = len(url)
    if url_len < 54: features.append(1)
    elif 54 <= url_len <= 75: features.append(0)
    else: features.append(-1)
    features.append(-1 if "@" in url else 1)
    dot_count = url.count('.')
    if dot_count <= 1: features.append(1)
    elif dot_count == 2: features.append(0)
    else: features.append(-1)
    return features

# 4. Model Training
@st.cache_resource
def train_velox_model():
    try:
        df = pd.read_csv("dataset.csv")
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

# 5. Sidebar & Presentation Info
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
    st.write("- **Dataset:** UCI Repository")

# 6. Main Interface
st.markdown("<h1 style='text-align: center; color: #ff4b4b;'>🛡️ VELOXGUARD AI</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #808495;'>Cloud-Integrated Cyber Threat Detection System</p>", unsafe_allow_html=True)

# --- Section 1: Manual URL Scan ---
url_input = st.text_input("🔗 Enter URL for deep heuristic analysis:", placeholder="https://secure-login.com")

if st.button("EXECUTE SCAN"):
    if model is not None and url_input:
        with st.spinner("Processing feature vectors..."):
            user_features = extract_features(url_input)
            prediction = model.predict([user_features])[0]
            prob = model.predict_proba([user_features])[0]
            
            st.write("---")
            col1, col2 = st.columns(2)
            
            if prediction == -1: 
                col1.metric("Status", "SECURE", delta="Normal")
                st.success("✅ **Legitimate Site.** No malicious patterns found.")
                st.balloons()
            else: 
                col1.metric("Status", "MALICIOUS", delta="-Danger", delta_color="inverse")
                st.error("🚨 **Warning: Phishing Link Detected!**")
                st.info(f"**Threat Probability:** {prob[1]*100:.2f}%")
    elif not url_input:
        st.warning("Please provide a URL to scan.")

# --- Section 2: AI-Powered Visual Threat Analysis (OCR) ---
st.write("---")
st.subheader("📸 Visual Threat Scan ")
uploaded_image = st.file_uploader("Upload a screenshot of a suspicious email or website", type=['png', 'jpg', 'jpeg'])

if st.button("SCAN SCREENSHOT"):
    if model is not None and uploaded_image:
        try:
            with st.spinner("Extracting URLs from image..."):
                img = Image.open(uploaded_image)
                # Perform OCR using the configured path
                extracted_text = pytesseract.image_to_string(img)
                found_urls = extract_urls_from_text(extracted_text)
                
                if found_urls:
                    st.success(f"Detected {len(found_urls)} URL(s) in screenshot.")
                    for url in found_urls:
                        st.markdown(f"**Analyzing:** `{url}`")
                        features = extract_features(url)
                        prediction = model.predict([features])[0]
                        if prediction == -1:
                            st.write("✅ Status: **SECURE**")
                        else:
                            st.write("🚨 Status: **MALICIOUS**")
                else:
                    st.warning("No URLs detected in the image. Ensure the text is clear.")
        except Exception as e:
            st.error(f"OCR Error: {e}")
            st.info("Note: Ensure Tesseract-OCR is installed on your system.")
    elif not uploaded_image:
        st.warning("Please upload an image first.")

st.write("---")
st.caption("© 2025 VeloxGuard | Project Presentation Mode | GitHub Sync Enabled")

