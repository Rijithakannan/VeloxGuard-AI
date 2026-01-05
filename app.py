import pandas as pd
import streamlit as st
import re
import shutil
import pytesseract
from sklearn.ensemble import RandomForestClassifier
from PIL import Image

# 1. Tesseract OCR Configuration
tesseract_path = shutil.which("tesseract")
if not tesseract_path:
    # Default Windows installation path
    tesseract_path = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
pytesseract.pytesseract.tesseract_cmd = tesseract_path

# --- OCR URL Extraction Logic ---
def extract_urls_from_text(text):
    """Detects URLs within text using enhanced Regex patterns."""
    url_pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    return re.findall(url_pattern, text)

# 2. Page Configuration
st.set_page_config(page_title="VeloxGuard AI", page_icon="🛡️", layout="wide")

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

# 3. Feature Extraction (Aligned with UCI Dataset Features)
def extract_features(url):
    features = []
    # Feature 1: IP Address
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(-1 if re.search(ip_pattern, url) else 1) 
    
    # Feature 2: URL Length
    url_len = len(url)
    if url_len < 54: features.append(1)
    elif 54 <= url_len <= 75: features.append(0)
    else: features.append(-1)
    
    # Feature 3: @ Symbol
    features.append(-1 if "@" in url else 1)
    
    # Feature 4: Subdomains
    dot_count = url.count('.')
    if dot_count <= 2: features.append(1) # Standard: 1 is secure
    elif dot_count == 3: features.append(0)
    else: features.append(-1)
    
    return features

# 4. Model Training
@st.cache_resource
def train_velox_model():
    try:
        # Ensure dataset.csv exists in the root directory
        df = pd.read_csv("dataset.csv")
        # Ensure these column names match your CSV exactly
        features_to_use = ['having_IPhaving_IP_Address', 'URLURL_Length', 'having_At_Symbol', 'having_Sub_Domain']
        X = df[features_to_use]
        y = df['Result'] 
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        return model
    except Exception as e:
        st.error(f"Setup Error: Dataset not found or column mismatch. {e}")
        return None

model = train_velox_model()

# 5. Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/fluency/144/shield.png", width=80)
    st.title("VeloxGuard Control")
    st.write("---")
    st.markdown("### 🚀 Deployment Status")
    st.success("Connected to GitHub")
    st.write("---")
    st.markdown("### Model Diagnostics")
    st.info("Algorithm: Random Forest")

# 6. Main Interface
st.markdown("<h1>🛡️ VELOXGUARD AI</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #808495;'>Cloud-Integrated Cyber Threat Detection System</p>", unsafe_allow_html=True)

# --- Section 1: Manual URL Scan ---
url_input = st.text_input("🔗 Enter URL for deep heuristic analysis:", placeholder="https://secure-login.com")

if st.button("EXECUTE SCAN"):
    if model is not None and url_input:
        with st.spinner("Analyzing vectors..."):
            user_features = extract_features(url_input)
            prediction = model.predict([user_features])[0]
            prob = model.predict_proba([user_features])[0]
            
            st.write("---")
            col1, col2 = st.columns(2)
            
            # NOTE: In UCI Dataset, 1 = Legitimate, -1 = Phishing
            if prediction == 1: 
                col1.metric("Status", "SECURE", delta="Safe")
                st.success(f"✅ **Legitimate Site.** Confidence: {max(prob)*100:.1f}%")
                st.balloons()
            else: 
                col1.metric("Status", "MALICIOUS", delta="-Danger", delta_color="inverse")
                st.error(f"🚨 **Warning: Phishing Link Detected!** Confidence: {max(prob)*100:.1f}%")
    elif not url_input:
        st.warning("Please provide a URL to scan.")

# --- Section 2: Visual Threat Analysis ---
st.write("---")
st.subheader("📸 Visual Threat Scan")
uploaded_image = st.file_uploader("Upload a screenshot for OCR analysis", type=['png', 'jpg', 'jpeg'])

if st.button("SCAN SCREENSHOT"):
    if model is not None and uploaded_image:
        try:
            with st.spinner("Extracting text..."):
                img = Image.open(uploaded_image)
                extracted_text = pytesseract.image_to_string(img)
                found_urls = extract_urls_from_text(extracted_text)
                
                if found_urls:
                    st.info(f"Detected {len(found_urls)} URL(s) in screenshot:")
                    for url in found_urls:
                        feat = extract_features(url)
                        res = model.predict([feat])[0]
                        label = "✅ SECURE" if res == 1 else "🚨 MALICIOUS"
                        st.markdown(f"- `{url}` : **{label}**")
                else:
                    st.warning("No URLs found. Please ensure the screenshot contains a visible web address.")
        except Exception as e:
            st.error("OCR Error: Ensure Tesseract is installed on your computer.")
            st.code("Download: https://github.com/UB-Mannheim/tesseract/wiki")

st.write("---")
st.caption("© 2026 VeloxGuard | AI Security Documentation")
