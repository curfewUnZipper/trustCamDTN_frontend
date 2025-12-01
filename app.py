import streamlit as st
import requests
import json
import base64
import os
import hashlib

from datetime import datetime

# Crypto imports (same as backend)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

API = "http://localhost:5000"  # Flask backend

# --- MUST MATCH BACKEND ---
AES_KEY = b'\x15\x2B\x4C\x0C\x5A\x16\x0B\x36\x63\x20\x13\xC8\x2C\x37\x42\x4D'
IV      = b'\x09\x08\x07\x06\x05\x04\x03\x02\x01\x16\x21\x2C'   # 12 bytes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ECDSA_PRIVATE_KEY_FILE = os.path.join(BASE_DIR, "ecdsa_private_key.pem")


def load_ecdsa_private_key():
    if not os.path.exists(ECDSA_PRIVATE_KEY_FILE):
        return None
    with open(ECDSA_PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def encrypt_aes_gcm(plaintext: bytes) -> bytes:
    aesgcm = AESGCM(AES_KEY)
    # NOTE: For real-world use, IV should be random per message.
    return aesgcm.encrypt(IV, plaintext, None)  # returns ciphertext + tag


def sign_digest_ecdsa(digest: bytes) -> bytes:
    """
    Sign SHA-256 digest with same ECDSA keypair as backend.
    Returns 64-byte raw (r||s) signature.
    """
    priv = load_ecdsa_private_key()
    if priv is None:
        return b""  # backend will treat as "no signature"
    der_sig = priv.sign(digest, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return raw


st.set_page_config(page_title="TrustCam-DTN Viewer", layout="wide")

# --- UI Header ---
st.markdown("""
# 🔐 TrustCam-DTN Viewer Dashboard
Secure Zero-Trust Image & File Sharing  

This UI **encrypts everything client-side** using AES-GCM and attaches an ECDSA-signed hash before sending to the backend.
""")

st.divider()

# ---------------- SECTION 1: Upload Manual Text or File ----------------

st.subheader("📤 Send Encrypted Text or File to System")

upload_mode = st.radio("Select input mode:", ["Text Message", "Upload File"])

if upload_mode == "Text Message":
    user_text = st.text_area("Enter text (will be encrypted before upload):", height=150)

    if st.button("Send Encrypted Text"):
        if not user_text.strip():
            st.warning("Please enter some text.")
        else:
            # 1) Prepare plaintext
            plaintext = user_text.encode("utf-8")

            # 2) Encrypt with AES-GCM
            ciphertext = encrypt_aes_gcm(plaintext)

            # 3) Compute SHA-256 hash of encrypted bundle
            digest = hashlib.sha256(ciphertext).digest()
            digest_hex = digest.hex()

            # 4) ECDSA sign the hash (using same key as backend)
            signature = sign_digest_ecdsa(digest)

            # 5) Metadata
            metadata = {
                "device_id": "UI_CLIENT_01",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "file_type": "text",
                "local_bundle_hash": digest_hex,
            }

            files = {
                "data": ("bundle.bin", ciphertext, "application/octet-stream"),
                "signature": ("sig.bin", signature, "application/octet-stream"),
            }

            res = requests.post(
                f"{API}/receive",
                files=files,
                data={"metadata": json.dumps(metadata)},
            )

            st.write("🔑 Local encrypted bundle SHA-256:")
            st.code(digest_hex)

            if res.status_code == 200:
                st.success("✔ Encrypted text uploaded successfully")
                st.json(res.json())
            else:
                st.error(f"Backend error: {res.status_code}")
                st.text(res.text)

else:
    upload = st.file_uploader("Upload a file (will be encrypted before upload)",
                              type=["jpg", "jpeg", "png", "txt", "pdf", "bin"])

    if upload and st.button("Upload Encrypted File"):
        # 1) Read file as bytes
        plaintext = upload.getvalue()

        # 2) Encrypt
        ciphertext = encrypt_aes_gcm(plaintext)

        # 3) Hash encrypted blob
        digest = hashlib.sha256(ciphertext).digest()
        digest_hex = digest.hex()

        # 4) Sign hash
        signature = sign_digest_ecdsa(digest)

        # 5) Metadata
        metadata = {
            "device_id": "UI_CLIENT_01",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "file_type": "binary",
            "original_name": upload.name,
            "local_bundle_hash": digest_hex,
        }

        files = {
            "data": ("bundle.bin", ciphertext, "application/octet-stream"),
            "signature": ("sig.bin", signature, "application/octet-stream"),
        }

        res = requests.post(
            f"{API}/receive",
            files=files,
            data={"metadata": json.dumps(metadata)},
        )

        st.write("🔑 Local encrypted bundle SHA-256:")
        st.code(digest_hex)

        if res.status_code == 200:
            st.success("✔ Encrypted file uploaded successfully")
            st.json(res.json())
        else:
            st.error(f"Backend error: {res.status_code}")
            st.text(res.text)

st.divider()

# ---------------- SECTION 2: View Stored Files ----------------

st.subheader("📁 Stored Files")

try:
    resp = requests.get(f"{API}/images").json()
except Exception as e:
    st.error(f"Could not contact backend: {e}")
    st.stop()

if resp["count"] == 0:
    st.write("⚠ No files uploaded yet.")
else:
    for f in resp["files"]:
        with st.expander(f"📄 " + f):

            file_bytes = requests.get(f"{API}/images/{f}").content
            ext = f.lower()

            # Image Preview
            if ext.endswith((".jpg", ".jpeg", ".png", ".gif")):
                st.image(file_bytes)

            # Text Preview
            elif ext.endswith(".txt"):
                st.text(file_bytes.decode(errors="ignore"))

            # PDF Preview note
            elif ext.endswith(".pdf"):
                st.info("📑 PDF detected — download to view.")

            # Unknown/Binary
            else:
                st.code(file_bytes[:140].hex() + " ...", language="text")

            # Download button for ALL files
            st.download_button(
                label="⬇ Download File",
                data=file_bytes,
                file_name=f,
                mime="application/octet-stream"
            )

st.divider()

# ---------------- SECTION 3: Transparency Log ----------------

st.subheader("🧾 Transparency Log")

log = requests.get(f"{API}/log").json()
verify = requests.get(f"{API}/log/verify").json()

col1, col2 = st.columns(2)

with col1:
    st.write("### 🔍 Chain Status")
    if verify["ok"]:
        st.success(verify["message"])
    else:
        st.error(verify["message"])

with col2:
    st.write("### 📦 Total Entries")
    st.metric("Captured Bundles", log["count"])

st.json(log)
