"""
SecureWipe Certificate Verification Web Server with Dynamic Key Verification
Replace: src/core/verify_server.py

Features:
- 4-stage verification process with visual progress
- Before/After badge display
- Real-time verification status
- Dynamic key verification via single QR code payload
- NEW: Added a button in the HTML template to trigger device camera for QR code scanning.
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import json
import hashlib
import os
import sys
import base64 # Import for Base64 decoding
import zlib # Import for simple decompression

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    USE_PYCRYPTO = True
except ImportError:
    USE_PYCRYPTO = False

app = Flask(__name__)
CORS(app)

# Global public key is NO LONGER needed to be loaded from local file

def verify_signature(cert_hash, signature_hex, public_key_content):
    """Verify RSA signature using the public key provided in the QR payload."""
    
    if not public_key_content:
        return False, "Public key content missing from QR payload"
    
    try:
        if USE_PYCRYPTO:
            # Import the key from the PEM string content
            public_key = RSA.import_key(public_key_content)
            
            # Use PyCrypto
            signature_bytes = bytes.fromhex(signature_hex)
            hash_object = SHA256.new(cert_hash.encode('utf-8'))
            verifier = pkcs1_15.new(public_key)
            verifier.verify(hash_object, signature_bytes)
            return True, "Signature verified successfully using PyCrypto (Dynamic Key)"
        
        else:
            # Fallback to OpenSSL CLI using a temporary key file
            import subprocess
            
            # Create temporary key, data, and signature files
            temp_key = "temp_verify_key.pem"
            temp_data = "temp_verify_data.bin"
            temp_sig = "temp_verify_sig.bin"
            
            try:
                # 1. Write public key content to temp file
                with open(temp_key, 'w') as f:
                    f.write(public_key_content)
                    
                # 2. Write data hash and signature to temp files
                with open(temp_data, 'w') as f:
                    f.write(cert_hash)
                
                with open(temp_sig, 'wb') as f:
                    f.write(bytes.fromhex(signature_hex))
                
                # 3. Verify using OpenSSL
                result = subprocess.run([
                    "openssl", "dgst",
                    "-sha256",
                    "-verify", temp_key, # Use the temporary key file
                    "-signature", temp_sig,
                    temp_data
                ], capture_output=True, text=True, timeout=10)
                
                is_valid = "Verified OK" in result.stdout
                message = "Signature verified successfully using OpenSSL (Dynamic Key)" if is_valid else "Signature verification failed"
                return is_valid, message
                
            finally:
                # Cleanup
                for f in [temp_key, temp_data, temp_sig]:
                    if os.path.exists(f):
                        os.remove(f)
            
    except (ValueError, TypeError) as e:
        return False, f"Invalid signature or key format: {str(e)}"
    except Exception as e:
        return False, f"Verification failed: {str(e)}"

def verify_blockchain_integrity(cert_data):
    """Verify blockchain hash integrity."""
    try:
        block_copy = cert_data.copy()
        block_copy.pop('hash', None)
        block_copy.pop('digital_signature', None)
        
        block_string = json.dumps(block_copy, sort_keys=True).encode()
        calculated_hash = hashlib.sha256(block_string).hexdigest()
        stored_hash = cert_data.get('hash')
        
        return calculated_hash == stored_hash
    except Exception as e:
        print(f"Blockchain verification error: {e}")
        return False

# HTML template modified to handle the URL parameter and camera scan button
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureWipe Certificate Verification Portal</title>
    <script src="https://unpkg.com/jsqr@1.4.0/dist/jsQR.js"></script> <style>
        /* ... CSS STYLES (AS IN ORIGINAL FILE) ... */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1000px;
            margin: 40px auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 50px 40px;
            text-align: center;
        }
        
        .header h1 { font-size: 2.8em; margin-bottom: 15px; font-weight: 700; }
        .header p { font-size: 1.2em; opacity: 0.95; }
        
        .content { padding: 50px 40px; }
        
        .upload-section {
            border: 3px dashed #667eea;
            border-radius: 15px;
            padding: 50px 40px;
            text-align: center;
            background: linear-gradient(135deg, #f8f9ff 0%, #f0f2ff 100%);
            transition: all 0.3s ease;
        }
        
        .upload-section:hover {
            border-color: #764ba2;
            transform: translateY(-2px);
        }
        
        .upload-icon { font-size: 5em; margin-bottom: 25px; }
        .upload-section h2 { color: #667eea; margin-bottom: 15px; font-size: 1.8em; }
        
        .upload-btn-group {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 20px;
        }
        
        .upload-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 25px;
            border: none;
            border-radius: 30px;
            font-size: 1.1em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
            min-width: 200px;
        }
        
        .upload-btn:hover { transform: translateY(-3px); }
        
        .verification-stages {
            display: none;
            margin-top: 40px;
        }
        
        .verification-stages.active {
            display: block;
            animation: fadeIn 0.5s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .progress-container {
            width: 100%;
            height: 8px;
            background: #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
            margin: 20px 0;
        }
        
        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            width: 0%;
            transition: width 0.5s ease;
        }
        
        .stage {
            background: #f8f9ff;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 20px;
            border-left: 5px solid #ccc;
            transition: all 0.3s;
        }
        
        .stage.active {
            border-left-color: #667eea;
            background: linear-gradient(135deg, #f8f9ff 0%, #f0f2ff 100%);
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.2);
        }
        
        .stage.completed {
            border-left-color: #28a745;
            background: linear-gradient(135deg, #e8f8e8 0%, #d4f1d4 100%);
        }
        
        .stage.failed {
            border-left-color: #dc3545;
            background: linear-gradient(135deg, #ffe8e8 0%, #ffd4d4 100%);
        }
        
        .stage-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .stage-icon {
            font-size: 2em;
            width: 50px;
            height: 50px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: white;
            border-radius: 50%;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .stage-title { font-size: 1.4em; font-weight: 600; color: #34495e; }
        .stage-content { margin-left: 65px; color: #555; }
        
        .badge-display {
            display: flex;
            justify-content: center;
            gap: 40px;
            margin: 30px 0;
            flex-wrap: wrap;
        }
        
        .badge-container { text-align: center; }
        
        .badge {
            width: 250px;
            height: 100px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: all 0.3s;
        }
        
        .badge:hover { transform: scale(1.05); }
        
        .badge.unverified {
            background: linear-gradient(135deg, #f5f5f5 0%, #e8e8e8 100%);
            border: 3px solid #999;
            color: #666;
        }
        
        .badge.verified {
            background: linear-gradient(135deg, #e6ffe6 0%, #ccffcc 100%);
            border: 3px solid #28a745;
            color: #155724;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3); }
            50% { box-shadow: 0 4px 25px rgba(40, 167, 69, 0.6); }
        }
        
        .badge.invalid {
            background: linear-gradient(135deg, #ffe6e6 0%, #ffcccc 100%);
            border: 3px solid #dc3545;
            color: #721c24;
        }
        
        .badge-symbol { font-size: 3em; font-weight: bold; }
        
        .badge-text { text-align: left; }
        .badge-title { font-weight: bold; font-size: 1.1em; margin-bottom: 5px; }
        .badge-subtitle { font-size: 0.9em; opacity: 0.9; }
        .badge-label { margin-top: 10px; font-weight: 600; color: #667eea; }
        
        .cert-details {
            background: #f8f9ff;
            border-radius: 12px;
            padding: 25px;
            margin-top: 25px;
        }
        
        .detail-row {
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .detail-row:last-child { border-bottom: none; }
        .detail-label { font-weight: 600; color: #34495e; }
        .detail-value {
            text-align: right;
            font-family: 'Courier New', monospace;
            color: #555;
            max-width: 60%;
            word-break: break-all;
        }
        
        .signature-box {
            background: #2c3e50;
            color: #2ecc71;
            padding: 20px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            word-break: break-all;
            margin: 20px 0;
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.3);
        }
        
        .loading {
            display: none;
            text-align: center;
            margin: 40px 0;
        }
        
        .loading.active { display: block; }
        
        .spinner {
            border: 5px solid rgba(102, 126, 234, 0.2);
            border-radius: 50%;
            border-top: 5px solid #667eea;
            width: 60px;
            height: 60px;
            animation: spin 1s linear infinite;
            margin: 0 auto 25px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .action-buttons {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 30px;
        }
        
        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 25px;
            font-weight: 600;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        
        .btn-secondary {
            background: white;
            color: #667eea;
            border: 2px solid #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 DSC Verification Portal</h1>
            <p>Digital Signature Certificate Validation System</p>
        </div>

        <div class="content">
            <div class="upload-section" id="uploadSection">
                <div class="upload-icon">📄</div>
                <h2>Verify Certificate by Upload or Scan</h2>
                <p>Use the camera to scan the QR code on the physical certificate, or upload the JSON file.</p>
                <div class="upload-btn-group">
                    <button class="upload-btn" onclick="document.getElementById('cameraInput').click()">
                        <span style="font-size: 1.2em; margin-right: 5px;">📷</span> Scan QR with Camera
                    </button>
                    <button class="upload-btn" onclick="document.getElementById('fileInput').click()">
                        <span style="font-size: 1.2em; margin-right: 5px;">📁</span> Upload JSON File
                    </button>
                </div>
                <input type="file" id="fileInput" accept=".json" style="display:none;">
                <input type="file" id="cameraInput" accept="image/*" capture="environment" style="display:none;">
            </div>

            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p style="color: #667eea; font-weight: 600; font-size: 1.2em;">Processing verification...</p>
            </div>

            <div class="verification-stages" id="verificationStages">
                <h2 style="text-align: center; margin-bottom: 30px; color: #34495e;">
                    Verification Process
                </h2>
                
                <div class="progress-container">
                    <div class="progress-bar" id="progressBar"></div>
                </div>

                <div class="stage" id="stage1">
                    <div class="stage-header">
                        <div class="stage-icon">📁</div>
                        <div class="stage-title">Stage 1: File/QR Data Upload</div>
                    </div>
                    <div class="stage-content">Loading certificate data...</div>
                </div>

                <div class="stage" id="stage2">
                    <div class="stage-header">
                        <div class="stage-icon">⏳</div>
                        <div class="stage-title">Stage 2: Key Registration & Pre-Validation</div>
                    </div>
                    <div class="stage-content">
                        <p id="keyRegistrationStatus">Extracting and registering signing key for this certificate...</p>
                        <div class="badge-display">
                            <div class="badge-container">
                                <div class="badge unverified">
                                    <div class="badge-symbol">⏳</div>
                                    <div class="badge-text">
                                        <div class="badge-title">AWAITING VERIFICATION</div>
                                        <div class="badge-subtitle">Not Yet Validated</div>
                                    </div>
                                </div>
                                <div class="badge-label">BEFORE VALIDATION</div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stage" id="stage3">
                    <div class="stage-header">
                        <div class="stage-icon">🔐</div>
                        <div class="stage-title">Stage 3: Digital Signature Verification</div>
                    </div>
                    <div class="stage-content">
                        <p>Verifying RSA-2048 cryptographic signature...</p>
                        <div class="signature-box" id="signatureDisplay">Loading signature data...</div>
                    </div>
                </div>

                <div class="stage" id="stage4">
                    <div class="stage-header">
                        <div class="stage-icon">✓</div>
                        <div class="stage-title">Stage 4: Post-Validation Result</div>
                    </div>
                    <div class="stage-content">
                        <div class="badge-display" id="resultBadges"></div>
                        <div class="cert-details" id="certDetails"></div>
                    </div>
                </div>

                <div class="action-buttons">
                    <button class="btn btn-primary" onclick="downloadReport()">
                        Download Verification Report
                    </button>
                    <button class="btn btn-secondary" onclick="resetVerification()">
                        Verify Another Certificate
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentCertData = null;
        let currentPublicKey = null;
        
        // --- Core QR Processing Function (Client Side) ---
        function decodeImageQR(file) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = (e) => {
                    const img = new Image();
                    img.onload = () => {
                        try {
                            // Create a canvas element to get image data
                            const canvas = document.createElement('canvas');
                            canvas.width = img.width;
                            canvas.height = img.height;
                            const ctx = canvas.getContext('2d');
                            ctx.drawImage(img, 0, 0, img.width, img.height);
                            
                            const imageData = ctx.getImageData(0, 0, img.width, img.height);
                            // Use the jsqr library imported in the head
                            const code = jsQR(imageData.data, imageData.width, imageData.height);
                            
                            if (code) {
                                // QR code data format is expected to be 'http://<url>/verify?data=<base64>'
                                const urlMatch = code.data.match(/data=(.*)/);
                                if (urlMatch && urlMatch[1]) {
                                    resolve(urlMatch[1]); // Resolve with just the base64 payload
                                } else {
                                    reject(new Error("QR code content is not a valid SecureWipe verification URL."));
                                }
                            } else {
                                reject(new Error("No QR code found in the image."));
                            }
                        } catch (err) {
                            reject(new Error("Error processing image for QR code: " + err.message));
                        }
                    };
                    img.src = e.target.result;
                };
                reader.onerror = (e) => reject(new Error("Failed to read file."));
                reader.readAsDataURL(file);
            });
        }
        // ------------------------------------------------
        
        // --- Handle Camera Scan ---
        document.getElementById('cameraInput').addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            
            document.getElementById('loading').classList.add('active');
            document.getElementById('uploadSection').style.display = 'none';

            try {
                // 1. Decode QR code from the captured image
                const qrPayload = await decodeImageQR(file);
                
                // 2. Start verification with the extracted payload
                await startVerification(qrPayload, 'qr');
                
            } catch (error) {
                alert('QR Code Scan Failed: ' + error.message);
                resetVerification();
            }
        });

        // --- Handle Manual File Upload ---
        document.getElementById('fileInput').addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            
            // For manual upload, we need the public key to be manually transferred 
            // and the server is assumed to be running with the correct key (or we fail).
            alert("Manual upload requires the verification server to be pre-configured with the correct public key. Verification may fail.");
            
            startVerification(file, 'manual');
        });
        
        // --- Handle URL QR Scan (Deep Link) ---
        document.addEventListener('DOMContentLoaded', () => {
            const urlParams = new URLSearchParams(window.location.search);
            const qrData = urlParams.get('data');
            
            if (qrData) {
                // Remove the URL parameter to clean up the address bar
                window.history.replaceState(null, null, window.location.pathname);
                startVerification(qrData, 'qr');
            }
        });

        async function startVerification(payload, type) {
            document.getElementById('uploadSection').style.display = 'none';
            document.getElementById('loading').classList.add('active');
            
            try {
                if (type === 'qr') {
                    // QR data is a Base64-encoded string containing a JSON of {key, cert}
                    const response = await fetch('/api/decode_qr', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ data: payload })
                    });
                    
                    const decodedPayload = await response.json();
                    if (!decodedPayload.success) throw new Error(decodedPayload.message);
                    
                    const fullPayload = JSON.parse(decodedPayload.data);
                    
                    // Assign global variables from the QR payload
                    currentPublicKey = fullPayload.key;
                    currentCertData = JSON.parse(fullPayload.cert);
                    
                } else if (type === 'manual') {
                    // Manual upload is just the certificate JSON. Public Key will be null.
                    const text = await payload.text();
                    currentCertData = JSON.parse(text);
                    currentPublicKey = null; // Key remains null for manual upload, server uses its local key (if loaded)
                }

                await runVerificationStages(currentCertData, currentPublicKey);
            } catch (error) {
                alert('Error processing certificate data: ' + error.message);
                resetVerification();
            }
        }
        
        async function runVerificationStages(certData, publicKey) {
            const stages = document.getElementById('verificationStages');
            const loading = document.getElementById('loading');
            
            loading.classList.remove('active');
            stages.classList.add('active');
            
            // Stage 1: File/QR Data Upload
            await activateStage('stage1', 25);
            document.querySelector('#stage1 .stage-content').innerHTML = 
                `<p>✓ Certificate data loaded successfully</p>
                 <p>Certificate ID: <code>${certData.hash ? certData.hash.substring(0, 16) : 'N/A'}</code></p>`;
            await sleep(1000);
            completeStage('stage1');
            
            // Stage 2: Key Registration & Pre-Validation
            await activateStage('stage2', 50);
            if (publicKey) {
                document.getElementById('keyRegistrationStatus').innerHTML = `
                    <p>✓ Signing key successfully extracted from QR data and registered for verification.</p>
                    <p>Key Hash: <code>${btoa(publicKey).substring(0, 32)}...</code></p>
                `;
            } else {
                 document.getElementById('keyRegistrationStatus').innerHTML = `
                    <p>⚠ Manual upload detected. Using server's default public key for verification.</p>
                 `;
            }
            await sleep(1500);
            completeStage('stage2');
            
            // Stage 3: Signature Verification
            await activateStage('stage3', 75);
            const signature = certData.digital_signature || 'N/A';
            document.getElementById('signatureDisplay').textContent = signature;
            await sleep(1000);
            
            // Call API to verify, including the public key in the body
            const response = await fetch('/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cert_data: certData, public_key: publicKey })
            });
            
            const result = await response.json();
            const isValid = result.valid;
            
            if (isValid) {
                completeStage('stage3');
            } else {
                failStage('stage3');
            }
            
            // Stage 4: Results
            await activateStage('stage4', 100);
            displayResults(certData, result);
            
            if (isValid) {
                completeStage('stage4');
            } else {
                failStage('stage4');
            }
        }
        
        // ... [activateStage, completeStage, failStage, downloadReport, resetVerification, sleep remain as in original file] ...
        
        async function activateStage(stageId, progress) {
            const stage = document.getElementById(stageId);
            stage.classList.add('active');
            stage.scrollIntoView({ behavior: 'smooth', block: 'center' });
            document.getElementById('progressBar').style.width = progress + '%';
            await sleep(300);
        }
        
        function completeStage(stageId) {
            const stage = document.getElementById(stageId);
            stage.classList.remove('active');
            stage.classList.add('completed');
            const icon = stage.querySelector('.stage-icon');
            icon.textContent = '✓';
        }
        
        function failStage(stageId) {
            const stage = document.getElementById(stageId);
            stage.classList.remove('active');
            stage.classList.add('failed');
            const icon = stage.querySelector('.stage-icon');
            icon.textContent = '✗';
        }
        
        function displayResults(certData, result) {
            const resultBadges = document.getElementById('resultBadges');
            const data = certData.data || {};
            const isValid = result.valid;
            
            resultBadges.innerHTML = `
                <div class="badge-container">
                    <div class="badge unverified">
                        <div class="badge-symbol">⏳</div>
                        <div class="badge-text">
                            <div class="badge-title">UNVERIFIED</div>
                            <div class="badge-subtitle">Initial State</div>
                        </div>
                    </div>
                    <div class="badge-label">BEFORE</div>
                </div>
                
                <div class="badge-container">
                    <div class="badge ${isValid ? 'verified' : 'invalid'}">
                        <div class="badge-symbol">${isValid ? '✓' : '✗'}</div>
                        <div class="badge-text">
                            <div class="badge-title">${isValid ? 'VERIFIED' : 'INVALID'}</div>
                            <div class="badge-subtitle">${isValid ? 'Cryptographically Authentic' : 'Verification Failed'}</div>
                        </div>
                    </div>
                    <div class="badge-label">AFTER</div>
                </div>
            `;
            
            const certDetails = document.getElementById('certDetails');
            certDetails.innerHTML = `
                <h3 style="margin-bottom: 15px; color: #34495e;">Certificate Details</h3>
                <div class="detail-row">
                    <span class="detail-label">Certificate ID:</span>
                    <span class="detail-value">${certData.hash ? certData.hash.substring(0, 16) : 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Device:</span>
                    <span class="detail-value">${data.device_model || 'N/A'} (${data.device_size || 'N/A'})</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Wipe Method:</span>
                    <span class="detail-value">${data.wipe_method || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Status:</span>
                    <span class="detail-value">${data.wipe_status || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Timestamp:</span>
                    <span class="detail-value">${data.timestamp_utc || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Verification Result:</span>
                    <span class="detail-value" style="color: ${isValid ? '#28a745' : '#dc3545'}; font-weight: bold;">
                        ${isValid ? '✓ SIGNATURE VALID' : '✗ SIGNATURE INVALID'}
                    </span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Verification Message:</span>
                    <span class="detail-value">${result.message || 'N/A'}</span>
                </div>
            `;
        }
        
        function downloadReport() {
            if (!currentCertData) return;
            
            const report = {
                verification_date: new Date().toISOString(),
                certificate_id: currentCertData.hash,
                verification_result: 'VERIFIED',
                certificate_data: currentCertData
            };
            
            const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `verification_report_${currentCertData.hash.substring(0, 16)}.json`;
            a.click();
        }
        
        function resetVerification() {
            document.getElementById('uploadSection').style.display = 'block';
            document.getElementById('loading').classList.remove('active');
            document.getElementById('verificationStages').classList.remove('active');
            document.getElementById('fileInput').value = '';
            document.getElementById('cameraInput').value = '';
            document.getElementById('progressBar').style.width = '0%';
            
            ['stage1', 'stage2', 'stage3', 'stage4'].forEach(stageId => {
                const stage = document.getElementById(stageId);
                stage.classList.remove('active', 'completed', 'failed');
            });
            
            currentCertData = null;
            currentPublicKey = null;
        }
        
        function sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }
    </script>
</body>
</html>
'''

# --- NEW ENDPOINT: Decode the complex QR payload ---
@app.route('/api/decode_qr', methods=['POST'])
def decode_qr_api():
    """Decodes, decompresses, and returns the QR payload."""
    try:
        data = request.get_json().get('data')
        if not data:
            return jsonify({'success': False, 'message': 'No data payload provided'}), 400
        
        # 1. Base64 Decode
        compressed_bytes = base64.urlsafe_b64decode(data.encode('utf-8'))
        
        # 2. Decompress
        decompressed_string = zlib.decompress(compressed_bytes).decode('utf-8')
        
        # 3. Return the decompressed JSON string
        return jsonify({'success': True, 'data': decompressed_string})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Decoding/Decompression failed: {str(e)}'}), 500

@app.route('/verify')
@app.route('/')
def index():
    """Serve the verification portal, handling the QR code data parameter."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/verify', methods=['POST'])
def verify_certificate_api():
    """API endpoint to verify certificate."""
    try:
        data = request.get_json()
        cert_data = data.get('cert_data')
        # The public key is passed in the request body from the front-end script
        public_key_content = data.get('public_key')
        
        if not cert_data:
            return jsonify({
                'valid': False,
                'message': 'No certificate data provided'
            }), 400
        
        cert_hash = cert_data.get('hash')
        signature = cert_data.get('digital_signature')
        
        # If public_key_content is None (e.g., manual upload), load the server's local key as a fallback
        if not public_key_content:
             # This loads the key from the local public.pem file
             # Navigates up two levels from src/core/ to the root
             key_paths = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'public.pem')
             if os.path.exists(key_paths):
                 with open(key_paths, 'r') as f:
                     public_key_content = f.read()
        
        if not cert_hash:
            return jsonify({
                'valid': False,
                'signature_valid': False,
                'blockchain_valid': False,
                'message': 'Certificate hash missing'
            })
        
        if not signature or signature == "N/A (Key Missing)" or signature.startswith("ERROR"):
            return jsonify({
                'valid': False,
                'signature_valid': False,
                'blockchain_valid': verify_blockchain_integrity(cert_data),
                'message': 'Digital signature missing or invalid'
            })
        
        # Verify blockchain integrity
        blockchain_valid = verify_blockchain_integrity(cert_data)
        
        # Verify signature using the key supplied in the request (either from QR or fallback)
        sig_valid, sig_message = verify_signature(cert_hash, signature, public_key_content)
        
        # Overall validity
        overall_valid = sig_valid and blockchain_valid
        
        return jsonify({
            'valid': overall_valid,
            'signature_valid': sig_valid,
            'blockchain_valid': blockchain_valid,
            'message': sig_message
        })
        
    except Exception as e:
        return jsonify({
            'valid': False,
            'signature_valid': False,
            'blockchain_valid': False,
            'message': f'Verification error: {str(e)}'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'public_key_loaded': 'Dynamic (via QR payload)',
        'server': 'SecureWipe-V6 Verification Portal'
    })

if __name__ == '__main__':
    print("\n" + "="*70)
    print(" SecureWipe-V6 Certificate Verification Server")
    print("="*70)
    
    print(" ✓ Server ready for DYNAMIC cryptographic verification")
    print("\n Starting server on http://localhost:5000")
    print(" Open this URL in your browser to access the verification portal")
    print(" Press Ctrl+C to stop the server")
    print("="*70 + "\n")
    
    # We explicitly do NOT call load_public_key() here, as the key is expected via QR.
    app.run(debug=True, host='0.0.0.0', port=5000)
