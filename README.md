# Secure Notes Application

![Home](assets/home.png)

## Application Purpose

This secure notes system is a console-based application designed for users to store confidential information securely using advanced cryptographic measures. It ensures **confidentiality**, **integrity**, **authentication**, and **non-repudiation**, while maintaining **availability** through efficient encrypted file management and certificate verification.

---

### App Usage

1. Clone or download this repository:
    ```bash
    git clone https://github.com/lgandarillas/crypto-notes.git
    cd crypto-notes
    ```

2. Set up the virtual environment and install dependencies:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3. Run the application:
    ```bash
    python src/main.py
    ```

3. On launch, choose a mode:
    - **Register**: Set up a new account with 2FA and certificates.
    - **Login**: Access your secure notes.
    - **Exit**: Close the application.

4. Inside the notes section:
    - Create, read, list, or delete notes.

5. All actions are secured with cryptographic measures and 2FA.

---

### Developers

- **Carlos Bravo Garrán** - [100474964@alumnos.uc3m.es](mailto:100474964@alumnos.uc3m.es)
- **Luis Gandarillas Fernández** - [100471965@alumnos.uc3m.es](mailto:100471965@alumnos.uc3m.es)

### Key Features
- **Robust Security**:
  - ChaCha20Poly1305 for authenticated encryption of notes.
  - RSA for asymmetric encryption of keys and digital signatures.
  - SHA-256 hashing for integrity.
  - PBKDF2-HMAC-SHA256 for password strengthening.
  - Two-factor authentication (2FA) with TOTP.
- **User Management**:
  - Registration with RSA key pair generation and certificate issuance.
  - Login with password validation, 2FA, and certificate hierarchy validation.
- **Certificate Infrastructure**:
  - Hierarchical PKI with Root CA, Intermediate CAs, and user certificates.
  - Certificate validation for login and cryptographic operations.
- **Note Management**:
  - Create, read, list, and delete encrypted notes.
  - Fully modularized encryption, decryption, and file management.
- **Logs & Error Handling**:
  - Debug logs for cryptographic operations.
  - Secure handling of interruptions (e.g., Ctrl+C).

---

### Cryptographic Design

#### **1. Symmetric and Asymmetric Encryption**
- **ChaCha20Poly1305**: Authenticated encryption of note content.
- **RSA**: Protects symmetric keys using RSA-OAEP with SHA-256 padding.

#### **2. Digital Signature**
- **Purpose**: Validates note authenticity and ensures no unauthorized modifications.
- **Implementation**:
  - Hash with SHA-256.
  - Signature with RSA-PSS using private keys.
- **Verification**: Ensures the signature is valid using the user's public key.

#### **3. Certificate Infrastructure**
- **PKI Hierarchy**:
  - Root CA signs Intermediate CAs.
  - Intermediate CAs issue user certificates.
- **Usage**:
  - Certificates validate public keys during login and cryptographic operations.

#### **4. Password Management**
- **PBKDF2-HMAC-SHA256**:
  - Derives keys from passwords with 480,000 iterations.
  - Unique salt stored securely.
- **Fernet Encryption**: Protects sensitive user data.

#### **5. Two-Factor Authentication (2FA)**
- **TOTP**: Google Authenticator generates time-based OTPs.
- **Setup**:
  - Unique secret for each user.
  - QR code generation for ease of use.
