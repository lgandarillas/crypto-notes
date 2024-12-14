# [crypto-notes | UC3M - Cryptography and computer security]

## Secure Notes Application

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

4. Inside the notes section of each user:
    - **Create**: Encrypts the note and signs it digitally.
    - **Read**: Decrypts the note and verifies its signature.
    - **List**: Retrieves encrypted note titles.
    - **Delete**: Removes the note and updates storage securely.

---

### Developers

- **Carlos Bravo Garrán** - [GitHub](https://github.com/CarlosBravoGarran)
- **Luis Gandarillas Fernández** - [GitHub](https://github.com/lgandarillas)

---

### Features and Cryptographic Design

**1. Robust Security**
- **Encryption**:
  - ChaCha20Poly1305: Used for authenticated encryption of notes.
  - RSA: Secures symmetric keys using RSA-OAEP with SHA-256 padding.
- **Password Protection**:
  - PBKDF2-HMAC-SHA256: Strengthens passwords with 480,000 iterations and a unique salt.
  - Fernet Encryption: Safeguards sensitive user data.
  - Two-Factor Authentication (2FA):
  - TOTP: Generates time-based one-time passwords, compatible with Google Authenticator.

**2. Certificate Infrastructure**
- **PKI Hierarchy**:
  - Public Key Infrastructure with Root CA and Intermediate CAs to issue user certificates.
  - Certificate validation during login and cryptographic operations.

**3. Digital Signature**
- **Purpose**:
  - Ensures note authenticity and integrity.
- **Implementation**:
  - Signatures generated using RSA-PSS with private keys.
  - Verification performed with users' public keys.

**4. Note Management**
- **Supported Actions**:
  - Create, read, list, and delete encrypted notes.
- **Modularity**:
  - Centralized management of encryption, decryption, and file handling.

**5. Logs & Error Handling**
- **Logs**:
  - Detailed logs for cryptographic operations.
- **Interruptions**:
  - Secure handling of interruptions (e.g., Ctrl+C) without compromising data.
