# Secure Authentication System

A Java-based authentication and identity management application built with Spring Boot. This project brings together multiple authentication mechanisms, account security features, OAuth2 integration, and a custom cryptographic token implementation.

The primary focus is exploring backend authentication workflows and implementing a custom encrypted token mechanism using AES-256 encryption and HMAC-SHA256 message authentication.

## Features

### 1. Authentication & Authorization
- User registration and login.
- Google OAuth2 authentication.
- GitHub OAuth2 authentication.
- Google reCAPTCHA integration.
- Role-based authorization.

### 2. Multi-Factor Authentication (MFA)
- TOTP-based authentication.
- QR code generation for authenticator app registration.
- Email OTP verification.

### 3. Account Security & Recovery
- Password hashing with BCrypt.
- Password reset functionality.
- Email-based verification.
- Session-based authentication and security management.

### 4. Custom Cryptographic Token System

A custom token generation and validation mechanism built using Java Cryptography Architecture (JCA).

Unlike a conventional JWT, this implementation encrypts its JSON payload before returning the token.

**Cryptographic components:**
- AES-256-CBC encryption.
- HMAC-SHA256 message authentication.
- Secure random 128-bit Initialization Vector (IV).
- Base64 encoding.
- Token expiration validation.
- Constant-time signature comparison using `MessageDigest.isEqual()`.
- External cryptographic key loading through environment variables.

**Token payload:**

| Field | Description |
|---|---|
| `sub` | Username / subject |
| `role` | Assigned user role |
| `iat` | Token issuance timestamp |
| `exp` | Token expiration timestamp |

**Custom token format:**

```text
HMAC_SIGNATURE.IV.ENCRYPTED_PAYLOAD
```

**Token generation workflow:**

1. Construct a JSON payload containing user identity, role, issuance time, and expiration time.
2. Generate a cryptographically secure random IV.
3. Encrypt the payload using AES-256-CBC.
4. Generate an HMAC-SHA256 value over the encrypted payload.
5. Encode the signature, IV, and encrypted payload using Base64.
6. Combine the components into the final token string.

**Token validation workflow:**

1. Split and decode the token components.
2. Recalculate the HMAC value.
3. Compare the expected and received signatures.
4. Reject tokens with invalid signatures.
5. Decrypt the payload.
6. Check token expiration.
7. Return the validated JSON payload.

**Cryptographic key management**

AES and HMAC keys are generated using Java's cryptographic key-generation facilities and loaded from environment variables.

```text
AES_SECRET_KEY
HMAC_SECRET_KEY
```

The keys are kept outside the source code rather than committed to version control.

## Technology Stack

| Category | Technologies |
|---|---|
| Language | Java 17 |
| Backend Framework | Spring Boot 3.4.10 |
| Security | Spring Security |
| Authentication | OAuth2 Client, TOTP, Email OTP |
| Frontend | Thymeleaf |
| Database | MySQL |
| Persistence | Spring Data JPA / Hibernate |
| Cryptography | Java Cryptography Architecture |
| Encryption | AES-256-CBC |
| Message Authentication | HMAC-SHA256 |
| Password Hashing | BCrypt |
| QR Code | ZXing |
| Email | Spring Boot Starter Mail |
| Build Tool | Maven |
| Testing | JUnit / Spring Boot Test |

## Project Structure

```text
src/
├── main/
│   ├── java/
│   │   └── com/SystemAuth/loginSystem/
│   │       ├── controller/
│   │       │   ├── AuthController.java
│   │       │   └── DashboardController.java
│   │       ├── model/
│   │       │   └── User.java
│   │       ├── repository/
│   │       │   └── UserRepository.java
│   │       ├── service/
│   │       │   ├── EmailService.java
│   │       │   └── UserService.java
│   │       ├── KeyGenerator.java
│   │       ├── SecurityConfig.java
│   │       ├── TokenUtil.java
│   │       └── LoginSystemApplication.java
│   └── resources/
│       └── templates/
│           ├── Dashboard.html
│           ├── Login.html
│           ├── Register.html
│           ├── TokenDisplay.html
│           ├── Verify-otp.html
│           ├── forget-password.html
│           ├── register-totp.html
│           └── reset-password.html
└── test/
```

## Getting Started

### Prerequisites

- Java 17 or later.
- Maven.
- MySQL server.
- Google OAuth2 credentials.
- GitHub OAuth2 credentials.
- Google reCAPTCHA credentials.
- SMTP email service credentials.

### 1. Clone the repository

```bash
git clone https://github.com/Arth3rLywin/secure-authentication-system.git
cd secure-authentication-system
```

### 2. Configure environment variables

Configure the cryptographic keys:

```text
AES_SECRET_KEY=your_base64_encoded_aes_key
HMAC_SECRET_KEY=your_base64_encoded_hmac_key
```

Generate the keys using the project's key-generation utility.

### 3. Configure application properties

Create your local `src/main/resources/application.properties` file.

Configure the following:

- MySQL database URL, username, and password.
- Google OAuth2 Client ID and Client Secret.
- GitHub OAuth2 Client ID and Client Secret.
- Google reCAPTCHA credentials.
- SMTP host, username, and password.

Do not commit real credentials or cryptographic keys to the repository.

### 4. Run the application

Using Maven:

```bash
mvn spring-boot:run
```

Or on Windows using the Maven wrapper:

```bash
mvnw.cmd spring-boot:run
```

## Learning Objectives

This project explores practical backend engineering concepts:

- Authentication and authorization with Spring Security.
- Third-party OAuth2 integration.
- Multi-factor authentication workflows.
- Password hashing and account recovery.
- Custom cryptographic token design.
- Encryption, message authentication, and key management.
- Database integration with Spring Data JPA.
- Backend application security.

## Author

**San Win Htet**

GitHub: [@Arth3rLywin](https://github.com/Arth3rLywin)

---

*An educational and portfolio project focused on Java backend development, authentication, and application security.*
