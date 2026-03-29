# Passkey Demo Application

This is a demonstration application showcasing the implementation of **Passkeys** (WebAuthn) using Go. It features full support for modern authentication flows, including **Conditional UI** and **Discovery-based login**.

## What are Passkeys?

Passkeys are a safer and easier replacement for passwords. With passkeys, users can sign in to apps and websites with a biometric sensor (such as a fingerprint or facial recognition), PIN, or pattern, the same way they unlock their device.

### Key Features of Passkeys:
- **Phishing Resistance:** Passkeys are cryptographically bound to the website or app they were created for, making them immune to phishing.
- **No More Passwords:** Users don't need to create, remember, or manage complex passwords.
- **Cross-Device Sync:** Many passkeys (like those from Google, Apple, or Microsoft) sync across a user's devices via the cloud.
- **Discovery (Resident Keys):** Users can log in without even typing their username. The authenticator provides the user identity to the application.

## How Autodiscovery Works in This App

This application is designed to make the login experience as seamless as possible:

1.  **WebAuthn Conditional UI (Autofill):** When the user clicks on the username field, the browser will automatically suggest any available passkeys for this site in an autocomplete dropdown.
2.  **Immediate Login Prompt:** Upon loading the page, the application will proactively ask the browser to check for available passkeys. If one is found, the browser may show a "pop-up" or prompt asking if the user wants to log in with it.
    *   *Note: Many modern browsers require a direct user gesture (like a click) to show a modal WebAuthn prompt. If the automatic prompt is blocked, you can still trigger it manually via the "Discovery Login" button.*
3.  **Discovery Login:** The "Discovery Login" button allows a user to authenticate without providing a username upfront. The browser will list all passkeys available for this domain.

---

## Features: Markdown Notes

Once authenticated, users can:
- **Write and Edit Notes:** A dedicated section appears for taking notes in Markdown format.
- **Live Preview:** See how your notes look as you type, thanks to integrated markdown rendering.
- **Persistence:** Notes are securely saved in the SQLite database, tied to your user account, and only accessible after passkey authentication.

---

## Setup and Installation

### Prerequisites
- [Go](https://go.dev/dl/) 1.25 or higher.
- [Docker](https://www.docker.com/) (optional, for containerized deployment).

### Local Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd passkey-demo
    ```

2.  **Install dependencies:**
    ```bash
    go mod download
    ```

3.  **Environment Configuration:**
    Create a `.env` file or use the defaults.
    ```env
    APP_DOMAIN=localhost
    PORT=8000
    ```

4.  **Run the application:**
    ```bash
    go run .
    ```
    The application will be available at `http://localhost:8000`.

### Docker Setup

1.  **Build and run with Docker Compose:**
    ```bash
    docker-compose up --build
    ```
    This will start the application and persist the SQLite database in the `./db` directory.

---

## Testing Passkeys Locally

WebAuthn usually requires a secure context (HTTPS) or `localhost`.

1.  Open `http://localhost:8000`.
2.  Enter a username and click **Register**.
3.  Follow your browser's prompts to create a passkey (you can use your phone, security key, or built-in biometrics).
4.  Once registered, refresh the page.
5.  **Autodiscovery:** You should see an immediate prompt from your browser asking to sign in.
6.  **Conditional UI:** Click the username box; your passkey should appear in the suggestions.
7.  **Discovery Login:** Click "Discovery Login" without typing anything to sign in with your stored passkey.

## Architecture Overview

-   **Frontend:** Simple HTML/JS using `@github/webauthn-json` for easy WebAuthn API interaction.
-   **Backend:**
    -   Go 1.25
    -   `github.com/egregors/passkey`: High-level library for WebAuthn routes.
    -   `github.com/go-webauthn/webauthn`: Core WebAuthn logic.
    -   `GORM` with `sqlite`: Persistence layer (CGO-free).
-   **Database:** SQLite stored in `db/passkey.db`.

---
*Note: This is a demo project. For production use, ensure proper session management, HTTPS configuration, and secure cookie settings.*
