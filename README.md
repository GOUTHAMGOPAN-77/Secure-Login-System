# Secure Login System

A full-stack Node.js login system that satisfies every security requirement:

| Requirement | Implementation |
|---|---|
| Hashed passwords (bcrypt/Argon2) | **bcrypt** with 12 salt rounds |
| SQL injection protection | Parameterised-style key lookups (swap-in PostgreSQL/MySQL with `?` placeholders) |
| Input validation | Server-side regex validation on all fields |
| Session management + logout | **express-session** — server-side, httpOnly cookie |
| Two-Factor Authentication (2FA) | **TOTP** via speakeasy — works with Google Authenticator, Authy, 1Password |

## Tech stack

- **Runtime**: Node.js
- **Framework**: Express
- **Password hashing**: bcrypt (12 rounds)
- **Sessions**: express-session (server-side, httpOnly, sameSite: strict)
- **2FA**: speakeasy (RFC 6238 TOTP) + qrcode
- **Security headers**: helmet
- **Rate limiting**: express-rate-limit (10 attempts / 15 min per IP)
- **Storage**: JSON file (swap with PostgreSQL/MySQL for production)

## Getting started

```bash
npm install
node server.js
# Open http://localhost:3000
```

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/register` | Create account |
| POST | `/api/login` | Login (returns `requires2fa: true` if TOTP enabled) |
| POST | `/api/login/2fa` | Complete login with TOTP code |
| POST | `/api/logout` | Destroy session |
| GET  | `/api/me` | Get current user (requires auth) |
| POST | `/api/2fa/setup` | Generate TOTP secret + QR code |
| POST | `/api/2fa/verify` | Verify and activate 2FA |

## Security features

- **bcrypt** — passwords are hashed with 12 rounds before storage; plain-text is never saved
- **Timing-safe login** — bcrypt runs even for non-existent usernames to prevent user enumeration
- **Server-side sessions** — session data lives on the server; only a signed cookie ID is sent to the browser
- **httpOnly cookies** — JavaScript cannot read the session cookie
- **SameSite: strict** — CSRF protection
- **Rate limiting** — brute-force protection on the login endpoint
- **Helmet** — sets 11 security-hardening HTTP headers
- **Input validation** — username, email, and password rules enforced server-side
- **XSS prevention** — all user content is HTML-escaped before rendering
- **2FA pending state** — session is only created after TOTP verification when 2FA is enabled

## Moving to production

1. Set `SESSION_SECRET` as an environment variable
2. Enable `cookie.secure = true` (requires HTTPS)
3. Replace the JSON file DB with PostgreSQL using `pg` and parameterised queries:
   ```js
   await db.query('SELECT * FROM users WHERE username = $1', [username])
   ```
4. Set `NODE_ENV=production`
