# Check catalogue

Each finding carries a stable `id`, a `severity`, a `confidence`, one or more
CWE references, and remediation guidance. Checks marked **active** only run when
`--active` (`active_probes`) is enabled and the required inputs (credentials,
protected path) are supplied.

## Transport & login (`login_detector`)

| ID | Severity | Mode | Description |
| --- | --- | --- | --- |
| `AR-LOGIN-001` | High | passive | Login form is served or submitted over cleartext HTTP (CWE-319). |
| `AR-LOGIN-002` | High | passive | Login form uses the GET method, placing credentials in the URL (CWE-598). |

## Cookies & session (`session_checker`)

| ID | Severity | Mode | Description |
| --- | --- | --- | --- |
| `AR-COOKIE-001` | Medium | passive | Session/auth cookie missing `Secure` (CWE-614). Reported only when the target is HTTPS. |
| `AR-COOKIE-002` | Medium | passive | Session/auth cookie missing `HttpOnly` (CWE-1004). CSRF cookies are excluded. |
| `AR-COOKIE-003` | Low | passive | Session/auth cookie missing `SameSite` (CWE-1275). |
| `AR-COOKIE-004` | Medium | passive | Cookie uses `SameSite=None` without `Secure` (CWE-1275). |
| `AR-SESSION-001` | High | active | Session identifier not rotated after login — session fixation (CWE-384). |
| `AR-SESSION-002` | High | active | Session still valid after logout — broken logout invalidation (CWE-613). |

## CSRF (`csrf_auth_analyzer`)

| ID | Severity | Mode | Description |
| --- | --- | --- | --- |
| `AR-CSRF-001` | Medium | passive | State-changing auth form (POST) without an anti-CSRF token and without a `SameSite=Lax/Strict` session cookie (CWE-352). |

## JWT & token storage (`jwt_analyzer`)

| ID | Severity | Mode | Description |
| --- | --- | --- | --- |
| `AR-JWT-001` | Critical | passive | JWT accepts the `none` algorithm — unsigned, forgeable (CWE-347). |
| `AR-JWT-002` | Medium | passive | JWT has no `exp` claim (CWE-613). |
| `AR-JWT-003` | Medium | passive | JWT lifetime exceeds the recommended maximum (CWE-613). |
| `AR-JWT-004` | High | passive | JWT payload carries sensitive claims (passwords, PII) (CWE-522). |
| `AR-JWT-005` | Medium | passive/browser | Auth token/JWT stored in `localStorage` (CWE-922). |
| `AR-JWT-006` | Low | passive/browser | Auth token/JWT stored in `sessionStorage` (CWE-922). |
| `AR-JWT-007` | Medium | passive | JWT leaked in a URL (CWE-598). |

## Rate limiting (`rate_limit_tester`)

| ID | Severity | Mode | Description |
| --- | --- | --- | --- |
| `AR-RATE-001` | High | active | Login endpoint shows no rate limiting / lockout after repeated failures (CWE-307, CWE-799). Probing uses a deliberately invalid username so real accounts are not locked. |

## OTP (`otp_analyzer`)

| ID | Severity | Mode | Description |
| --- | --- | --- | --- |
| `AR-OTP-001` | Medium | passive | One-time password is too short (small keyspace) (CWE-307). |
| `AR-OTP-002` | High | active | OTP verification lacks rate limiting — OTP brute force (CWE-307). |

## Password reset (`reset_flow_analyzer`)

| ID | Severity | Mode | Description |
| --- | --- | --- | --- |
| `AR-RESET-001` | High | passive | Weak reset token: low keyspace or low character diversity (CWE-330, CWE-640). |
| `AR-RESET-002` | High | analyzer | Reset token can be replayed after use (CWE-640). |
| `AR-RESET-003` | Medium | analyzer | Reset token is long-lived (CWE-640). |
| `AR-RESET-004` | High | passive | Reset tokens are sequential/predictable (CWE-340). |

> `AR-RESET-002` and `AR-RESET-003` are exposed as pure analyzer functions for
> use when token reuse/TTL data is available (for example via a custom plugin or
> integration test); the built-in scanner passively analyses any reset tokens it
> observes in URLs.

## Account enumeration (`account_enum_detector`)

| ID | Severity | Mode | Description |
| --- | --- | --- | --- |
| `AR-ENUM-001` | Medium | active | The application responds differently to a valid vs invalid identifier (status, body length, wording, or timing), enabling account enumeration (CWE-204). |

## MFA (`mfa_validator`)

| ID | Severity | Mode | Description |
| --- | --- | --- | --- |
| `AR-MFA-001` | Critical | active | Protected resource reachable after only the first factor — MFA bypass (CWE-287, CWE-306). |
| `AR-MFA-002` | High | active | MFA step accepts an empty/invalid code (CWE-287). |
