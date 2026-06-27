# Security Policy

## Responsible, authorized use

AuthRadar generates real HTTP traffic against its target, including optional
active probes (repeated failed logins, OTP attempts, enumeration). **Only use it
against systems you own or have explicit written authorization to test.**
Unauthorized scanning may violate computer-misuse laws.

AuthRadar is designed as a **defensive** tool: it detects misconfigurations and
weaknesses so they can be fixed. It deliberately does not implement credential
stuffing, account takeover, or other offensive automation. Active probes use a
deliberately invalid username for rate-limit testing so that real accounts are
not locked out.

## Reporting a vulnerability

If you discover a security vulnerability in AuthRadar itself, please report it
privately rather than opening a public issue:

1. Email the maintainers or use GitHub's private security advisory feature.
2. Include a description, affected versions, and reproduction steps.
3. Allow a reasonable time for a fix before public disclosure.

We aim to acknowledge reports promptly and will credit reporters who wish to be
named.

## Supported versions

AuthRadar is pre-1.0; security fixes are applied to the latest released version.
