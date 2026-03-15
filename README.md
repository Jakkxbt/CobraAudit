# CobraAudit

**Bug bounty audit framework** — three focused modules for common vulnerability classes.

```
  ╔═╗╔═╗╔╗ ╦═╗╔═╗  ╔═╗╦ ╦╔╦╗╦╔╦╗
  ║  ║ ║╠╩╗╠╦╝╠═╣  ╠═╣║ ║ ║║║ ║
  ╚═╝╚═╝╚═╝╩╚═╩ ╩  ╩ ╩╚═╝═╩╝╩ ╩
```

## Modules

| Module | What it tests |
|--------|--------------|
| `apikeys` | Stripe, SendGrid, GitHub, Slack, Mailgun, Firebase, NPM, AWS, Shopify, Twilio |  
| `oauth` | Implicit flow, PKCE enforcement, state parameter, redirect URI bypass |
| `pwreset` | Host header injection, username enumeration, rate limiting |

## Installation

```bash
pip install -e .
```

After install, `cobraaudit` is available globally.

## Usage

```bash
# Test a single API key
cobraaudit apikeys --key sk_live_xxxx

# Scan a file for API keys (e.g. NextRecon JS output)
cobraaudit apikeys --file output.js

# Scan a live URL for embedded keys
cobraaudit apikeys --target https://target.com/app.js

# OAuth audit
cobraaudit oauth --target https://target.com
cobraaudit oauth --target https://target.com --client-id myapp

# Password reset audit
cobraaudit pwreset --target https://target.com --email test@target.com
cobraaudit pwreset --target https://target.com --email test@target.com --reset-endpoint /forgot-password

# Run all modules
cobraaudit all --target https://target.com --email test@target.com
```

## Notes

- Host header injection in `pwreset` requires Burp Collaborator or [interactsh](https://github.com/projectdiscovery/interactsh) to confirm callback in reset email.
- OAuth tests work best with a known `--client-id` — without one, results may be inconclusive.
- Always test against in-scope targets only.
