# RemotePiAgent

A small, hardened HTTPS service that lets you securely send prompts to the local
`pi` agent on a Windows server from anywhere — a rescue channel for when RDP is
down. Works from any browser or `curl`.

## Security model

| Layer | Implementation |
|---|---|
| Transport | HTTPS only (TLS). Uses a cert from the LocalMachine store via `CertThumbprint`, or falls back to a temporary self-signed cert. |
| Login | Username + password (**Argon2id**, 64 MB / 3 iter) + **TOTP** 6-digit code (RFC 6238, Microsoft/Google Authenticator compatible, ±1 step tolerance) |
| Brute force | 5 failed logins → 15-minute lockout per IP (configurable) |
| Session | HMAC-SHA256-signed bearer token, 15-min expiry, constant-time validation |
| Injection safety | Prompt is passed to the pi process as a **single argv argument** — never through a shell — so shell metacharacters can't execute anything |
| Abuse limits | 64 KB max request body, prompt length cap, hard command timeout with process-tree kill, output size cap |
| Audit | Every login/run/error is written to `audit.log` (IP, action, result; never secrets) |

## Setup (on the server)

```powershell
# 1. Generate each secret
RemotePiAgent.exe --hash-password "YourStrongPassword!"
RemotePiAgent.exe --gen-totp        # put the Base32 secret in Authenticator ("manual entry")
RemotePiAgent.exe --gen-tokenkey

# 2. Fill in appsettings.json (Auth section + Username, PiExecutable path to pi)
# 3. (optional, recommended) Reuse your IIS HTTPS cert:
#    Get the thumbprint:
Get-ChildItem Cert:\LocalMachine\My | Format-List Subject, Thumbprint, NotAfter
#    ...and set CertThumbprint in appsettings.json. Then import that cert on your
#    client (or trust it) to get green-padlock TLS.

# 4. Open the firewall (restrict source IP if you can!)
New-NetFirewallRule -DisplayName "RemotePiAgent" -Direction Inbound -LocalPort 45454 -Protocol TCP -RemoteAddress <YOUR_HOME_IP> -Action Allow

# 5. Run as a Windows service (auto-start after reboots/updates)
sc.exe create RemotePiAgent binPath= "D:\Projects\RemotePiAgent\bin\Release\net10.0\RemotePiAgent.exe" start= auto obj= LocalSystem
sc.exe description RemotePiAgent "Secure HTTPS bridge to local pi agent"
sc.exe failure RemotePiAgent reset= 86400 actions= restart/5000/restart/5000/restart/10000
sc.exe start RemotePiAgent
```

## Usage (from home)

Open `https://<server-ip>:45454/` in a browser — the built-in client page has
login (password + Authenticator code) and a prompt box. Tokens last 15 minutes.

Or with curl:

```bash
# login (totp = current 6-digit code from Authenticator)
curl -k https://SERVER:45454/api/auth/login -d '{"username":"you","password":"...","totp":"123456"}'

# send a prompt to pi
curl -k https://SERVER:45454/api/agent/run \
  -H "Authorization: Bearer TOKEN" \
  -d '{"prompt":"check why the RDP listener is not accepting connections and fix it"}'
```

Endpoints: `GET /health` (no auth), `POST /api/auth/login`, `POST /api/agent/run` (Bearer token), `GET /` (client page).

## Notes

- `PiExecutable` must resolve on the server (full path is safest, e.g. `C:\Program Files\pi\pi.exe`).
- The pi agent runs as LocalSystem when launched by the service — it can fix
  system things, but that also means anyone with valid credentials + a working
  TOTP code gets that power. Keep the password strong and the TOTP secret private.
- If RDP keeps breaking after Windows Updates, ask pi to check the Remote
  Desktop Services listener and the Schannel event log (Event ID 36869/36871).
