# WARP AmneziaWG Config Generator

Generate AmneziaWG configs for Cloudflare WARP — **consumer mode by default**, with optional **Zero Trust** enrollment.

Keys are generated per request. Nothing is stored on the server.

## Features

- **Consumer WARP** (default): registers a free WARP device via the public Cloudflare API — no login required
- **Zero Trust** (optional): enroll via your organization's Cloudflare Access portal
  - Portal URL + email OTP, or paste a JWT manually
- AmneziaWG obfuscation (I1 QUIC packet)
- All-traffic routing with IPv6 enabled by default
- Split tunnel with AllowedIPs calculator
- Endpoint modes: default IPv4, peer IPv6, NAT64

## Quick start

Requires **Node.js 18+** (uses native `fetch` and Web Crypto).

```bash
git clone <your-repo-url>
cd warp-amnezia-generator
npm start
```

Open http://localhost:3000

## Deploy from GitHub

This app needs a small Node.js backend (Cloudflare API calls and OTP flow cannot run from static GitHub Pages alone).

Deploy the repository to any Node.js host:

| Platform | Notes |
|----------|-------|
| [Railway](https://railway.app) | Connect repo, set start command `npm start` |
| [Render](https://render.com) | Web Service, build: `npm install`, start: `npm start` |
| [Fly.io](https://fly.io) | `fly launch` then `fly deploy` |
| VPS / Docker | Run `node server.mjs`, set `PORT` env var |

Set the `PORT` environment variable if your host requires a specific port.

### GitHub Actions CI

The included workflow verifies the server starts successfully on every push.

## Project structure

```
warp-amnezia-generator/
├── server.mjs           # HTTP server + API routes
├── lib/
│   ├── x25519.mjs       # WireGuard key generation
│   ├── cidr.mjs         # AllowedIPs calculator
│   ├── quic-i1.mjs      # AmneziaWG I1 obfuscation packet
│   ├── warp-api.mjs     # Cloudflare WARP registration
│   ├── access-otp.mjs   # Zero Trust portal OTP flow
│   └── config-builder.mjs
└── public/              # Static UI
    ├── index.html
    ├── styles.css
    └── app.js
```

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/generate` | Register device and build config |
| `POST` | `/api/calc` | Preview AllowedIPs (no registration) |
| `POST` | `/api/otp/start` | Send email OTP (Zero Trust) |
| `POST` | `/api/otp/complete` | Verify OTP, return JWT |
| `POST` | `/api/otp/refresh` | Refresh short-lived JWT |
| `POST` | `/api/revoke` | Delete device registration |

## Security

- Private keys exist only in memory for the duration of one request
- No logging or persistence of tokens or keys
- Zero Trust portal URL is stored only in the user's browser (`localStorage`)

## Credits

- [warp.sh](https://gitlab.com/fscarmen/warp)
- [rany2/warp.sh](https://github.com/rany2/warp.sh)
- [warp-generator](https://github.com/warp-generator/warp-generator.github.io)
- [ImMALWARE/bash-warp-generator](https://github.com/ImMALWARE/bash-warp-generator) — consumer WARP registration flow
- [WireGuard AllowedIPs calculator](https://www.procustodibus.com/blog/2021/03/wireguard-allowedips-calculator/)

## License

MIT
