# unline

Self-hostable wrapper for the LINE web client assets.
セルフホスト可能なLINEのWebクライアント

## Docker Quick Start

```bash
gh repo clone EdamAme-x/unline
cd unline
UNLINE_SETUP_UID=$(id -u) UNLINE_SETUP_GID=$(id -g) docker compose run --rm setup
docker compose up -d --build unline
```

Open `http://127.0.0.1:8080`.

If `8080` is already in use:

```bash
UNLINE_HOST_PORT=18080 docker compose up -d --build unline
```

`setup` first asks `Enable access authentication? (y/n) => `. If you answer `y`, it asks for an access key twice and writes `.env` with only a salted PBKDF2-SHA256 hash. If you answer `n`, access authentication stays disabled. `.env` is gitignored.

If you expose it behind a reverse proxy, edit `.env` and set the exact public host:

```bash
UNLINE_ALLOWED_HOSTS=chat.example.com,localhost
```

## Docker Build

```bash
docker compose build
docker compose up -d unline
```

The compose file binds to `127.0.0.1`, runs as a non-root user, drops Linux capabilities, sets `no-new-privileges`, and mounts the container root filesystem read-only.

Build-time asset knobs:

```bash
docker compose build \
  --build-arg UNLINE_EXTENSION_ID=ophjlpahpchlmihnnnihgmmeilfjmjjc \
  --build-arg UNLINE_PROD_VERSION=120.0.6099.109
```

## Runtime Settings

Useful `.env` values:

```bash
UNLINE_ADDR=127.0.0.1:8080
UNLINE_ASSETS_DIR=./www
UNLINE_ALLOWED_HOSTS=localhost,127.0.0.1,::1
UNLINE_FORWARD_COOKIES=false
UNLINE_FORWARD_AUTHORIZATION=false
UNLINE_BASIC_AUTH_USERNAME=unline
UNLINE_BASIC_AUTH_PASSWORD_HASH=pbkdf2-sha256:...
UNLINE_BASIC_AUTH_REALM=unline
```

Only enable `UNLINE_FORWARD_COOKIES` or `UNLINE_FORWARD_AUTHORIZATION` if a future LINE asset version proves it is required. When access authentication is enabled, the incoming `Authorization` header is consumed by unline and is not forwarded to LINE upstreams.

## Go Development Commands

Normal users should use Docker. These commands are for local development only.

```bash
go run ./cmd/unline setup --out .env
set -a; . ./.env; set +a
go run ./cmd/unline generate --out ./www
go run ./cmd/unline verify --assets ./www
go run ./cmd/unline serve --assets ./www --allowed-hosts localhost,127.0.0.1,::1
```

## Secret Scanning

Hooks use `gitleaks`; install it before committing:

```bash
go install github.com/zricethezav/gitleaks/v8@v8.24.3
scripts/install-githooks.sh
```

## GitHub

This project is intended to live in the private repository:

```bash
gh repo view EdamAme-x/unline --json name,visibility,url
git remote add origin git@github.com:EdamAme-x/unline.git
git push -u origin main
```

## Generated Patches

The Docker build and `generate` command download the LINE Chrome extension package, extract it, then apply these patches:

- Rewrites LINE API calls to same-origin `/_proxy/...` routes.
- Preserves the Chrome extension origin constant where the client expects it.
- Disables known Sentry telemetry literals.
- Injects `Powered by unline` with a link to `https://github.com/EdamAme-x/unline`.
- Hardens the generated `manifest.json` so wildcard host permissions are not left behind.

`verify` checks those artifacts directly and fails on missing patches, direct upstream literals, telemetry host literals, or wildcard extension host permissions.
