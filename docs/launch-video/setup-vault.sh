#!/bin/sh
# Creates a fresh demo vault, starts `ven ui` on 127.0.0.1:7420 and prints the launch URL.
# The vault lives in $VEN_DEMO_DIR (shown on the dashboard's Settings page).
set -e
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
V="$ROOT/bin/ven"
D=${VEN_DEMO_DIR:-$HOME/.local/share/ven-demo}
mkdir -p "$D"; cd "$D"
rm -f vault.db vault.db-wal vault.db-shm ui.log ui.pid
export VEN_VAULT="$D/vault.db"; PW='correct-horse-battery'
printf '%s\n' "$PW" | "$V" --password-stdin init >/dev/null 2>&1
"$V" projects create "Billing API" --description "Payments and invoicing service" >/dev/null 2>&1
"$V" projects create "Web App" --description "Next.js storefront" >/dev/null 2>&1
"$V" projects create "Auth Service" --description "OAuth and sessions" >/dev/null 2>&1
cat > dev.env <<'X'
DATABASE_URL=postgres://billing:s3cr3t@db.internal:5432/billing
STRIPE_SECRET_KEY=sk_live_51NzQ8vKp2mXy7RtLb9eWq
STRIPE_WEBHOOK_SECRET=whsec_9fJ2kLm4nPq8rStUvWx
REDIS_URL=redis://cache.internal:6379/0
JWT_SIGNING_KEY=a8f3c91e7d2b4605f8e1c3a9b7d24e6f
SENTRY_DSN=https://4f2a@o12345.ingest.sentry.io/678
LOG_LEVEL=info
PORT=8080
X
sed -e 's/billing:s3cr3t@db.internal/billing:Pr0d-9xQ2@db-prod.internal/' -e 's/LOG_LEVEL=info/LOG_LEVEL=warn/' -e 's/7RtLb9eWq/Hq4ZtW2nVc/' dev.env > prod.env
grep -v SENTRY dev.env | sed 's/db.internal/db-staging.internal/' > staging.env
printf 'NEXT_PUBLIC_API_URL=https://api.example.com\nNEXTAUTH_SECRET=Qm9vdHN0cmFwU2VjcmV0S2V5MTIz\nNEXTAUTH_URL=http://localhost:3000\nSTRIPE_PUBLISHABLE_KEY=pk_live_51NzQ8vKp2mXyAbCd\n' > web.env
printf 'OAUTH_CLIENT_ID=ven-auth-7731\nOAUTH_CLIENT_SECRET=gho_Zx81Lq0pRt5sVb\nSESSION_TTL=3600\n' > auth.env
imp() { printf '%s\n' "$PW" | "$V" --password-stdin import "$1" -p "$2" -e "$3" --yes >/dev/null 2>&1; }
imp dev.env billing-api development; imp staging.env billing-api staging; imp prod.env billing-api production
imp web.env web-app development; imp web.env web-app production; imp auth.env auth-service development
rm -f dev.env prod.env staging.env web.env auth.env
"$V" ui --no-browser --port 7420 > ui.log 2>&1 &
echo $! > ui.pid
for i in 1 2 3 4 5 6 7 8 9 10; do grep -q launch= ui.log 2>/dev/null && break; sleep 0.3; done
echo "$D/ui.pid"
grep -o 'http://127[^ ]*#launch=[a-f0-9]*' ui.log
