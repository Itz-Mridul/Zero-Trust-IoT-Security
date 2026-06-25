#!/usr/bin/env bash
# ============================================================
#  fix_ngrok.sh — Re-authenticate ngrok and start the tunnel
#  Run: bash fix_ngrok.sh YOUR_NGROK_TOKEN
# ============================================================

TOKEN="$1"

if [ -z "$TOKEN" ]; then
    echo ""
    echo "❌ Usage: bash fix_ngrok.sh YOUR_NGROK_TOKEN"
    echo ""
    echo "   Get your token from: https://dashboard.ngrok.com/get-started/your-authtoken"
    echo "   It looks like: 2abc...xxxxx_yyy..."
    echo ""
    exit 1
fi

echo ""
echo "🔑 Setting ngrok auth token..."
ngrok config add-authtoken "$TOKEN"

echo ""
echo "🔴 Stopping any old ngrok instances..."
pkill -f ngrok 2>/dev/null
sleep 2

echo ""
echo "🚀 Starting ngrok tunnel on port 5001 (background)..."
nohup ngrok http 5001 --log=stdout > ~/ngrok.log 2>&1 &
NGROK_PID=$!
echo "   ngrok PID: $NGROK_PID"

echo ""
echo "⏳ Waiting for tunnel to establish..."
sleep 5

# Try to get URL from ngrok API
PUBLIC_URL=$(curl -s --max-time 5 http://localhost:4040/api/tunnels 2>/dev/null \
    | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    tunnels = d.get('tunnels', [])
    for t in tunnels:
        url = t.get('public_url', '')
        if url.startswith('https'):
            print(url)
            break
except:
    pass
" 2>/dev/null)

if [ -n "$PUBLIC_URL" ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  ✅ NGROK TUNNEL ACTIVE                                  ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║  🌐 PUBLIC URL: $PUBLIC_URL"
    echo "║  📊 Local:      http://192.168.1.113:5001               ║"
    echo "║  🔍 Inspector:  http://localhost:4040                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Open on any device worldwide: $PUBLIC_URL"
else
    echo ""
    echo "⚠️  Could not auto-detect URL. Check ~/ngrok.log:"
    grep -o 'https://[^ "]*' ~/ngrok.log | head -3
    echo ""
    echo "  Or open: http://localhost:4040 in a browser on the Pi"
fi
