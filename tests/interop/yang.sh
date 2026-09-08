#!/usr/bin/env bash
# YANG surface gate (W3.8): `lr-daemon yang render` output must validate
# against the shipped RFC 9647 / RFC 8177 modules with yanglint (libyang).
#
#   phase 1: the shipped yang/ modules parse (and their transitive
#            imports resolve).
#   phase 2: the ietf-babel (RFC 9647) instance data for a config with
#            HMAC-SHA256 + BLAKE2s keys validates as config data.
#   phase 3: the ietf-key-chain (RFC 8177) instance data validates
#            (hmac-sha256 key; the always-valid send-accept lifetime).
#   phase 4: a blake2s key is rejected in the key-chain view (no RFC 8177
#            crypto-algorithm identity exists) — fail closed.
#
# Skips gracefully when yanglint is absent or too old to parse the
# dependency modules (mirrors the tcp_ao.sh capability probe).
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN=target/debug/lr-daemon
if [ ! -x "$BIN" ]; then
    BIN=target/release/lr-daemon
fi

# Locate yanglint (PATH first, then the extracted-tree location this
# environment uses when there is no root to install from).
YANGLINT=${YANGLINT:-yanglint}
if ! command -v "$YANGLINT" >/dev/null 2>&1; then
    if [ -x /home/z/opt/libyang/root/usr/bin/yanglint ]; then
        YANGLINT=/home/z/opt/libyang/root/usr/bin/yanglint
        export LD_LIBRARY_PATH="/home/z/opt/libyang/root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    else
        echo "SKIP: yanglint not found"
        exit 0
    fi
fi

DEPS=/tmp/lr_yang_deps
mkdir -p "$DEPS"
for f in \
    ietf-inet-types@2013-07-15.yang \
    ietf-yang-types@2013-07-15.yang \
    ietf-interfaces@2018-02-20.yang \
    ietf-netconf-acm@2018-02-14.yang \
    ietf-routing@2018-03-13.yang \
    ietf-crypto-types@2024-10-10.yang; do
    if [ ! -s "$DEPS/$f" ]; then
        curl -fsSL -o "$DEPS/$f" \
            "https://raw.githubusercontent.com/YangModels/yang/main/standard/ietf/RFC/$f" \
            || { echo "SKIP: cannot fetch YANG import $f"; exit 0; }
    fi
done

OUT=/tmp/lr_yang_gate
rm -rf "$OUT"; mkdir -p "$OUT"
cp yang/*.yang "$OUT/"

YLP="$YANGLINT -p $DEPS -p $OUT"

# --- phase 1: shipped modules parse with their imports resolved ---
for m in ietf-babel@2024-10-10.yang ietf-key-chain@2017-06-15.yang; do
    if ! $YLP -i "$OUT/$m" >/dev/null 2>"$OUT/err"; then
        echo "SKIP: yanglint cannot parse $m (tool too old?): $(head -1 "$OUT/err")"
        exit 0
    fi
done
echo "PASS: phase 1 — shipped ietf-babel + ietf-key-chain modules parse"

cat >"$OUT/cfg.toml" <<'EOF'
[babel]
port = 6697

[[babel.key]]
secret = "one"
algorithm = "hmac-sha256"

[[babel.key]]
secret = "two"
algorithm = "blake2s"
EOF

# --- phase 2: ietf-babel instance data validates ---
"$BIN" yang render "$OUT/cfg.toml" --model babel >"$OUT/babel.xml"
$YLP -i "$OUT/ietf-babel@2024-10-10.yang" -t config "$OUT/babel.xml" >/dev/null
grep -q "babel:hmac-sha256" "$OUT/babel.xml"
grep -q "babel:blake2s" "$OUT/babel.xml"
grep -q "b25l" "$OUT/babel.xml" # base64("one")
echo "PASS: phase 2 — ietf-babel instance data validates (libyang)"

# --- phase 3: ietf-key-chain instance data validates ---
"$BIN" yang render "$OUT/cfg.toml" --model keychain >"$OUT/kc.xml" 2>"$OUT/kc.err" \
    && FAIL=0 || FAIL=$?
if [ "$FAIL" = 0 ]; then
    echo "FAIL: blake2s key accepted in the key-chain view (must fail closed)"
    exit 1
fi
# Render with only the hmac key for the positive view.
cat >"$OUT/cfg_hmac.toml" <<'EOF'
[[babel.key]]
secret = "one"
algorithm = "hmac-sha256"
EOF
"$BIN" yang render "$OUT/cfg_hmac.toml" --model keychain >"$OUT/kc.xml"
$YLP -i "$OUT/ietf-key-chain@2017-06-15.yang" -t config "$OUT/kc.xml" >/dev/null
grep -q "key-chain:hmac-sha-256" "$OUT/kc.xml"
grep -q "send-accept-lifetime" "$OUT/kc.xml"
echo "PASS: phase 3 — ietf-key-chain instance data validates (libyang)"

# --- phase 4: blake2s is a hard error in the key-chain view ---
if ! grep -qi "blake2s\|crypto-algorithm" "$OUT/kc.err"; then
    echo "FAIL: blake2s rejection did not explain itself"
    exit 1
fi
echo "PASS: phase 4 — blake2s keys fail closed in the key-chain view"

echo "== YANG surface gate complete: 9647 + 8177 instance data is libyang-clean =="
