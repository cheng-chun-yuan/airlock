#!/usr/bin/env bash
# End-to-end smoke test against a running gateway (mock World ID + static registry).
set -euo pipefail
GW=${GW:-http://localhost:8787}
PROMPT=$(node -e 'console.log(JSON.stringify("Review this contract, list the riskiest clauses:\n\n"+require("fs").readFileSync("demo/contract.md","utf8")))')
body() { echo "{\"model\":\"airlock/claude-sonnet-5\",\"messages\":[{\"role\":\"user\",\"content\":$PROMPT}]}"; }
pending() { for _ in $(seq 1 40); do id=$(curl -s "$GW/approvals?status=pending" | node -e 'const a=JSON.parse(require("fs").readFileSync(0));process.stdout.write(a[0]?.id??"")'); [ -n "$id" ] && { echo "$id"; return; }; sleep 0.25; done; echo "no pending approval" >&2; exit 1; }
summary() { node -e 'const j=JSON.parse(require("fs").readFileSync(0));const a=j.airlock;console.log(`  → decision=${a.decision} egressed=${a.egressed} class=${a.sourceClass} entities=${JSON.stringify(a.entities)} reason=${a.reason??""}`)'; }
verify() { curl -s -X POST "$GW/approvals/$1/verify" -H content-type:application/json -d "{\"mock\":true,\"nullifier\":\"$2\",\"approverName\":\"$3\"}" | node -e 'const d=JSON.parse(require("fs").readFileSync(0));console.log(`  verify: ${d.status} roleCheck=${d.roleCheck??"-"} ${d.reason??""}`)'; }

run() { # $1=label, $2=action...
  echo "== $1"
  body | curl -s "$GW/v1/chat/completions" -H content-type:application/json -H "x-airlock-session: smoke-$RANDOM" -d @- > /tmp/airlock-smoke.json &
  local pid=$!; local id; id=$(pending); echo "  pending approval $id"
  "${@:2}" "$id"; wait $pid; summary < /tmp/airlock-smoke.json
}
approve_alice() { verify "$1" 0x0a11ce alice.legal.approvers.acme.eth; }
deny() { curl -s -X POST "$GW/approvals/$1/deny" -H content-type:application/json -d '{}' >/dev/null; echo "  denied"; }
mallory() { verify "$1" 0x0bad mallory.legal.approvers.acme.eth; }

run "1. approve (alice, valid ENS role)" approve_alice
run "2. deny" deny
run "3. real human, not an approver (mallory)" mallory
curl -s -X POST "$GW/admin/revoke" -H content-type:application/json -d '{"approverName":"alice.legal.approvers.acme.eth"}' >/dev/null; echo "== revoked alice"
run "4. approve after revocation (alice)" approve_alice
echo "== audit"; curl -s "$GW/audit" | node -e 'const a=JSON.parse(require("fs").readFileSync(0));console.log(`  records=${a.records.length} chain=${JSON.stringify(a.chain)} root=${a.merkleRoot}`)'
