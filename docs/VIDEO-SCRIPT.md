# Demo video script (narration)

Record your own voice over the cut demo (3:43, 1080p, no audio). ETHGlobal rules: 2–4 minutes, at least 720p, **your own narration**: no text-to-speech, no AI voiceover, no music, and no speed-up.

The intro and outro are spoken over the first and last seconds of the video, so the total stays 3:43. Don't add title cards longer than 15 s in total, or you'll pass 4:00. Timecodes are positions in the cut video; the `→` notes say what is on screen. Speak at a relaxed pace; the lines are sized to fit.

The cut removes only idle waiting (the Sepolia transaction during Revoke, 1:32). Nothing is sped up.

---

**[0:00 · Intro · over Overview]** → live status of every dependency
> This is Airlock, the human-consent gateway for AI agents. Agents leak confidential data the moment they call a frontier model. Airlock is the airlock between them.

**[0:08 · 01 Public]** → *Public question* → SENT AUTOMATICALLY
> An agent talks to Airlock like any OpenAI endpoint. A public question has nothing sensitive in it, so it goes straight out, and it's still audited.

**[0:17 · 02 Confidential]** → held at the door → *As the model sees it* → hold → World ID (0:37) → CLEARED (0:44)
> Now a confidential contract review. Airlock de-identifies names, money and email into labels. I can read them here, but the model only ever sees ORG-1 and PERSON-1. A local model already tried to re-identify them and failed, so risk is low. The policy comes from ENS: legal has to approve. I hold, and verify with World ID for Agents. Approved. Only the labels left the building, and the answer streams back with the real names restored.

**[0:56 · 03 Seal]** → note → Seal → NOT SENT, local model answers
> Same request, but this time I seal it, with a note. Nothing leaves. The local model answers instead, and the employee sees why.

**[1:19 · 04 Revoked]** → Approvers → Revoke on ENS → REVOKED (1:34) → approve as carol (1:53) → ROLE CHECK FAILED
> Carol is an approver. I revoke her ENS subname on Sepolia. It's one transaction, and MultiBaas pushes the event to the gateway right away. Now she tries to approve. She's still a verified human, but her role is gone, so nothing is sent.

**[2:05 · 05 Two humans]** → *Client pricing* → risk high, needs 2 → bob ✓ 1 of 2 (2:19) → alice, same World ID (2:32) → NOT COUNTED (2:36)
> Here the name TSMC is hidden, but the context gives it away, and our re-identification test catches it. High risk means the ENS policy requires two different humans. Bob approves: one of two. Now I try again as "Alice", with the same World ID, and it's refused. World ID knows it's the same person, without knowing who. An account system can't do that without KYC. Only a second, different human can release it.

**[2:43 · 06 New agent]** → agent `intern-bot` → NOT SENT, exceeds maxClass=internal
> A brand-new agent that nobody registered gets the org's default policy through ENSv2 wildcard resolution. Confidential data is blocked, with zero setup.

**[2:59 · 07 Proof]** → Agents (policy, access matrix) → Audit (3:16) → Verify chain → Anchor to ENS (3:25)
> Everything is on the record. Agents link to one shared policy record, so you edit it once and all of them change. Only the security key can change policy; the gateway can only write approvers and the audit root. MultiBaas shows every on-chain change, and every decision is hash-chained and anchored to ENS.

**[3:36 · Outro · over the anchored ledger]**
> Airlock. Frontier AI for power. Humans for consent. Blockchain for certainty.

---

## New segments to record (self-serve + agents)

The product changed after the cut above: you sign in with a wallet (no access token), anyone creates their own gateway, and admins assign each member an agent. Record these as new screen footage, then splice them in **after 05 Two humans, replacing 06 New agent**. Durations are estimates at the same relaxed pace; the timecodes above stay as-is until you re-cut.

**[A · 38 s (recorded) · Sign in + create gateway]** → Sign in with wallet (signature, no gas) → *Create gateway* `kestrel-legal` → `kestrel-legal.airlock.eth` registered on Sepolia, owner = your wallet → Models: local endpoint + frontier key
> Anyone can run their own Airlock. I sign in with my wallet, just a signature. I create kestrel-legal, and it's registered as kestrel-legal.airlock.eth on Sepolia, owned by my wallet. Then I plug in my own local and frontier models.

**[B · 86 s (recorded; trim to fit) · Invite + assign agent → blocked]** → Manage › Members: invite link, role *member* → intern's API key → Manage › Agents & policy: agent `intern-bot` → 🔗 `strict.policy.kestrel-legal.airlock.eth` (maxClass=internal), wallet signs one tx → Manage › Members: intern runs as `intern-bot` → intern sends *Contract review* → NOT SENT, "confidential exceeds intern-bot… maxClass=internal" → Audit row shows agent `intern-bot`
> I invite an intern with a one-time link, and they get their own API key. On ENS, I link the intern-bot agent to our strict policy: one transaction, signed by my wallet. Then I assign the intern to intern-bot. They send a confidential contract. Blocked, and the audit records which agent it ran as.

**[C · optional · ~12 s · Owner-signed policy change]** → edit `strict` policy → wallet prompt → receipt checked → saved
> After setup, the platform hands the gateway over. A policy change is a transaction my wallet signs. The platform can't rewrite it.

### Cuts to stay under 4:00

New footage adds ~45 s (A + B), or ~57 s with C. These cuts to the existing cut save ~48 s:

| Cut | Where | Saves | Narration change |
|---|---|---|---|
| Drop **06 New agent** | 2:43–2:59 | 16 s | Delete the line; B shows agents better (wildcard default → assigned agent → blocked). |
| Trim **03 Seal** to the note + NOT SENT | 0:56–1:19 → ~10 s | 13 s | Keep only: "Or I seal it, with a note. Nothing leaves; the local model answers." |
| Trim the **07 Proof** Agents page, keep Audit | 2:59–3:16 → ~5 s | 12 s | Replace the first three sentences with: "Everything is on the record." Keep the MultiBaas / hash-chain / anchor sentence. The "only the security key can change policy" point moves to C (or drop it if C isn't recorded). |
| Trim the idle gap in **04 Revoked** | 1:34–1:53 → ~12 s | 7 s | None; the line already fits. |

Resulting order and approximate timecodes:

| Segment | Start | Length |
|---|---|---|
| Intro | 0:00 | 8 s |
| 01 Public | 0:08 | 9 s |
| 02 Confidential | 0:17 | 39 s |
| 03 Seal (trimmed) | 0:56 | 10 s |
| 04 Revoked (trimmed) | 1:06 | 39 s |
| 05 Two humans | 1:45 | 38 s |
| **A** Create gateway | 2:23 | 20 s |
| **B** Assign agent → blocked | 2:43 | 25 s |
| **C** Owner-signed policy (optional) | 3:08 | 12 s |
| 07 Proof (trimmed) | 3:20 | 25 s |
| Outro | 3:45 | 7 s |
| **Total** | | **3:52** with C, **3:40** without |

If a take runs long, drop C first. Don't go past ~3:55; you need headroom under 4:00. Once re-cut, update line 5 above (total length) and the timecodes.

---

## Recording tips
- Record the voice in one take while watching the video (QuickTime, OBS or iMovie), then mux it onto the mp4. No background music.
- Read slightly slower than feels natural; each result stays on screen for a few seconds, and that's where the key line should land.
- If a line runs long, drop the second sentence rather than rushing. The on-screen result carries it.
