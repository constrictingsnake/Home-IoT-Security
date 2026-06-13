# Difference-Set Classification Rubric (shared by all three AI reviewers)

This is the **single source of truth** every reviewer follows — Claude Code (manual),
Codex (manual), and Gemini (API). Judge identically so the triple-check is meaningful.

## Your task
You are given one CVE (description + CPE strings) and one **device category**. Decide
whether the CVE genuinely affects a **home IoT device** of that category, or is a false
positive that merely matched a keyword/brand string.

## Blind-judgment principle (non-negotiable)
- Classify using **only** the `description` and `cpe_strings` of the row.
- **Ignore every other column**, especially any other AI's judgment. Do not look for,
  reference, or be influenced by another reviewer's answer. Each judgment must be formed
  independently.

## What "home IoT device" means
An internet-connected sensor, appliance, or embedded system deployed in a **private
residence** for **monitoring, automation, or control** of the home, owned by non-expert
consumers. A row qualifies only if it plausibly satisfies all of:
1. **Connectivity** — networked (TCP/IP, MQTT, CoAP, Zigbee, BLE).
2. **Device class** — special-purpose sensor/appliance/embedded system; **not** general
   IT (PC, phone, tablet, server, game console).
3. **Deployment** — meant for a private home, not primarily enterprise/industrial.
4. **Function** — primary purpose is to monitor/automate/control the home (climate,
   security, access, lighting, appliances, presence). Media/entertainment, general
   computing, and communication are **not** qualifying functions.
5. **Security context** — owned/maintained by consumers, no professional IT security.

Connectivity alone is not membership: a device that merely talks to home IoT (or runs an
app that controls it) is not itself home IoT. Function (4) and class (2) are the discriminators.

## Output — three fields
- **Judgment**: `Yes` / `No` / `Maybe`
  - `Yes` — genuinely affects a home IoT device of this category.
  - `No` — false positive; keyword matched but the CVE is unrelated.
  - `Maybe` — genuinely ambiguous, needs a human. **Always paired with Low confidence.**
- **Confidence**: `High` / `Low`
  - `High` — clear from the description and/or CPE. Leave reasoning empty.
  - `Low` — some uncertainty. Reasoning **required**.
- **Reasoning**: short, self-contained. Required for **Low** confidence and **Maybe** only;
  empty otherwise. Explain from the description/CPE alone — never mention other reviewers.

## Calibration rules
- `Maybe` is **always** Low confidence. There is no confident "ambiguous".
- Use **Low** when: the device is plausibly home but primarily commercial/industrial; the
  description says the category but the CPE points at enterprise hardware; the CVE is in a
  software/protocol layer shared between home and non-home contexts.
- **Missing CPE does not force `Maybe`.** CPE is frequently absent on 2024–2026 CVEs due to
  NIST lag. If the description unambiguously names a home device and a residential attack
  vector (e.g. "via the LAN or a home router with port forwarding"), classify on the content
  (often `Yes (High)`).
- A `Maybe` or a Low-confidence `No` is more useful than a confident wrong answer — only
  rows with reasoning get human attention, so when genuinely unsure, use Low.
