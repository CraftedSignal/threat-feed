---
brief_id: brief-2026-10-27-electrum-sig-verification
event_id: brief-2026-10-27-electrum-sig-verification
revision: 1
activity_at: "2026-10-27T15:50:58Z"
title: 'Electrum: Unverified signature vulnerability in mempool transactions (CVE-2026-117601)'
slug: 2026-10-electrum-sig-verification
description: Electrum versions prior to 4.8.3 fail to verify signatures of wallet-owned inputs in unconfirmed transactions, allowing malicious servers to trick users into signing fraudulent fee-replacement transactions.
date: "2026-10-27T15:50:58Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: verified against NVD
cpes:
  - cpe:2.3:a:electrum:electrum:*:*:*:*:*:*:*:*
vendors:
  - Electrum
products:
  - Electrum (< 4.8.3)
cves:
  - id: CVE-2026-117601
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117601
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all Electrum client installations to version 4.8.3 or later.
      owner: IT Operations
      due: 48h
      evidence: Electrum before 4.8.3 fails to verify signatures of wallet-owned inputs in unconfirmed mempool transactions.
  hunt_leads:
    - lead: Identify endpoints running Electrum versions below 4.8.3 via asset inventory or endpoint telemetry.
      technique_id: T1566.002
      data_needed:
        - Endpoint software inventory logs
        - Process file metadata
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Electrum before 4.8.3 fails to verify signatures of wallet-owned inputs.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Electrum to 4.8.3
      owner: IT Operations
      addresses: CVE-2026-117601
      evidence: Electrum before 4.8.3 fails to verify signatures of wallet-owned inputs.
---

Electrum versions before 4.8.3 contain a vulnerability (CVE-2026-117601) where the client fails to verify the signatures of wallet-owned inputs for transactions residing in the unconfirmed mempool. This flaw allows a malicious server to intercept and replace a broadcast transaction with a conflicting one. 

## Impact
Attackers can manipulate the user's view of pending transactions, suppressing the original broadcast and presenting a modified, invalid zero-fee version that pays an attacker-controlled address. By presenting this as a transaction that requires an RBF (Replace-By-Fee) bump, the attacker tricks the user into signing a transaction that transfers funds to the attacker.

## Recommendation
- Upgrade Electrum clients to version 4.8.3 or later on all systems where the wallet software is installed.
- Until patching is complete, verify all RBF requests against the intended recipient address and fee structure before signing transactions.
- For enterprise or high-value environments, isolate Electrum instances to connect only to trusted, verified Electrum servers rather than relying on auto-discovered or public nodes.
