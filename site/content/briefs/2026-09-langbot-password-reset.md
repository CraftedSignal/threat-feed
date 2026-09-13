---
title: Insufficient Entropy and Lack of Rate Limiting in LangBot Password Recovery
slug: 2026-09-langbot-password-reset
description: LangBot versions prior to 4.10.11 are vulnerable to account takeover via a predictable password reset process due to insufficient entropy in recovery keys and a lack of rate limiting on the reset endpoint.
date: "2026-09-13T11:25:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:langbot:langbot:*:*:*:*:*:*:*:*
vendors:
  - LangBot
products:
  - LangBot (< 4.10.11)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Remote attackers knowing the administrator email can exhaust the keyspace through concurrent requests to reset the admin password and gain account access.
    confidence_band: high
cves:
  - id: CVE-2026-90562
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90562
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade LangBot to version 4.10.11 or later to patch CVE-2026-90562.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies version 4.10.11 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 4.10.11 or later.
      owner: IT Operations
      addresses: CVE-2026-90562
      evidence: NVD vulnerability details
---

LangBot versions prior to 4.10.11 contain a security vulnerability in the password recovery mechanism that allows remote, unauthenticated attackers to hijack administrator accounts. The application generates password reset tokens with only 24 bits of entropy, which results in a significantly small keyspace. Furthermore, the application fails to implement rate limiting on the unauthenticated reset-password endpoint, enabling attackers to systematically brute-force the recovery keys. By targeting a known administrator email address, an attacker can launch concurrent requests to the reset-password endpoint, exhaust the 24-bit keyspace in a short time, and successfully reset the password to gain unauthorized access to the LangBot environment. This vulnerability poses a critical risk to organizations relying on LangBot for sensitive operations, as it bypasses standard authentication controls without requiring prior valid credentials.
