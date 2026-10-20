---
brief_id: brief-2026-10-20-certifi-compromised-roots
event_id: brief-2026-10-20-certifi-compromised-roots
revision: 1
activity_at: "2026-10-20T23:53:18Z"
title: 'Certifi: Bundled eMudhra root CAs with compromised intermediate keys'
slug: 2026-10-certifi-compromised-roots
description: Certifi versions prior to 2026.10.19 bundled the emSign ECC Root CA - G3, enabling on-path attackers to perform TLS interception using certificates issued by revoked intermediate CAs.
date: "2026-10-20T23:53:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - supply-chain
  - tls-interception
  - python
vendors:
  - eMudhra
products:
  - certifi (< 2026.10.19)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    subtechnique_id: T1557.002
    subtechnique_name: ARP Cache Poisoning
    evidence: An attacker with one of the compromised keys can issue valid-looking certificates for any hostname. If the attacker is also on-path, they can intercept or modify TLS traffic from clients that trust the certifi bundle.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6q48-6c7w-9gw2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade certifi library to 2026.10.19 or later
      owner: IT Operations
      due: 24h
      evidence: Certifi 2026.10.19 restored the emSign roots that are not affected.
  mitigation_plan:
    - priority: immediate
      action: Rebuild container images that vendor certifi
      owner: IT Operations
      addresses: certifi (< 2026.10.19)
      evidence: Rebuild container images that vendor certifi.
---

Certifi versions before 2026.10.18 included the 'emSign ECC Root CA - G3' root certificate in their default CA bundle. It was discovered that eight eMudhra intermediate CA certificates chaining to this root had their private keys compromised, leading to their revocation by the issuing CA. Because these compromised intermediate certificates remained trusted by older versions of the certifi bundle, an attacker could potentially issue fraudulent TLS certificates for any domain. 

Applications relying on the certifi bundle for TLS verification - including widely used Python libraries like requests, urllib3, and pip, as well as the Python.org macOS installer - are vulnerable to man-in-the-middle attacks if the attacker is in an on-path position. This allows for traffic decryption, manipulation, and credential theft. Certifi 2026.10.18 initially removed all emSign roots to mitigate the risk, and 2026.10.19 subsequently restored only the unaffected roots. Organizations must upgrade to 2026.10.19 or later and rebuild all container images or environments that include the vulnerable certifi bundle.

## Impact

The vulnerability impacts any software platform or environment utilizing affected versions of the certifi library to validate TLS connections. Successful exploitation allows an on-path attacker to intercept and modify encrypted communications, potentially leading to widespread data exfiltration, service impersonation, and the compromise of sensitive credentials transmitted over TLS-protected sessions.

## Recommendation

- Upgrade the certifi library in all development, production, and container environments to version 2026.10.19 or later immediately.
- Rebuild and redeploy container images and virtual machine snapshots that vendored earlier versions of the certifi package.
- Audit infrastructure dependencies to identify software specifically relying on bundled certifi CA stores, such as custom scripts using the requests or urllib3 libraries.
