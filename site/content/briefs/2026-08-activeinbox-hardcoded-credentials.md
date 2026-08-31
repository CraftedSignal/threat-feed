---
title: ActiveInbox Extension Hard-coded Google OAuth Client Secret
slug: 2026-08-activeinbox-hardcoded-credentials
description: The ActiveInbox Chrome extension up to version 7.10.24 contains hard-coded Google OAuth Client Secrets in its service worker, potentially enabling unauthorized API access and OAuth flow manipulation.
date: "2026-08-31T17:58:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:inbox_foundry:activeinbox:*:*:*:*:*:chrome:*:*
tags:
  - credential-exposure
  - chrome-extension
  - oauth
  - cve-2026-82808
vendors:
  - Inbox Foundry
products:
  - ActiveInbox Extension (<= 7.10.24)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Impacted is an unknown function of the file dist/service-worker.production-esm.js of the component Google OAuth Client Secret. Such manipulation leads to hard-coded credentials.
    confidence_band: high
cves:
  - id: CVE-2026-82808
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82808
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all endpoints running the ActiveInbox Chrome extension.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82808 vulnerability impact.
  mitigation_plan:
    - priority: immediate
      action: Remove or restrict the affected ActiveInbox extension versions (<= 7.10.24) until the vendor provides a patched release.
      owner: IT Operations
      addresses: CVE-2026-82808
      evidence: NVD disclosure indicating hard-coded credentials.
---

A vulnerability identified as CVE-2026-82808 affects the Inbox Foundry ActiveInbox extension for Chrome, versions 7.10.24 and earlier. The issue lies within the dist/service-worker.production-esm.js file, which contains a hard-coded Google OAuth Client Secret. This security oversight allows for the extraction of sensitive credentials used to identify the application during OAuth authentication flows. 

Remote attackers can leverage this hard-coded secret to perform unauthorized API requests or interfere with OAuth authentication processes for users of the extension. The vulnerability has been publicly disclosed, and proof-of-concept exploitation material is available, increasing the risk of abuse. Although the vendor was notified, they have noted that their bug bounty program is currently on hold, leaving the exposure present in legacy versions until an update is applied.

## Impact

The exposure of the Google OAuth Client Secret permits attackers to masquerade as the legitimate ActiveInbox application during OAuth handshake processes. This can lead to unauthorized access to user data connected via the extension or potential API manipulation, impacting the confidentiality and integrity of the integration between the user's email client and the ActiveInbox service.

## Recommendation

- Audit internal software supply chains for instances of the ActiveInbox Chrome extension, version 7.10.24 or older.
- Implement browser-based security policies to restrict or monitor the installation of extensions that have known hard-coded credential vulnerabilities.
- Require users to rotate credentials or re-authenticate through updated service versions once a patch is provided by Inbox Foundry to invalidate the compromised client secret.
