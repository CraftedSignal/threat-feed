---
title: Improper Verification Vulnerability in Contrast Coordinator Peer Recovery
slug: 2026-10-contrast-coordinator-flaw
description: Contrast versions 1.8.0 through 1.24.0 are vulnerable to an improper verification flaw in the Coordinator peer recovery process that allows manifest history replay and potential Mesh CA key disclosure.
date: "2026-10-12T20:30:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:contrast:contrast:*:*:*:*:*:*:*:*
vendors:
  - Contrast
products:
  - Contrast (1.8.0-1.24.0)
cves:
  - id: CVE-2026-109359
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109359
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Contrast instances to 1.24.1 or later
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-109359 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade Contrast to 1.24.1
      owner: IT Operations
      addresses: CVE-2026-109359
      evidence: NVD vulnerability details
---

Contrast versions 1.8.0 through 1.24.0 are affected by an improper verification vulnerability (CVE-2026-109359) within the Coordinator peer recovery mechanism. The flaw stems from a failure to confirm that a serving peer utilizes the same manifest generation during the recovery handshake. An attacker who gains write access to the manifest history can perform a replay attack using a superseded history head. This enables the issuance of trusted mesh certificates to unauthorized, withdrawn workloads or, in scenarios where the secret seed is obtained, the disclosure of the Mesh CA key. This vulnerability poses a significant risk to the integrity of the service mesh environment, potentially allowing for lateral movement or intercept of encrypted traffic by unauthorized workloads.

## Impact

Successful exploitation allows for the compromise of service mesh authentication and authorization, permitting unauthorized workloads to masquerade as trusted entities. If the Mesh CA key is disclosed via the secret seed, an attacker could potentially sign arbitrary certificates, leading to a complete compromise of the mesh trust domain. This affects organizations deploying Contrast versions prior to 1.24.1.

## Recommendation

- Upgrade all instances of Contrast to version 1.24.1 or later to resolve the improper verification flaw in peer recovery.
- Audit access controls for the manifest history storage to prevent unauthorized write modifications that could facilitate replay attacks.
- Rotate the Mesh CA key and associated secret seeds immediately if there is any indication that the environment was exposed or if the integrity of the manifest history is in question.
- Review network logs and service mesh orchestration logs for anomalous peer recovery attempts or synchronization requests originating from unauthorized or withdrawn workloads.
