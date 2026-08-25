---
title: Hard-coded RSA-512 Mesh Key in TP-Link Deco Routers
slug: 2026-08-tp-link-mesh-key
description: A hard-coded RSA-512 private key in TP-Link Deco mesh firmware allows adjacent attackers to impersonate trusted nodes, enabling unauthorized configuration changes and firmware modification.
date: "2026-08-25T05:12:20Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - TP-Link
products:
  - Deco XE75
  - Deco XE5300
  - Deco WE10800
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A shared RSA-512 mesh group private key is hard-coded into the TP-Link Deco firmware image and is identical across every unit of the affected models.
    confidence_band: high
cves:
  - id: CVE-2026-15469
references:
  - https://www.tp-link.com/us/support/faq/5263/
  - https://sploitus.com/exploit?id=3D953520-C13A-55AE-B146-8184DA3EA47F
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch affected TP-Link Deco firmware to 1.5.0 Build 20260603
      owner: IT Operations
      due: 24h
      evidence: Vendor advisory confirms fix is available in this release.
---

TP-Link Deco XE75, XE5300, and WE10800 mesh networking devices contain a hard-coded RSA-512 cryptographic key used for mesh group authentication (TDP/TMP protocols). Because this key is identical across all units of the affected models, an attacker with local network access to the mesh environment can extract the key from publicly available firmware images. Using this key, an attacker can impersonate a legitimate mesh node during the authentication handshake. This vulnerability, tracked as CVE-2026-15469, facilitates critical risks including unauthorized configuration changes, the deployment of unsigned malicious firmware, and seamless lateral movement across the mesh network. The flaw was publicly disclosed following vendor coordination and a patch release. It is fixed in firmware version 1.5.0 Build 20260603 and later.

## Impact

Successful exploitation allows for the complete compromise of the mesh network environment. Attackers can gain control over configuration settings, inject malicious firmware updates to maintain persistence, and pivot through the network as a trusted mesh node. This affects all deployments of the listed TP-Link Deco models that have not been updated to the corrected firmware version.

## Recommendation

- Update all TP-Link Deco XE75, XE5300, and WE10800 units to firmware version 1.5.0 Build 20260603 or newer immediately.
- Audit mesh network traffic for unauthorized node onboarding or unusual administrative activity originated from unexpected MAC addresses.
- Restrict physical and logical access to the management and mesh-interconnect network segments to prevent adjacent network attackers from reaching the mesh protocol interfaces.
