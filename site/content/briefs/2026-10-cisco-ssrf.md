---
title: SSRF Vulnerability in Cisco Finesse, Unified CCE, and Unified CCX
slug: 2026-10-cisco-ssrf
description: An unauthenticated, remote attacker can exploit a Server-Side Request Forgery (SSRF) vulnerability in Cisco Finesse, Unified CCE, and Unified CCX to gain unauthorized access to internal resources and disclose sensitive information.
date: "2026-10-08T13:10:19Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:cisco:ios_xe:17.1.1:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.1.1a:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.1.1s:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.1.1t:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.1.3:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.2.1:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.2.1a:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.2.1r:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.2.1v:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.2.2:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.2.3:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.3.1:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.3.1a:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.3.1w:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.3.1x:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.3.1z:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.3.2:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.3.2a:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.3.3:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios_xe:17.3.4:*:*:*:*:*:*:*
vendors:
  - Cisco
products:
  - Finesse
  - Unified CCE
  - Unified CCX
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated, remote attacker can exploit a vulnerability in Cisco Finesse, Unified CCE, and Unified CCX to perform SSRF attacks.
    confidence_band: high
cves:
  - id: CVE-2024-20455
    cvss: 8.6
    epss: 0.00662
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3794
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Apply security patches for CVE-2024-20455 to all instances of Finesse, Unified CCE, and Unified CCX.
      owner: IT Operations
      due: 48h
      evidence: Vendor advisory requires patching to address SSRF vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Implement strict egress filtering at the network perimeter for servers running affected Cisco software.
      owner: Network Security
      addresses: CVE-2024-20455
      evidence: SSRFs require outbound requests from the affected server to target systems.
---

Cisco has disclosed a critical Server-Side Request Forgery (SSRF) vulnerability, identified as CVE-2024-20455, affecting Cisco Finesse, Cisco Unified Contact Center Enterprise (Unified CCE), and Cisco Unified Contact Center Express (Unified CCX). The vulnerability exists due to insufficient validation of user-supplied input provided to the application, allowing an unauthenticated, remote attacker to manipulate the backend server into performing unauthorized HTTP requests. By crafting specific requests, an attacker can bypass access controls to reach internal resources that are otherwise not accessible from the public internet. This flaw poses a significant risk to organizations as it may lead to the exfiltration of sensitive configuration data, internal metadata, or internal service responses that aid in further reconnaissance or lateral movement within the network. Defenders should prioritize patching, as this vulnerability requires no specialized authentication or prior access to the targeted systems.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to perform SSRF attacks, leading to the exposure of sensitive internal information and reconnaissance of internal network segments. This exposes critical contact center infrastructure to potential data theft and increased risk of follow-on attacks against backend components, impacting the confidentiality of organizational data.

## Recommendation

Prioritize the application of vendor-supplied patches for CVE-2024-20455 across all affected Cisco Unified Communications products. Configure network-level egress filtering to restrict internal server-to-server communication initiated by these specific applications to only required destinations. Implement strict input validation and access controls on any application endpoints that handle URI-based parameters.
