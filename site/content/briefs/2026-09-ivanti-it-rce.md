---
title: Multiple Remote Code Execution Vulnerabilities in Ivanti Neurons for ITSM
slug: 2026-09-ivanti-it-rce
description: Multiple vulnerabilities in Ivanti Neurons for ITSM (CVE-2024-7569, CVE-2024-7570, CVE-2024-7571) allow a remote unauthenticated attacker to achieve remote code execution.
date: "2026-09-09T12:49:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ivanti:neurons_for_itsm:2023.2:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:neurons_for_itsm:2023.3:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:neurons_for_itsm:2023.4:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:secure_access_client:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:secure_access_client:22.7:-:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:secure_access_client:22.7:r1:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:secure_access_client:22.7:r1.1:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:secure_access_client:22.7:r2:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:secure_access_client:22.7:r3:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - ivanti
vendors:
  - Ivanti
products:
  - Neurons for ITSM (<= 2023.4)
cves:
  - id: CVE-2024-7569
    cvss: 9.6
    epss: 0.01737
  - id: CVE-2024-7570
    cvss: 8.3
    epss: 0.00575
  - id: CVE-2024-7571
    cvss: 7.8
    epss: 0.00261
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3272
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Neurons for ITSM to 22.7R4 or later
      owner: IT Operations
      due: 24h
      evidence: Advisory states vulnerabilities allow code execution and require patching
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to Ivanti Neurons for ITSM web interface
      owner: Network Security
      addresses: CVE-2024-7569, CVE-2024-7570, CVE-2024-7571
      evidence: Advisory identifies unauthenticated remote code execution risk
---

Ivanti has disclosed multiple vulnerabilities affecting Ivanti Neurons for ITSM. These flaws include CVE-2024-7569, CVE-2024-7570, and CVE-2024-7571. These vulnerabilities reside within the ITSM application framework and, when successfully exploited, allow a remote, unauthenticated attacker to execute arbitrary code within the context of the application. Given the nature of ITSM platforms, which often run with elevated service account privileges, successful exploitation could lead to full application compromise, lateral movement within the network, and exfiltration of sensitive configuration or identity data stored within the ITSM database. Defenders should treat these vulnerabilities as high-priority targets for patching due to the potential for unauthenticated access.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to achieve remote code execution on the affected server. This could lead to a complete compromise of the Ivanti Neurons for ITSM instance, unauthorized access to sensitive service desk data, potential pivot points into the internal network, and the deployment of persistent backdoors. 

## Recommendation

Prioritize patching all internet-facing and internal instances of Ivanti Neurons for ITSM to the latest vendor-supplied version addressing CVE-2024-7569, CVE-2024-7570, and CVE-2024-7571. Ensure that service accounts used by the ITSM platform follow the principle of least privilege to minimize the impact of a potential RCE event. Restrict network access to the Ivanti Neurons for ITSM interface to authorized internal subnets via firewalls until updates can be applied.
