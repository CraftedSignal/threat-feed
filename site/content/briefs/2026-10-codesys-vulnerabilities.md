---
title: Multiple Vulnerabilities in CODESYS Control Runtime and Gateway
slug: 2026-10-codesys-vulnerabilities
description: Multiple vulnerabilities in CODESYS Control Runtime and Gateway Client allow a remote attacker to manipulate data or cause a denial-of-service condition.
date: "2026-10-02T14:20:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:dlink:dir-846w_firmware:fw100a43:*:*:*:*:*:*:*
tags:
  - ics
  - industrial-control-system
  - vulnerability
vendors:
  - CODESYS
products:
  - CODESYS Control Runtime
  - CODESYS Gateway Client
cves:
  - id: CVE-2024-44336
    cvss: 5.3
    epss: 0.00301
  - id: CVE-2024-44337
    cvss: 5.1
    epss: 0.00506
  - id: CVE-2024-44340
    cvss: 8.8
    epss: 0.01794
  - id: CVE-2024-44341
    cvss: 9.8
    epss: 0.01832
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3710
action_plan:
  priority: elevated
  owners:
    - OT Security
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Patch CODESYS Control Runtime and Gateway Client
      owner: IT Operations
      addresses: CVE-2024-44336 through CVE-2024-44344
      evidence: Source states multiple vulnerabilities allow data manipulation and DoS
---

The BSI has released an advisory regarding multiple vulnerabilities identified in CODESYS Control Runtime and Gateway Client components. These flaws, tracked under CVE-2024-44336 through CVE-2024-44344, pose a significant risk to industrial environments where these components are deployed. Exploitation of these vulnerabilities may allow an unauthenticated or remote attacker to manipulate process data or induce a denial-of-service (DoS) condition, potentially leading to operational disruption of industrial control systems. As these components often operate in critical infrastructure, defenders must prioritize the assessment of their exposure and apply vendor-provided patches.

## Impact

The affected vulnerabilities impact organizations utilizing CODESYS industrial automation software. Successful exploitation could result in the unauthorized modification of process data or complete service unavailability, necessitating emergency maintenance in critical production environments.

## Recommendation

Prioritize the identification of all instances of CODESYS Control Runtime and Gateway Client within the enterprise OT environment. Apply security updates provided by CODESYS immediately to mitigate the risks associated with CVE-2024-44336, CVE-2024-44337, CVE-2024-44338, CVE-2024-44339, CVE-2024-44340, CVE-2024-44341, CVE-2024-44342, CVE-2024-44343, and CVE-2024-44344. Ensure internal firewalls restrict access to industrial control interfaces to authorized engineering stations only.
