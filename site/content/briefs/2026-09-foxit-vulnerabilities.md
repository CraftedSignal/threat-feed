---
title: Multiple Vulnerabilities in Foxit PDF Reader and Foxit PDF Editor
slug: 2026-09-foxit-vulnerabilities
description: Foxit PDF Reader and Foxit PDF Editor are susceptible to multiple vulnerabilities that allow attackers to achieve arbitrary code execution, privilege escalation, and security control bypass.
date: "2026-09-23T13:57:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - software-security
vendors:
  - Foxit
products:
  - Foxit PDF Reader
  - Foxit PDF Editor
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: An attacker can exploit multiple vulnerabilities in Foxit PDF Reader and Foxit PDF Editor to execute arbitrary code.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3525
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Foxit PDF Reader and Foxit PDF Editor to the latest vendor-recommended versions.
      owner: IT Operations
---

Foxit PDF Reader and Foxit PDF Editor contain multiple vulnerabilities that can be leveraged by a remote attacker to compromise an affected host. These flaws allow for arbitrary code execution, privilege escalation, unauthorized information disclosure, the bypass of existing security controls, and the manipulation of user data. The vulnerabilities stem from flaws in how the software processes specific, maliciously crafted PDF files. These vulnerabilities pose a significant risk, as successful exploitation could lead to full system compromise if a user is tricked into opening a malicious document. Organizations should prioritize updating to the latest vendor-provided versions to mitigate these risks.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to execute arbitrary code with the privileges of the victim user, escalate privileges, or bypass security restrictions. This could result in a complete compromise of the local workstation, unauthorized access to sensitive local files, and exfiltration of corporate data. As these products are widely used in enterprise environments, the potential for lateral movement and broad system access is high.

## Recommendation

Update all instances of Foxit PDF Reader and Foxit PDF Editor to the latest version provided by the vendor immediately. Audit software deployment logs to identify and patch legacy installations that are no longer managed by central software update services.
