---
title: Elevation of Privilege Vulnerability in Microsoft Exchange Server
slug: 2026-10-exchange-eop
description: CVE-2026-96940 is an elevation of privilege vulnerability in Microsoft Exchange Server that allows authenticated attackers to escalate privileges within the server environment.
date: "2026-10-06T00:48:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Exchange Server 2016 Cumulative Update 23 (< 15.01.2507.075)
  - Exchange Server 2019 Cumulative Update 14 (< 15.02.1544.048)
  - Exchange Server 2019 Cumulative Update 15 (< 15.02.1748.053)
  - Exchange Server Subscription Edition RTM (< 15.02.2562.053)
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability allows an authenticated attacker to escalate their privileges within the context of the affected mail server environment.
    confidence_band: high
cves:
  - id: CVE-2026-96940
    cvss: 8.8
    epss: 0.00496
references:
  - https://cyber.gc.ca/en/alerts-advisories/microsoft-security-advisory-av26-1001
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96940
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Patch all affected Microsoft Exchange Server versions to the specified security update levels.
      owner: IT Operations
      addresses: CVE-2026-96940
      evidence: Microsoft security advisory AV26-1001
---

Microsoft has disclosed CVE-2026-96940, an elevation of privilege vulnerability affecting several versions of Microsoft Exchange Server, including Exchange Server 2016 Cumulative Update 23, Exchange Server 2019 Cumulative Update 14 and 15, and the Exchange Server Subscription Edition RTM. This vulnerability permits an authenticated attacker to perform unauthorized actions or gain increased permissions within the context of the affected mail server. Given the critical role of Exchange Servers in enterprise communications and their common position within internal networks, this vulnerability poses a significant risk for lateral movement and further exploitation if an attacker has already established a presence within the network. Administrators are advised to review their environment and apply the security updates as provided by Microsoft.

## Impact

Successful exploitation of this vulnerability allows an authenticated user to escalate their privileges, potentially leading to unauthorized access to sensitive mail data, configuration modification, or further compromise of the underlying Windows Server hosting the Exchange environment. This risk is prevalent across organizations utilizing the specified versions of Microsoft Exchange Server.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Apply security updates to Microsoft Exchange Server 2016 Cumulative Update 23 (update to 15.01.2507.075 or later).
- Apply security updates to Microsoft Exchange Server 2019 Cumulative Update 14 (update to 15.02.1544.048 or later).
- Apply security updates to Microsoft Exchange Server 2019 Cumulative Update 15 (update to 15.02.1748.053 or later).
- Apply security updates to Microsoft Exchange Server Subscription Edition RTM (update to 15.02.2562.053 or later).
- Monitor for anomalous account activity or unauthorized elevation of privilege attempts originating from authenticated internal users targeting Exchange management interfaces.
