---
title: Unauthenticated XXE Injection in Ellucian WebAdvisor
slug: 2026-10-ellucian-xxe
description: Ellucian WebAdvisor 3.2 is vulnerable to an unauthenticated XXE injection, enabling remote attackers to perform SSRF, steal NTLMv2 hashes, and conduct arbitrary file read operations.
date: "2026-10-15T04:35:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ellucian:webadvisor:3.2:*:*:*:*:*:*:*
vendors:
  - Ellucian
products:
  - WebAdvisor (3.2)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ellucian WebAdvisor 3.2 contains an unauthenticated XML External Entity (XXE) injection vulnerability that allows remote attackers to submit crafted XML POST requests.
    confidence_band: high
cves:
  - id: CVE-2026-109430
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109430
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all servers running Ellucian WebAdvisor 3.2 for immediate decommissioning.
      owner: IT Operations
      due: 24h
      evidence: Software is end-of-support and vulnerable to unauthenticated RCE/Info-Disclosure.
  mitigation_plan:
    - priority: immediate
      action: Migrate from Ellucian WebAdvisor to Colleague Self-Service.
      owner: IT Operations
      addresses: CVE-2026-109430
      evidence: Users are encouraged to migrate to Colleague Self-Service.
---

Ellucian WebAdvisor version 3.2 contains an unauthenticated XML External Entity (XXE) injection vulnerability (CVE-2026-109430). The vulnerability stems from improper configuration of XML parsers within the /WebAdvisor/WebAdvisor endpoint, which fail to properly disable external entity and Document Type Definition (DTD) resolution. Remote attackers can leverage this flaw to send crafted XML POST requests to the application. Successful exploitation allows for server-side request forgery (SSRF), the coercion of NTLMv2 hash disclosure by forcing the server to authenticate against attacker-controlled SMB shares, and the reading of arbitrary local files from the underlying Windows host via error-based exfiltration. As Ellucian WebAdvisor reached end-of-support in June 2022, there are no patches available for this vulnerability. Organizations using this software are at significant risk and are urged to migrate to Colleague Self-Service immediately.

## Impact

Successful exploitation results in full server-side information disclosure and potential credential theft. Attackers can bypass authentication to read sensitive configuration files, system files, or application data. Furthermore, the ability to coerce the server into performing SMB authentication provides a vector for lateral movement or credential harvesting through NTLMv2 relay attacks. Given the nature of the software in higher education environments, this impact could lead to the broad compromise of institutional sensitive data.

## Recommendation

* Identify and isolate all remaining instances of Ellucian WebAdvisor in the environment, as the software is no longer supported and cannot be patched.
* Migrate all workflows currently relying on WebAdvisor to Colleague Self-Service or an alternative supported platform.
* Implement restrictive network egress rules for all servers previously running WebAdvisor to prevent SSRF and SMB-based hash exfiltration.
* Monitor IIS web server logs for HTTP POST requests to /WebAdvisor/WebAdvisor containing XML structures with DTD definitions or external entity declarations.
