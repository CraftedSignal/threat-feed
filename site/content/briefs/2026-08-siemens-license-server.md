---
title: Multiple Vulnerabilities in Siemens License Server
slug: 2026-08-siemens-license-server
description: Siemens License Server (SLS) contains vulnerabilities allowing remote file disclosure (CVE-2026-69109) and local privilege escalation (CVE-2026-69108).
date: "2026-08-13T16:51:47Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Siemens
products:
  - Siemens License Server (SLS)
cves:
  - id: CVE-2026-69109
    cvss: 7.5
    epss: 0.00462
  - id: CVE-2026-69108
    cvss: 6
    epss: 0.00112
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-07
  - https://www.cve.org/CVERecord?id=CVE-2026-69108
  - https://www.cve.org/CVERecord?id=CVE-2026-69109
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Siemens License Server (SLS) to V5.3 or later
      owner: IT Operations
      due: 72h
      evidence: Vendor fix provided by Siemens
  mitigation_plan:
    - priority: immediate
      action: Isolate license server from internet-facing network segments
      owner: IT Operations
      addresses: CVE-2026-69109
      evidence: CISA recommended practices
---

Siemens License Server (SLS) is affected by two vulnerabilities that pose significant security risks to industrial and IT environments. CVE-2026-69108 is a local privilege escalation vulnerability caused by an insecure sudoers policy, which allows a local attacker to execute arbitrary commands with root privileges and create malicious files on the underlying system. CVE-2026-69109 is a path traversal vulnerability resulting from inadequate sanitization of user-supplied input, enabling an unauthenticated remote attacker to access arbitrary files on the host system. These vulnerabilities affect versions of Siemens License Server prior to V5.1 (for the privilege escalation flaw) and V5.3 (for the path traversal flaw). Defenders should prioritize patching to version 5.3 or later to mitigate these security gaps.

## Impact

Successful exploitation of these vulnerabilities could result in full system compromise, unauthorized access to sensitive application data, and the potential for lateral movement within an organization's network. Given the role of license servers in industrial control system (ICS) environments, compromise of this service could impact the availability or integrity of license management for critical infrastructure deployments.

## Recommendation

- Upgrade all instances of Siemens License Server (SLS) to version 5.3 or later to remediate both CVE-2026-69108 and CVE-2026-69109.
- Restrict network access to the Siemens License Server to only necessary management segments, isolating the server from public internet exposure as per CISA guidelines.
- Implement strict ingress and egress filtering on firewall segments hosting the SLS to prevent unauthorized remote requests and potential data exfiltration resulting from path traversal attempts.
- Conduct an audit of sudoers configuration files on systems hosting SLS to ensure least-privilege principles are enforced and to prevent unauthorized privilege escalation.
