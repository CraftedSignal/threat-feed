---
title: Multiple Vulnerabilities in Docker Sandboxes
slug: 2026-09-docker-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-77179 and CVE-2026-79994, in Docker Sandboxes versions prior to 0.42.0 could allow remote code execution, data confidentiality breaches, and integrity loss.
date: "2026-09-16T13:06:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:docker:sandboxes:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - docker
vendors:
  - Docker
products:
  - Docker Sandboxes (< 0.42.0)
cves:
  - id: CVE-2026-77179
  - id: CVE-2026-79994
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1189/
  - https://docs.docker.com/security/security-announcements/#docker-sandboxes-0420-security-update-cve-2026-77179-and-cve-2026-79994
  - https://www.cve.org/CVERecord?id=CVE-2026-77179
  - https://www.cve.org/CVERecord?id=CVE-2026-79994
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Docker Sandboxes to version 0.42.0 or later
      owner: IT Operations
      addresses: CVE-2026-77179, CVE-2026-79994
      evidence: 'Vendor security bulletin #docker-sandboxes-0420-security-update-cve-2026-77179-and-cve-2026-79994'
---

The French National Cybersecurity Agency (ANSSI) has published an advisory regarding multiple vulnerabilities identified within Docker Sandboxes. These vulnerabilities, identified as CVE-2026-77179 and CVE-2026-79994, affect versions prior to 0.42.0. If successfully exploited, these flaws could allow a remote attacker to achieve arbitrary code execution on the host or target container, compromise the confidentiality of sensitive data, or impact the integrity of stored or processed information. Organizations utilizing Docker Sandboxes are advised to refer to the official vendor security bulletin to apply the necessary patches. Given the potential for remote code execution, timely patching is critical to mitigate the risk of unauthorized system access.

## Impact

Successful exploitation of these vulnerabilities may result in full remote control over the affected containerized environment. This exposure risks the exfiltration of sensitive data, modification of application logic, and broader lateral movement within the host system. The scope of impact extends to any organization deploying Docker Sandboxes in versions earlier than 0.42.0.

## Recommendation

- Upgrade Docker Sandboxes to version 0.42.0 or later immediately.
- Review the official vendor security announcement at https://docs.docker.com/security/security-announcements/#docker-sandboxes-0420-security-update-cve-2026-77179-and-cve-2026-79994 to verify all addressed security fixes.
- Identify and inventory all systems running Docker Sandboxes in the environment to ensure comprehensive patching.
