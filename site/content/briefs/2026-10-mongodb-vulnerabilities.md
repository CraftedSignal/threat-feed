---
title: Multiple Vulnerabilities in MongoDB Server
slug: 2026-10-mongodb-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-103965, CVE-2026-104004, CVE-2026-104005, CVE-2026-96297, and CVE-2026-96299, in MongoDB Server allow remote attackers to achieve arbitrary code execution or denial of service.
date: "2026-10-14T16:21:33Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:mongodb:server:*:*:*:*:*:*:*:*
vendors:
  - MongoDB
products:
  - MongoDB Server (versions < 7.0.45)
  - MongoDB Server (versions < 8.0.34)
  - MongoDB Server (versions < 8.3.13)
  - MongoDB Server (versions < 9.0.0-rc2)
  - MongoDB Server (versions < 9.1.0-rc1024)
cves:
  - id: CVE-2026-103965
    cvss: 5.4
  - id: CVE-2026-104004
    cvss: 6.5
  - id: CVE-2026-104005
    cvss: 6.5
  - id: CVE-2026-96297
    cvss: 6.5
  - id: CVE-2026-96299
    cvss: 6.5
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1304/
  - https://jira.mongodb.org/browse/SERVER-130431
  - https://jira.mongodb.org/browse/SERVER-131411
  - https://jira.mongodb.org/browse/SERVER-131412
  - https://jira.mongodb.org/browse/SERVER-132946
  - https://jira.mongodb.org/browse/SERVER-134618
  - https://www.cve.org/CVERecord?id=CVE-2026-103965
  - https://www.cve.org/CVERecord?id=CVE-2026-104004
  - https://www.cve.org/CVERecord?id=CVE-2026-104005
  - https://www.cve.org/CVERecord?id=CVE-2026-96297
  - https://www.cve.org/CVERecord?id=CVE-2026-96299
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade MongoDB Server to 7.0.45 or later
      owner: IT Operations
      due: 72h
      evidence: Source provides specific vulnerable versions for multiple branches.
  mitigation_plan:
    - priority: immediate
      action: Apply patches provided in MongoDB security bulletins SERVER-130431, SERVER-131411, SERVER-131412, SERVER-132946, and SERVER-134618.
      owner: IT Operations
      addresses: CVE-2026-103965, CVE-2026-104004, CVE-2026-104005, CVE-2026-96297, CVE-2026-96299
      evidence: Source identifies these CVEs and associated JIRA fix references.
---

The French National Cybersecurity Agency (ANSSI) has reported multiple vulnerabilities affecting various branches of MongoDB Server. These vulnerabilities, identified as CVE-2026-103965, CVE-2026-104004, CVE-2026-104005, CVE-2026-96297, and CVE-2026-96299, present significant security risks, including the potential for remote arbitrary code execution (RCE) and denial of service (DoS). The affected versions include MongoDB Server 7.x prior to 7.0.45, 8.0.x prior to 8.0.34, 8.3.x prior to 8.3.13, 9.0.x prior to 9.0.0-rc2, and 9.1.x prior to 9.1.0-rc1024. Organizations using these versions are encouraged to audit their database deployments and apply the security patches provided by MongoDB as soon as possible to mitigate the risk of exploitation.

## Impact

Successful exploitation of these vulnerabilities could result in a complete system compromise via remote arbitrary code execution or service disruption through denial of service. The scope of impact includes any infrastructure running the vulnerable MongoDB Server versions, potentially leading to unauthorized data access, system takeover, or operational downtime across business-critical database environments.

## Recommendation

- Upgrade all affected MongoDB Server instances to the patched versions specified in the vendor's security bulletins (SERVER-130431, SERVER-131411, SERVER-131412, SERVER-132946, SERVER-134618).
- Review the official MongoDB JIRA project documentation linked in the references for detailed remediation steps for each identified CVE.
- Restrict network access to MongoDB instances to authorized clients only to minimize the attack surface while update procedures are scheduled.
