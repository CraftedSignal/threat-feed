---
title: Critical Vulnerabilities in Applied Systems Engineering ASE2000 V2
slug: 2026-08-ase2000-vulnerabilities
description: Applied Systems Engineering ASE2000 V2 (versions 2.25-2.37) is affected by critical XXE and improper TLS validation vulnerabilities that allow for remote code execution, arbitrary file access, and man-in-the-middle attacks.
date: "2026-08-27T16:05:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:apache:log4net:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:30:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:31:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:32:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:application_testing_suite:13.3.0.1:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:hospitality_opera_5:5.5:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:hospitality_opera_5:5.6:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:hospitality_simphony:18.2.7.2:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:hospitality_simphony:19.1.3:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:manageability_software_development_kit:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:snapcenter:-:*:*:*:*:*:*:*
vendors:
  - Applied Systems Engineering
products:
  - ASE2000 V2 Communications Test Set
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation of these vulnerabilities could allow an attacker to read or write arbitrary local files, cause the application to issue outbound network requests, or intercept the connection to impersonate the trusted peer.
    confidence_band: high
cves:
  - id: CVE-2018-1285
    cvss: 9.8
    epss: 0.17366
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-239-04
  - https://www.cve.org/CVERecord?id=CVE-2018-1285
  - https://www.cve.org/CVERecord?id=CVE-2026-18717
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Upgrade ASE2000 V2 to version 2.38
      owner: IT Operations
      due: 24h
      evidence: 'Vendor mitigation: ASE/Kalkitech provides an upgraded version 2.38 that fixes both vulnerabilities.'
  mitigation_plan:
    - priority: immediate
      action: Isolate ASE2000 hosts behind firewalls and restrict network access
      owner: OT Security
      addresses: CVE-2018-1285, CVE-2026-18717
      evidence: 'Vendor mitigation: Ensure the host is protected by a network firewall.'
---

Applied Systems Engineering (ASE) has disclosed critical security vulnerabilities affecting the ASE2000 V2 Communications Test Set, specifically versions 2.25 through 2.37. These flaws pose significant risks to industrial control environments, including the Energy, Chemical, and Water/Wastewater sectors. The vulnerabilities include an XML External Entity (XXE) injection flaw (CVE-2018-1285) due to an outdated log4net library, which enables local file read/write operations and potential arbitrary command execution. Additionally, a flaw in the IEC 60870-5-104 TLS implementation (CVE-2026-18717) allows for improper certificate validation, permitting attackers to impersonate trusted peers and intercept or modify sensitive industrial communications. Impacted organizations are urged to upgrade to version 2.38 immediately, which resolves both issues and updates the underlying log4net dependencies.

## Impact

Successful exploitation of these vulnerabilities allows unauthorized actors to read or write arbitrary local files, trigger malicious outbound network requests, and intercept encrypted communications via man-in-the-middle attacks. These capabilities jeopardize the integrity and availability of industrial processes globally, potentially leading to unauthorized control of communication streams or system compromise. Organizations relying on ASE2000 for critical infrastructure operations are at high risk if these systems remain internet-exposed or reside on untrusted, shared segments.

## Recommendation

* Upgrade all instances of ASE2000 V2 to version 2.38 or later immediately to patch CVE-2018-1285 and CVE-2026-18717.
* Restrict write access to the ASE2000 installation directory and configuration files to prevent the placement of malicious log4net configuration files used to trigger CVE-2018-1285.
* Isolate hosts running ASE2000 into segmented networks with strict firewall controls, ensuring they are not reachable from the public internet or untrusted enterprise network segments.
* Disable or avoid the use of IEC 60870-5-104 over TLS on networks where traffic cannot be fully trusted, pending system upgrades.
