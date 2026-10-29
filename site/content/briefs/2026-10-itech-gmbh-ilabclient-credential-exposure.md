---
brief_id: brief-2026-10-29-itech-gmbh-ilabclient-credential-exposure
event_id: brief-2026-10-29-itech-gmbh-ilabclient-credential-exposure
revision: 1
activity_at: "2026-10-29T03:50:14Z"
title: 'Itech-gmbh Ilabclient: Local credential exposure (CVE-2024-56428)'
slug: 2026-10-itech-gmbh-ilabclient-credential-exposure
description: Itech-gmbh Ilabclient version 3.7.1 stores credentials in cleartext within an Apache Derby database, allowing local attackers to extract configuration data via the ij tool.
date: "2026-10-29T03:50:14Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:itech-gmbh:ilabclient:3.7.1:*:*:*:*:*:*:*
tags:
  - credential-access
  - local-access
  - vulnerability
vendors:
  - Itech-gmbh
products:
  - Ilabclient (3.7.1)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Cleartext passwords in iLabClient local Derby database enable credential disclosure.
    confidence_band: high
cves:
  - id: CVE-2024-56428
    cvss: 5.5
    epss: 0.00164
    kev_status: "false"
  - id: CVE-2024-56429
    cvss: 7.7
    epss: 0.00164
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-LISA-2905-CVE-2024-56428
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-LISA-2905-CVE-2024-56428&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all hosts running Itech-gmbh Ilabclient 3.7.1 and restrict local user access to the application directory.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability requires local file access to the Derby database.
  hunt_leads:
    - lead: Identify execution of the Apache Derby ij tool within the ilabClient path.
      technique_id: T1552.001
      data_needed:
        - Process creation logs (Event ID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The automated exploit script utilizes java.exe to execute the ij tool from the derby-lib directory.
  mitigation_plan:
    - priority: medium
      action: Upgrade to a patched version of Ilabclient once provided by Itech-gmbh.
      owner: IT Operations
      addresses: CVE-2024-56428
      evidence: Cleartext storage of passwords is a design vulnerability.
---

Itech-gmbh Ilabclient version 3.7.1 stores configuration data in an Apache Derby local database. Security research identifies that credentials within this database are stored in cleartext. An attacker with local access to the affected system can query the database using the Apache Derby 'ij' utility to retrieve stored credentials. This vulnerability is documented alongside CVE-2024-56429.

## Impact
Successful exploitation allows a local attacker to recover cleartext passwords from the ilabClient configuration database, potentially leading to unauthorized access to associated laboratory systems.

## Recommendation
- Audit systems running Ilabclient 3.7.1 for access to the directory 'C:\ilabClient' and its subdirectories.
- Monitor for the execution of the Apache Derby 'ij' tool within the context of the ilabClient installation directory.
- Restrict local file system permissions on the database files managed by the ilabClient to only the service account required for application operation.
