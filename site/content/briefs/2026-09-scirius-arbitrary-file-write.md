---
title: Arbitrary File Write in Scirius PCAP Filestore Upload
slug: 2026-09-scirius-arbitrary-file-write
description: Scirius versions 3.8.0 and earlier are vulnerable to an arbitrary file write attack via the PCAP filestore upload endpoint, allowing authenticated users to perform path traversal to write files to arbitrary locations.
date: "2026-09-16T19:51:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:scirius:scirius:*:*:*:*:*:*:*:*
tags:
  - arbitrary-file-write
  - path-traversal
  - web-application
vendors:
  - Scirius
products:
  - Scirius (<= 3.8.0)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can supply path traversal sequences in the uploaded document's _id field to escape the intended directory and write files with .json extension to arbitrary locations as root.
    confidence_band: high
cves:
  - id: CVE-2026-92604
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92604
rules:
  - title: Detect CVE-2026-92604 - Arbitrary File Write via Scirius PCAP Upload
    description: Detects exploitation of CVE-2026-92604 by identifying POST requests to the PCAP filestore endpoint containing path traversal sequences in the _id parameter.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect attempted path traversal in Scirius uploads
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-92604 vulnerability description
  mitigation_plan:
    - priority: immediate
      action: Upgrade Scirius to a version greater than 3.8.0 once the vendor provides a security patch
      owner: IT Operations
      addresses: CVE-2026-92604
      evidence: NVD vulnerability disclosure
---

Scirius versions through 3.8.0 contain a critical vulnerability in the PCAP filestore upload endpoint that permits arbitrary file writes. The flaw originates from insufficient sanitization of the _id field within uploaded JSON documents processed by the endpoint. Authenticated users assigned the default User role can exploit this by injecting path traversal sequences (such as ../) into the _id field. This manipulation allows the application to write attacker-controlled JSON content to arbitrary locations on the host filesystem. Because the application processes these requests with root privileges, this vulnerability enables the creation of malicious files with a .json extension in protected directories, potentially facilitating further exploitation such as configuration manipulation or code execution.

## Impact

Successful exploitation allows authenticated low-privileged users to achieve arbitrary file writes with root privileges. This can lead to full system compromise, persistent unauthorized access, or the overwriting of critical system configuration files.

## Recommendation

- Upgrade Scirius to a patched version beyond 3.8.0 as soon as the vendor makes a fix available.
- Audit logs for the PCAP filestore upload endpoint for requests containing path traversal characters (e.g., ../) in the _id field.
- Restrict access to the PCAP filestore upload functionality to only authorized administrative accounts.
