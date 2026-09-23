---
title: XXE Vulnerability in MPXJ MerlinReader
slug: 2026-09-mpxj-xxe
description: MPXJ is vulnerable to an XML External Entity (XXE) injection flaw via the MerlinReader component when processing XML content within the ZTIMEINTERVALS column of Merlin project SQLite files, allowing for arbitrary file reads.
date: "2026-09-23T07:55:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mpxj:mpxj:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - xxe
  - java
  - .net
  - python
  - ruby
vendors:
  - MPXJ
products:
  - mpxj (>= 5.5.5, < 16.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: MPXJ used the default configuration when creating a DocumentBuilder instance, which leaves doctype declarations enabled, when parsing the XML content of the ZTIMEINTERVALS column from a Merlin project SQLite file.
    confidence_band: high
cves:
  - id: CVE-2026-61570
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-5vvx-3h34-f3gj
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade MPXJ to version 16.4.1 or later across all projects.
      owner: IT Operations
      addresses: CVE-2026-61570
      evidence: The patch is included in MPXJ 16.4.1
---

The MPXJ project library contains an XML External Entity (XXE) injection vulnerability (CVE-2026-61570) within its MerlinReader component. The issue originates from the use of default DocumentBuilder configurations that do not disable Document Type Definition (DTD) processing when parsing XML content stored in the ZTIMEINTERVALS column of Merlin project SQLite files. 

An attacker can supply a malicious Merlin project file containing a crafted XML payload to trigger the vulnerability. While the current processing logic within MPXJ limits the ability to exfiltrate the contents of the read files, the vulnerability exposes local system files to unauthorized access. This issue affects multiple language ports including Maven, RubyGems, NuGet, and Python/pip packages for MPXJ versions 5.5.5 through 16.4.0. Users are advised to upgrade to MPXJ 16.4.1 or later to resolve this vulnerability.

## Impact

The vulnerability allows an attacker to perform arbitrary file reads on the system where the MPXJ library parses untrusted Merlin project files. While successful exploitation is hindered by subsequent application logic preventing direct exfiltration of the data, it represents a high-severity security risk for any software component or enterprise application utilizing MPXJ to process external Merlin project files.

## Recommendation

* Upgrade all instances of MPXJ to version 16.4.1 or later to remediate CVE-2026-61570.
* Implement strict validation of Merlin project files before ingestion into any application utilizing the MPXJ library.
* If upgrading is not immediately possible, implement pre-processing steps to strip doctype declarations from the ZTIMEINTERVALS column of Merlin SQLite databases prior to passing them to the reader.
