---
brief_id: brief-2026-10-23-apache-camel-docling-traversal
event_id: brief-2026-10-23-apache-camel-docling-traversal
revision: 1
activity_at: "2026-10-23T14:58:09Z"
title: 'Apache Camel: Path traversal in camel-docling (CVE-2026-95629)'
slug: 2026-10-apache-camel-docling-traversal
description: An unvalidated output path header in the Apache Camel camel-docling component allows authenticated attackers to perform path traversal and write converted files to arbitrary directories on the host filesystem.
date: "2026-10-23T14:58:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
vendors:
  - Apache Software Foundation
products:
  - Apache Camel (4.15.0 <= version < 4.18.5)
  - Apache Camel (4.19.0 <= version < 4.22.2)
cves:
  - id: CVE-2026-95629
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/345
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Apache Camel camel-docling to version 4.18.5 or 4.22.2.
      owner: IT Operations
      due: 72h
      evidence: Source notes affected versions and provided fixed versions.
  hunt_leads:
    - lead: Hunt for file creation events originating from the application service process that target sensitive directories outside the expected output folder.
      data_needed:
        - Application audit logs or file system monitoring (e.g., Sysmon Event ID 11)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows writing converted files to arbitrary directories via unvalidated path headers.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches or upgrade to the non-vulnerable versions.
      owner: IT Operations
      addresses: CVE-2026-95629
      evidence: Source identifies versions 4.18.5 and 4.22.2 as fixed.
---

Apache Camel versions using the camel-docling component (4.15.0 to 4.18.4 and 4.19.0 to 4.22.1) are vulnerable to a path traversal issue (CVE-2026-95629). An authenticated user can supply a crafted output path header to manipulate where the component writes converted file outputs, potentially leading to unauthorized file overwrites or service disruption.

## Impact

Successful exploitation allows an authenticated attacker to write files outside of the intended directory. This can lead to unauthorized file modification, potential corruption of critical system files, or denial of service by overwriting application-specific configuration or binary files.

## Recommendation

- Upgrade Apache Camel camel-docling to version 4.18.5 or later for the 4.15.x branch.
- Upgrade Apache Camel camel-docling to version 4.22.2 or later for the 4.19.x branch.
- Audit application logs for abnormal file system write operations originating from the camel-docling service process if patching cannot be performed immediately.
