---
title: Heap Out-of-Bounds Read in pgPointcloud
slug: 2026-09-pgpointcloud-oob
description: pgPointcloud versions through 1.2.5 contain a heap out-of-bounds read vulnerability in WKB deserialization that allows authenticated database users to exfiltrate heap memory or trigger backend service crashes.
date: "2026-09-25T22:55:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pgpointcloud_project:pgpointcloud:*:*:*:*:*:postgresql:*:*
vendors:
  - PostgreSQL
products:
  - pgPointcloud (<= 1.2.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: pgPointcloud through 1.2.5 contains a heap out-of-bounds read vulnerability in dimensional patch WKB deserialization.
    confidence_band: high
cves:
  - id: CVE-2026-100387
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100387
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review and restrict access to pgPointcloud extension functions for untrusted database users.
      owner: SOC
      due: 48h
      evidence: authenticated database users to read adjacent heap memory.
  mitigation_plan:
    - priority: immediate
      action: Monitor PostgreSQL service logs for unexpected crash loops or segmentation faults.
      owner: IT Operations
      addresses: CVE-2026-100387
      evidence: or crash the PostgreSQL backend.
---

pgPointcloud through version 1.2.5 is susceptible to a heap out-of-bounds read vulnerability occurring during the deserialization of dimensional patch Well-Known Binary (WKB) data. This flaw stems from improper handling of size fields within the input data, which can be manipulated by an authenticated database user. By providing a crafted pcpatch value, an attacker can trick the PostgreSQL backend into reading and returning memory addresses outside of the allocated buffer. This can result in the leakage of sensitive data stored in the database heap or the termination of the backend process, leading to a denial-of-service condition. This vulnerability is significant for organizations utilizing the pgPointcloud extension for spatial data processing, as it permits unauthorized access to database memory from within the database environment.

## Impact

Successful exploitation allows an authenticated user to perform unauthorized information disclosure by reading adjacent memory segments, potentially exposing credentials, cryptographic keys, or sensitive records. Furthermore, the ability to induce an out-of-bounds read often leads to memory corruption, enabling attackers to crash the PostgreSQL backend service, which disrupts database availability for all users.

## Recommendation

Prioritized actions include:

- Update the pgPointcloud extension to the latest secure version addressing this vulnerability once available.
- Review database access controls and minimize privileges for users with the ability to execute spatial functions or interact with pgPointcloud objects.
- Monitor PostgreSQL logs for frequent backend crashes or service restarts that may indicate attempted exploitation of this memory corruption vulnerability.
