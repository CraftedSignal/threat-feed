---
title: Information Disclosure Vulnerability in pgAdmin
slug: 2026-08-pgadmin-info-disclosure
description: An authenticated remote attacker can exploit a vulnerability in pgAdmin to access sensitive information due to improper session or configuration data management.
date: "2026-08-17T12:42:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - pgAdmin
products:
  - pgAdmin 4
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A vulnerability in pgAdmin allows a remote, authenticated attacker to perform information disclosure.
    confidence_band: high
cves:
  - id: CVE-2024-31163
    cvss: 7.2
    epss: 0.00617
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0323
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch pgAdmin 4 to the current secure version to mitigate CVE-2024-31163.
      owner: IT Operations
      due: 72h
      evidence: Source advisory specifies pgAdmin 4 is affected by an information disclosure vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Patch software
      owner: IT Operations
      addresses: CVE-2024-31163
      evidence: Official BSI security advisory.
---

The BSI has released a security advisory regarding an information disclosure vulnerability affecting pgAdmin 4. A remote, authenticated attacker can leverage this flaw to access unauthorized information by exploiting the improper handling of session or configuration data within the application. This vulnerability is tracked as CVE-2024-31163. Because the attack requires prior authentication, the primary risk is associated with internal actors or compromised accounts within the pgAdmin environment. Security teams should prioritize patching pgAdmin to the latest version to remediate the underlying configuration management issue.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive information handled by the pgAdmin instance, which may include database connection details, session tokens, or other metadata, potentially facilitating lateral movement or further exploitation within the database management layer.

## Recommendation

Update all instances of pgAdmin 4 to the vendor-provided patch version that addresses CVE-2024-31163. Monitor access logs for the pgAdmin web interface for unusual patterns or excessive data requests from authenticated users during their sessions.
