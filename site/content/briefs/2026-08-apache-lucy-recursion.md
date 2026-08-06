---
title: Uncontrolled Recursion Vulnerability in Apache Lucy
slug: 2026-08-apache-lucy-recursion
description: Apache Lucy, a retired project, contains an uncontrolled recursion vulnerability (CVE-2026-61483) for which no patch will be issued due to the project's end-of-life status.
date: "2026-08-06T19:26:31Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:apache:lucy:*:*:*:*:*:*:*:*
vendors:
  - Apache
products:
  - Lucy
cves:
  - id: CVE-2026-61483
    cvss: 7.5
    epss: 0.00149
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61483
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Architecture
  immediate_actions:
    - action: Inventory enterprise assets for Apache Lucy dependencies
      owner: IT Operations
      due: 72h
      evidence: Apache Lucy is a retired project with no available patches for CVE-2026-61483
  mitigation_plan:
    - priority: immediate
      action: Network-level isolation of legacy Apache Lucy instances
      owner: Security Architecture
      addresses: CVE-2026-61483
      evidence: Maintainers recommend restricting access to instances to trusted users
---

Apache Lucy has been identified as containing an uncontrolled recursion vulnerability, tracked as CVE-2026-61483. This flaw allows for potential exploitation due to insufficient bounds checking on recursive calls within the software, which can lead to application crashes or denial-of-service conditions when triggered. The vulnerability affects all versions of the Apache Lucy software. Because the Apache Lucy project is currently retired, the maintainers have confirmed that no security patches will be developed or released to address this issue. Organizations currently utilizing Apache Lucy in their production environments are strongly advised to migrate to alternative software or isolate instances by restricting network access to strictly trusted users.

## Impact

The vulnerability carries a CVSS v3.1 base score of 7.5, indicating a high risk to availability. Exploitation of the recursion flaw could lead to a persistent denial-of-service state for applications dependent on the library. Since the software is unmaintained, systems remaining on this platform will have no path to remediation, leaving them permanently exposed to any future discovered vulnerabilities.

## Recommendation

* Conduct an internal audit to identify any legacy instances of Apache Lucy within the environment.
* Prioritize the migration of all identified Apache Lucy instances to a supported search engine or library alternative.
* If migration is not immediately feasible, deploy network segmentation or application-level firewalls to restrict access to the affected instances to only explicitly trusted, internal-only endpoints.
