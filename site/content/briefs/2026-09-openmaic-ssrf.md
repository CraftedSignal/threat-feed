---
title: Unauthenticated SSRF Vulnerability in OpenMAIC
slug: 2026-09-openmaic-ssrf
description: OpenMAIC versions prior to 1.0.1 contain a vulnerability in non-production builds that allows unauthenticated attackers to perform SSRF by manipulating request headers or parameters to access cloud metadata services.
date: "2026-09-06T14:46:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openmaic:openmaic:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ssrf
  - cloud-security
vendors:
  - OpenMAIC
products:
  - OpenMAIC (< 1.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenMAIC before 1.0.1 skips server-side request forgery validation in non-production builds, allowing unauthenticated attackers to reach cloud instance metadata services.
    confidence_band: high
cves:
  - id: CVE-2026-86259
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86259
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade OpenMAIC to version 1.0.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies version 1.0.1 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to metadata services for non-production OpenMAIC instances
      owner: Security Engineering
      addresses: CVE-2026-86259
      evidence: Mitigation limits the impact of SSRF against metadata services.
---

OpenMAIC versions prior to 1.0.1 are vulnerable to a Server-Side Request Forgery (SSRF) flaw due to insufficient validation logic in non-production builds. The vulnerability arises because the application fails to properly sanitize or validate user-supplied input when processing outgoing requests. Unauthenticated attackers can leverage this oversight by injecting malicious values into the 'x-base-url' HTTP header or the 'baseUrl' query parameter. 

By forcing the OpenMAIC server to redirect requests to internal endpoints, specifically cloud instance metadata services (such as those hosted on 169.254.169.254 in AWS, GCP, or Azure environments), an attacker can retrieve sensitive information, including temporary cloud identity credentials, environment variables, and instance configuration data. This vulnerability is particularly critical for deployments that rely on non-production builds for testing or staging purposes, as it provides a direct pathway for lateral movement and privilege escalation within the cloud environment.

## Impact

Successful exploitation allows unauthenticated attackers to retrieve sensitive cloud credentials and metadata, potentially leading to full compromise of the affected cloud instance's identity and subsequent unauthorized access to broader cloud infrastructure.

## Recommendation

* Upgrade all OpenMAIC installations to version 1.0.1 or later immediately to patch the SSRF validation logic.
* Audit all non-production deployments of OpenMAIC to ensure they are not exposed to the public internet.
* Implement egress filtering at the cloud network layer to block access to sensitive metadata services (169.254.169.254) from non-essential application containers or VMs.
* Review logs for HTTP requests containing suspicious values in the 'x-base-url' header or 'baseUrl' parameter directed at internal network resources.
