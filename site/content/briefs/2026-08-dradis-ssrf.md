---
title: Authorization Bypass and SSRF in Dradis Community Edition
slug: 2026-08-dradis-ssrf
description: An authorization bypass vulnerability in Dradis Community Edition allows authenticated users to execute SSRF attacks by injecting malicious AI provider configurations.
date: "2026-08-25T20:49:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - ssrf
  - vulnerability
  - authorization-bypass
vendors:
  - Dradis
products:
  - Dradis Community Edition
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The authorization bypass allows an authenticated user to perform SSRF.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage Object
    evidence: The attacker can target cloud metadata services and read responses to exfiltrate metadata or credentials.
    confidence_band: high
cves:
  - id: CVE-2026-79788
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79788
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict egress traffic from Dradis application server to local metadata IPs and internal subnets.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-79788 allows SSRF against internal resources.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Dradis Community Edition to the latest secure version.
      owner: IT Operations
      addresses: CVE-2026-79788
      evidence: Vendor patch availability.
---

Dradis Community Edition contains an authorization bypass vulnerability (CVE-2026-79788) within the ProvidersController and AgentsController. The application improperly gates the `admin_required` before_action by checking for the `Dradis::Pro` constant, which is never defined in the Community Edition. This failure causes the authorization check to be skipped entirely, allowing any authenticated, non-privileged user to modify AI provider and agent configurations. Attackers can leverage this to create malicious AI providers that point to internal or cloud-local network addresses, including metadata services such as 169.254.169.254. When an AI interaction is subsequently triggered, the application performs an outbound request to the attacker-defined URL. Because the application reflects response bodies of non-2xx status codes via ActionCable/Turbo Stream, an attacker can read the content of internal network resources, leading to potential data exfiltration.

## Impact

Successful exploitation allows authenticated users to perform server-side request forgery against internal resources or cloud metadata services. This can result in unauthorized access to sensitive internal configuration data, cloud environment credentials, or metadata, facilitating deeper compromise of the environment.

## Recommendation

- Monitor web server and application logs for unexpected outbound connections from the Dradis server, particularly to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 169.254.169.254).
- Review access logs for non-administrative users interacting with the `/providers` and `/agents` controller endpoints.
- Apply security patches or updates provided by the vendor to address CVE-2026-79788.
- Implement egress filtering at the network level to restrict the Dradis server from initiating requests to internal or metadata-related IP addresses.
