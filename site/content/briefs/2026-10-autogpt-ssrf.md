---
title: CVE-2026-33234 SSRF Vulnerability in AutoGPT Platform
slug: 2026-10-autogpt-ssrf
description: CVE-2026-33234 is an SSRF vulnerability in the AutoGPT Platform that allows authenticated users to bypass IP blocklists via the SendEmailBlock component to conduct internal network reconnaissance and banner grabbing.
date: "2026-10-19T20:23:01Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:significant_gravitas:autogpt_platform:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - reconnaissance
  - vulnerability
  - autogpt
vendors:
  - Significant Gravitas
products:
  - AutoGPT Platform (<= 0.6.51)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The HTTP layer was locked down tight... then I traced the code path and found that smtplib.SMTP() opens a raw TCP socket.
    confidence_band: high
cves:
  - id: CVE-2026-33234
    cvss: 5
    epss: 0.00373
references:
  - https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-4jwj-6mg5-wrwf
rules:
  - title: Detect Potential SSRF via AutoGPT SendEmailBlock
    description: Detects attempts to use the AutoGPT SendEmailBlock for internal scanning by identifying API requests with internal IP addresses in the smtp_server parameter.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade AutoGPT Platform to version 0.6.52.
      owner: IT Operations
      due: 48h
      evidence: 'Fixed in: autogpt-platform-backend 0.6.52.'
  hunt_leads:
    - lead: Identify abnormal SMTP connection attempts in logs originating from the AutoGPT application servers.
      technique_id: T1595.005
      data_needed:
        - Network firewall logs showing outbound connections from AutoGPT backend IPs to internal subnets.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The platform protected every outbound door except the one labeled outgoing mail.
  mitigation_plan:
    - priority: immediate
      action: Apply egress filtering on AutoGPT server network segment to prevent access to internal IPs.
      owner: IT Operations
      addresses: CVE-2026-33234
      evidence: The platform protected every outbound door except the one labeled outgoing mail.
---

CVE-2026-33234 is a Server-Side Request Forgery (SSRF) vulnerability discovered in the AutoGPT Platform. The vulnerability exists within the 'SendEmailBlock' component, which accepts user-supplied SMTP server and port parameters. The platform performs standard IP blocklist enforcement for HTTP-based traffic, but the 'SendEmailBlock' utilizes the Python 'smtplib' library to initiate raw TCP connections, which bypass these protections.

An authenticated attacker can manipulate these parameters to scan internal network infrastructure. Because the application processes 'smtplib' connection errors and exposes them in the block execution output, an attacker can receive raw banner data, such as SSH, Redis, or MySQL service signatures. This enables internal network mapping, identification of running services, and enumeration of service versions, facilitating further targeted exploitation. The issue was addressed by Significant Gravitas in version 0.6.52.

## Attack Chain

1. Attacker authenticates to the AutoGPT Platform via the API or dashboard.
2. Attacker invokes the 'SendEmailBlock' execution API via a POST request to /api/blocks/execute.
3. Attacker injects internal network IP addresses and arbitrary ports into the 'smtp_server' and 'smtp_port' input fields.
4. The 'SendEmailBlock' passes these inputs directly to the 'smtplib.SMTP()' function.
5. The backend initiates an unvalidated raw TCP connection to the specified internal target, bypassing the HTTP-layer IP filter.
6. The target service responds; if a service is listening, the response is captured as an SMTP greeting.
7. The application returns an 'SMTPConnectError' containing the raw service banner (e.g., SSH version string) to the attacker.
8. Attacker uses the leaked banner information to identify vulnerable services within the internal network.

## Impact

Successful exploitation allows for the discovery and reconnaissance of internal network segments that should be unreachable from the application environment. This includes sensitive internal cloud metadata endpoints, management interfaces, and database services. The leakage of exact software versions enables attackers to prioritize follow-on attacks based on known CVEs.

## Recommendation

1. Upgrade 'AutoGPT Platform' to version 0.6.52 or later to apply input validation and port restrictions for the SMTP configuration.
2. Implement outbound network egress filtering at the firewall or cloud VPC level to prevent the AutoGPT backend from reaching internal, non-SMTP infrastructure.
3. Monitor web server and API logs for high volumes of 'SMTPConnectError' entries or unusual 'smtp_server' inputs in block execution requests.
