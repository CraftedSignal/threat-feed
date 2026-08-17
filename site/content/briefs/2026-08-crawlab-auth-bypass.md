---
title: Authorization Bypass in Crawlab Password Change Endpoint
slug: 2026-08-crawlab-auth-bypass
description: An authorization bypass vulnerability in Crawlab (CVE-2026-75103) allows authenticated users to reset the passwords of any account, enabling administrator takeover and subsequent arbitrary code execution.
date: "2026-08-17T22:51:18Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Crawlab
products:
  - Crawlab (0.6.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can enumerate user accounts through the user listing endpoint and change administrator credentials to achieve full account takeover.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Change administrator credentials to achieve full account takeover and arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-75103
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75103
  - https://www.vulncheck.com/advisories/crawlab-missing-authorization-on-password-change-endpoint-allows-account-takeover
  - https://github.com/crawlab-team/crawlab/issues/1623
rules:
  - title: Detect CVE-2026-75103 Exploitation - Password Reset via User Listing
    description: Detects potential exploitation of CVE-2026-75103 by identifying suspicious patterns of user enumeration followed by password changes on the same Crawlab instance.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Crawlab to version > 0.6.3
      owner: IT Operations
      due: 48h
      evidence: Affected version range 0.6.3 and earlier
    - action: Deploy webserver detection rule
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-75103 exploitation pattern
---

Crawlab, an open-source distributed web crawler platform, contains an authorization bypass vulnerability (CWE-639) affecting versions 0.6.3 and earlier. The flaw resides in the password-change endpoint, which fails to verify whether the requester owns the account or possesses administrative privileges. This design failure allows any authenticated user to change the password for any other user, including administrative accounts. An attacker who gains a foothold as a low-privileged user can leverage this endpoint to perform account takeover, obtain administrative access, and subsequently execute arbitrary code on the underlying server. This vulnerability is significant because it provides an easy path to full system compromise for any attacker with basic credentials.

## Attack Chain

1. Attacker obtains valid credentials for a low-privileged account on the Crawlab instance.
2. Attacker logs into the Crawlab web interface using the acquired credentials.
3. Attacker accesses the user listing endpoint to identify existing accounts, specifically targeting accounts with administrative roles.
4. Attacker constructs an HTTP request targeting the vulnerable password-change endpoint.
5. Attacker submits the password-change request with the target administrator's account identifier and a new, known password.
6. The backend fails to validate the authorization of the request, updating the administrative account password.
7. Attacker logs into the system using the compromised administrator credentials.
8. Attacker leverages administrative functionality, such as custom crawler task management, to achieve arbitrary code execution.

## Impact

Successful exploitation of CVE-2026-75103 results in complete account takeover, leading to unauthorized access to all crawler data and administrative control over the Crawlab instance. Because Crawlab is designed to execute custom code for scraping, an administrator can trigger remote code execution (RCE) on the server, potentially leading to full host compromise, lateral movement within the network, and exfiltration of sensitive harvested data.

## Recommendation

* Immediately upgrade Crawlab instances to the latest patched version to remediate CVE-2026-75103.
* Audit access logs for the password-change endpoint to identify anomalous password reset activity originating from non-administrative users.
* Monitor for unauthorized or suspicious user account enumeration requests via the Crawlab API endpoints.
* Enforce strict network segmentation for web scraping infrastructure to limit the blast radius of a potential RCE event.
