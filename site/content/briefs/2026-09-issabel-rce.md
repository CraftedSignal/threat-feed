---
title: Hard-Coded JWT Key in Issabel Framework Enabling RCE
slug: 2026-09-issabel-rce
description: A hard-coded HS256 signing key in the Issabel Framework allows unauthenticated attackers to forge JWTs and execute arbitrary commands via the Asterisk manager originate endpoint.
date: "2026-09-15T17:42:18Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - remote-code-execution
  - pbx
  - cve-2026-89026
vendors:
  - Issabel
products:
  - Issabel Framework (< commit b97dbaf)
  - Issabel PBX
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This vulnerability allows unauthenticated remote attackers to forge valid bearer tokens.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1552.004
    technique_name: 'Unsecured Credentials: Private Keys'
    evidence: The Issabel Framework... contains a hard-coded HS256 JWT signing key... that is identical across every installation.
    confidence_band: high
cves:
  - id: CVE-2026-89026
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89026
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Issabel Framework to commit b97dbaf or later.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates commit b97dbaf as the fix.
  hunt_leads:
    - lead: Search web logs for unauthorized POST requests to pbxapi/index.php.
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation uses the pbxapi endpoint.
  mitigation_plan:
    - priority: immediate
      action: Block public network access to pbxapi web endpoints.
      owner: IT Operations
      addresses: CVE-2026-89026
      evidence: Hard-coded key allows unauthenticated RCE from remote attackers.
---

The Issabel Framework, which serves as the web management interface for Issabel PBX software, contains a critical security vulnerability (CVE-2026-89026) due to a hard-coded HS256 JWT signing key present in the 'pbxapi/index.php' file. This key is identical across all Issabel PBX installations, enabling unauthenticated remote attackers to generate valid bearer tokens. By utilizing these forged tokens, an attacker can authenticate to the 'manager originate' endpoint. This endpoint, intended for administrative control of the telephony system, accepts an 'Application' parameter that supports the 'System' command. Attackers can leverage this to execute arbitrary OS commands on the host system running with the privileges of the Asterisk user. The Shadowserver Foundation first observed exploitation of this vulnerability in the wild on September 9, 2026. This issue affects versions of the Issabel Framework prior to commit b97dbaf.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing Issabel PBX instances.
2. Attacker retrieves the hard-coded HS256 signing key from publicly available repository commits.
3. Attacker crafts a malicious JWT using the compromised secret and signs it to impersonate a privileged administrator.
4. Attacker sends an HTTP request to the '/pbxapi/index.php' endpoint or related API routes with the forged Bearer token in the Authorization header.
5. Attacker makes a request to the 'manager originate' API endpoint, injecting the 'System' application string with a malicious OS command into the request body.
6. The Asterisk service receives the command and interprets the 'System' parameter, spawning a shell process.
7. Arbitrary code executes on the underlying operating system with the permissions of the Asterisk user.

## Impact

Successful exploitation grants unauthenticated attackers full remote code execution on Issabel PBX appliances. This allows for total system compromise, including the ability to exfiltrate call records, intercept communications, or pivot into the internal network. Exploitation has been observed in the wild by the Shadowserver Foundation, indicating wide-scale scanning and targeting of vulnerable PBX infrastructure.

## Recommendation

* Immediately update Issabel Framework to commit b97dbaf or later to remove the hard-coded secret and implement unique per-installation key management.
* Restrict access to the Issabel PBX management web interface and API endpoints (pbxapi) to trusted management subnets using firewall rules.
* Monitor web server access logs for anomalous POST requests to 'pbxapi/index.php' followed by 'manager originate' parameters.
* Review all scheduled jobs and user accounts on Issabel PBX servers for signs of persistence established by the Asterisk user.
