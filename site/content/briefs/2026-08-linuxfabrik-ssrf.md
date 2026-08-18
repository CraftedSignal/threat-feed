---
title: SSRF Vulnerability in Linuxfabrik monitoring-plugins Leading to Credential Leak
slug: 2026-08-linuxfabrik-ssrf
description: A Server-Side Request Forgery vulnerability in Linuxfabrik monitoring-plugins 6.0.0 and earlier allows attackers to leak BMC credentials by manipulating @odata.id parameters to redirect requests to malicious endpoints.
date: "2026-08-18T14:30:24Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Linuxfabrik
products:
  - monitoring-plugins
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552.001
    technique_name: Unsecured Credentials
    evidence: The plugin re-fetches with the Redfish Authorization header attached, leaking BMC credentials to an attacker host.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52653
  - https://github.com/Pig-Tail/security-research/tree/master/GHSA-96fx-pqc3-28xv-monitoring-plugins
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade monitoring-plugins to 6.0.1
      owner: IT Operations
      due: 24h
      evidence: Vendor fix version identified in advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict egress traffic from monitoring server
      owner: IT Operations
      addresses: SSRF credential exfiltration
      evidence: Vulnerability allows egress of credentials via SSRF
---

Security researchers have identified a Server-Side Request Forgery (SSRF) vulnerability in Linuxfabrik monitoring-plugins version 6.0.0 and earlier. The flaw exists within the plugin's interaction with Redfish-compatible Baseboard Management Controllers (BMC). Specifically, when the plugin processes an @odata.id attribute that lacks a leading forward slash, it improperly rewrites the request authority. 

When this occurs, the plugin initiates a new request to the attacker-controlled authority, mistakenly including the sensitive 'Authorization' header containing the BMC credentials. This allows an attacker positioned to influence the @odata.id response from a BMC or an intermediate proxy to intercept the credentials. This vulnerability is tracked under GHSA-96fx-pqc3-28xv and was addressed in version 6.0.1.

## Impact

The vulnerability results in the unauthorized disclosure of BMC credentials, which could lead to full administrative compromise of affected server hardware. By obtaining these credentials, an attacker can gain persistent access to the management interface, potentially allowing them to modify hardware configurations, power-cycle systems, or access sensitive diagnostic data.

## Recommendation

- Upgrade to Linuxfabrik monitoring-plugins version 6.0.1 or later immediately.
- Audit logs for unauthorized egress traffic originating from the monitoring server, specifically focusing on connections to unknown or unexpected external IP addresses on management-related ports.
- Implement network-level segmentation to restrict the monitoring server's ability to initiate connections to unauthorized external hosts.
