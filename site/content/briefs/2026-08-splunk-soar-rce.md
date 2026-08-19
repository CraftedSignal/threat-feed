---
title: Unauthenticated Remote Code Execution in Splunk SOAR via Automation Broker
slug: 2026-08-splunk-soar-rce
description: Splunk SOAR versions prior to 8.6.0 are vulnerable to remote code execution because the Automation Broker fails to validate client-supplied source IP headers, allowing unauthenticated attackers to spoof local requests.
date: "2026-08-19T22:43:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - vulnerability
  - splunk
vendors:
  - Splunk
products:
  - Splunk SOAR
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated user could spoof the source IP address in a crafted request to an Automation Broker notification endpoint and execute arbitrary code on the Splunk SOAR host.
    confidence_band: high
cves:
  - id: CVE-2026-76356
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76356
  - https://help.splunk.com/en/splunk-soar/splunk-automation-broker/about-splunk-soar-automation-broker/about-splunk-soar-automation-broker
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Splunk SOAR to version 8.6.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-76356 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Implement WAF/firewall rules to restrict access to Automation Broker endpoint
      owner: Network Security
      addresses: CVE-2026-76356
      evidence: Vulnerability requires unauthenticated network access
---

Splunk SOAR versions below 8.6.0 contain a critical vulnerability in the Automation Broker notification endpoint. The vulnerability arises because the Automation Broker improperly trusts client-supplied source IP address headers to verify the origin of a request. An unauthenticated attacker can craft an HTTP request that spoofs the source IP to appear as though it originates from the local host, bypassing intended access controls. Successful exploitation enables the execution of arbitrary code on the underlying host, which can lead to full system compromise, data exfiltration, and service disruption. Defenders should prioritize patching Splunk SOAR instances to version 8.6.0 or later to mitigate this risk.

## Impact

Successful exploitation of CVE-2026-76356 allows an unauthenticated, remote attacker to execute arbitrary code on the Splunk SOAR host. This results in complete compromise of the SOAR platform, potential access to highly sensitive security data stored within the SOAR environment, and the ability to pivot to other integrated security tools or managed internal systems.

## Recommendation

- Upgrade all Splunk SOAR instances to version 8.6.0 or higher immediately.
- Until patching is possible, restrict network access to the Automation Broker notification endpoint to only authorized, trusted IP ranges at the network perimeter or application firewall level.
- Review web server access logs for requests to the Automation Broker endpoint originating from unexpected or external IP addresses that attempt to manipulate header fields.
