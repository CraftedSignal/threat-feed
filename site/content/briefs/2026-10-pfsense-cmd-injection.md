---
title: OS Command Injection in Netgate pfSense CE QinQ Interface Configuration
slug: 2026-10-pfsense-cmd-injection
description: Authenticated users with QinQ edit privileges can leverage an OS command injection vulnerability in Netgate pfSense CE 2.7.0 through 2.9.0 to execute arbitrary commands as root.
date: "2026-10-15T20:40:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:netgate:pfsense:2.7.0:*:*:*:*:*:*:*
  - cpe:2.3:a:netgate:pfsense:2.9.0:*:*:*:*:*:*:*
vendors:
  - Netgate
products:
  - pfSense CE (2.7.0 through 2.9.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Authenticated users with QinQ edit privilege to run commands by storing an unvalidated parent interface name.
    confidence_band: high
cves:
  - id: CVE-2026-111214
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111214
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review and restrict QinQ interface configuration privileges for non-administrative accounts
      owner: IT Operations
      due: 24h
      evidence: Vulnerability requires QinQ edit privileges for exploitation
  mitigation_plan:
    - priority: immediate
      action: Upgrade pfSense CE to the latest version once available beyond 2.9.0
      owner: IT Operations
      addresses: CVE-2026-111214
      evidence: Vulnerability exists in 2.7.0 through 2.9.0
---

Netgate pfSense CE versions 2.7.0 through 2.9.0 contain an OS command injection vulnerability within the QinQ interface configuration module. The vulnerability exists due to improper validation of the parent interface name field when editing a QinQ entry. An authenticated attacker with sufficient privileges (QinQ edit access) can provide a crafted input string that is improperly sanitized and subsequently passed to the underlying ifconfig shell command. When the system processes the interface configuration, the injected command is executed with root privileges, leading to full system compromise. This issue highlights the risks associated with improper input handling in network appliance management interfaces.

## Impact

Successful exploitation allows an authenticated user to elevate their access level to root on the affected pfSense firewall, enabling full control over the network device, data interception, and persistence mechanisms. This affects all installations of pfSense CE versions 2.7.0 through 2.9.0.

## Recommendation

Prioritize the update of all affected pfSense CE installations to a version beyond 2.9.0 once the vendor releases a patch. As an immediate mitigation, review administrative access logs and restrict the 'QinQ edit' privilege to only highly trusted and necessary accounts to minimize the potential attack surface.
