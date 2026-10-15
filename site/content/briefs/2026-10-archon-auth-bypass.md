---
title: Unauthenticated RCE in Archon API
slug: 2026-10-archon-auth-bypass
description: Archon versions 0.2.13 through 0.11.1 contain a missing authentication vulnerability allowing unauthenticated, network-adjacent attackers to execute arbitrary commands via the /api/* control API.
date: "2026-10-15T22:41:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:archon:archon:*:*:*:*:*:*:*:*
vendors:
  - Archon
products:
  - Archon (0.2.13 - 0.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Archon 0.2.13 through 0.11.1 contains a missing authentication vulnerability that allows unauthenticated attackers to access the /api/* control API.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers with network access can send messages to the AI coding agent... to execute commands on the host as the Archon user.
    confidence_band: high
cves:
  - id: CVE-2026-111322
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111322
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to Archon /api/* endpoints via firewall
      owner: IT Operations
      due: 24h
      evidence: Service binds to 0.0.0.0 by default
  mitigation_plan:
    - priority: immediate
      action: Upgrade Archon to version 0.11.2 or higher once released
      owner: IT Operations
      addresses: CVE-2026-111322
      evidence: NVD vulnerability disclosure
---

Archon versions 0.2.13 through 0.11.1 are susceptible to a critical authentication bypass vulnerability (CVE-2026-111322) affecting the control API endpoints. The application binds its control interface to 0.0.0.0 by default, exposing the API to all network interfaces. Because the service lacks proper access control for the /api/* namespace, unauthenticated remote attackers can interact with the embedded AI coding agent. The agent is configured to operate with elevated privileges, allowing successful exploitation to result in arbitrary command execution on the host machine under the security context of the Archon service user. This vulnerability represents a significant risk for any developer environments or production servers where Archon is exposed to network traffic.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain full command execution on the host machine. This grants the attacker the ability to exfiltrate source code, manipulate local files, or pivot further into the internal network from the compromised host. As of the disclosure date, the vulnerability affects all deployments within the specified version range.

## Recommendation

* Immediately restrict network access to the Archon control API using host-based firewalls or network access control lists to prevent unauthenticated access from unauthorized segments.
* Upgrade Archon to a version beyond 0.11.1 as soon as the vendor provides a security patch to address the underlying authentication flaw.
* Audit host process logs for any unexpected child processes spawned by the Archon application user, as this indicates potential agent abuse or malicious command execution.
