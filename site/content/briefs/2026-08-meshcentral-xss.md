---
title: Stored XSS Vulnerabilities in MeshCentral via MeshAgent Data Fields
slug: 2026-08-meshcentral-xss
description: MeshCentral versions prior to 1.1.60 are vulnerable to stored cross-site scripting (XSS) due to insufficient sanitization of data fields sent from MeshAgents, allowing attackers to execute arbitrary JavaScript in administrative browser sessions.
date: "2026-08-18T20:57:45Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - MeshCentral
products:
  - MeshCentral (< 1.1.60)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: MeshCentral versions prior to 1.1.60 are vulnerable to multiple stored cross-site scripting (XSS) attacks due to a lack of server-side sanitization on data fields received from MeshAgents.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-c7hr-448w-65px
iocs:
  - type: url
    value: https://evil.com/steal
ioc_counts:
  url: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch MeshCentral to version 1.1.60 or later
      owner: IT Operations
      due: 24h
      evidence: MeshCentral versions prior to 1.1.60 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade to v1.1.60
      owner: IT Operations
      addresses: MeshCentral XSS Vulnerability
      evidence: Source advisory recommends update to v1.1.60
---

MeshCentral versions prior to 1.1.60 contain multiple stored XSS vulnerabilities stemming from the lack of server-side sanitization for data transmitted by MeshAgents. Specifically, the 'osdesc' (Operating System description), 'node.name', and several other fields received from agents are processed and stored by the server without being scrubbed for malicious HTML or JavaScript. When an administrator views these fields in the device management UI, the application renders the raw content using innerHTML, triggering execution of the payload. Because the MeshCentral management UI's Content Security Policy (CSP) explicitly allows 'unsafe-inline' scripts, an attacker can bypass traditional script restrictions. This vulnerability allows a compromised or rogue MeshAgent to achieve full control over an administrator's browser session, facilitating actions such as cookie theft, unauthorized device management, or command execution within the context of the admin account.

## Attack Chain

1. An attacker compromises an existing MeshAgent or deploys a rogue MeshAgent instance.
2. The attacker establishes a WebSocket connection to the MeshCentral server.
3. The attacker transmits a malicious 'coreinfo' JSON payload to the server containing a crafted string in the 'osdesc' or 'node.name' field.
4. The MeshCentral server receives the message, performs only basic type validation (typeof == 'string'), and commits the malicious string to the database.
5. An administrator logs into the MeshCentral management interface and navigates to the device details or sharing panels.
6. The server fetches the malicious data from the database and sends it to the admin's browser as part of the UI response.
7. The browser renders the data via an internal function that sets the 'innerHTML' property, forcing the execution of the injected script.
8. The script executes within the admin's session, enabling exfiltration of cookies or unauthorized administrative operations.

## Impact

Successful exploitation results in Stored XSS in the MeshCentral administrative dashboard. This provides an attacker with the ability to perform any action the administrator can execute, including stealing session cookies, modifying server configuration, and gaining control over all connected agents. The impact is significant for organizations managing large fleets of devices through MeshCentral.

## Recommendation

1. Upgrade MeshCentral to version 1.1.60 or later immediately to patch the sanitization logic.
2. Review the MeshCentral management UI's Content Security Policy (CSP) to restrict or remove 'unsafe-inline' if consistent with organizational security posture.
3. Inspect MeshCentral server-side logs for unexpected 'coreinfo' WebSocket messages containing HTML or script-related characters.
4. Monitor administrative sessions for anomalous API calls originating from the MeshCentral dashboard that do not correlate with legitimate administrative activity.
