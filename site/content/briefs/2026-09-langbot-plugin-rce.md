---
title: Unauthenticated Remote Access and Plugin Injection in LangBot langbot_plugin
slug: 2026-09-langbot-plugin-rce
description: The LangBot langbot_plugin (<= 0.4.17) exposes an unauthenticated debug WebSocket server on port 5401, allowing remote attackers to intercept chat traffic, inject malicious LLM tools, and trigger persistent denial-of-service via plugin registration conflicts.
date: "2026-09-14T13:34:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:langbot:langbot_plugin:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - web-application
  - cve-2026-90938
vendors:
  - LangBot
products:
  - langbot_plugin (<= 0.4.17)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker's plugin receives the full context of every IM message event and can inject forged replies, send messages as any configured bot, and invoke configured LLM models.
    confidence_band: high
cves:
  - id: CVE-2026-90938
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90938
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict network access to TCP port 5401 via host firewall or cloud security groups
      owner: IT Operations
      due: 24h
      evidence: Source states that the debug server is exposed to 0.0.0.0 and port 5401 is published to the host.
  mitigation_plan:
    - priority: immediate
      action: Disable or block access to the /plugin/ws WebSocket endpoint
      owner: IT Operations
      addresses: CVE-2026-90938
      evidence: Vulnerability allows unauthenticated plugin registration via the /plugin/ws WebSocket server.
---

The LangBot plugin runtime, specifically the `langbot_plugin` Python package versions 0.4.17 and earlier, contains a critical vulnerability regarding its debug WebSocket server. The server, accessible at `/plugin/ws` on port 5401, is bound to 0.0.0.0 by default. Authentication for this endpoint relies on a `plugin_debug_key` configuration variable; however, the software defaults this key to an empty string. Because the upstream repository, Docker images, and `docker-compose` configurations fail to set or enforce this key, the authentication check is bypassed entirely. 

This allows any remote attacker with network reach to port 5401 to register arbitrary "debug plugins." Once registered, the attacker's plugin is granted full access to the event broadcast stream, which contains plaintext IM messages, user IDs, and metadata from all conversations. Furthermore, the attacker can leverage the plugin runtime to invoke LLM models, read knowledge-base contents, and register malicious tools into the message pipeline. Additionally, an attacker can cause a persistent denial-of-service by registering a plugin with `prod_mode` set to true, which prevents subsequent legitimate plugin installations.

## Impact

Successful exploitation allows for full surveillance of internal IM communications processed by the bot, data exfiltration from knowledge bases, and the injection of unauthorized LLM prompts or replies. By deploying conflicting plugins in `prod_mode`, an attacker can effectively disable legitimate bot functionality, impacting business operations that rely on the LangBot for automated communication or LLM interaction.

## Recommendation

Prioritize network segmentation and access control to mitigate exposure while awaiting an official patch.
- Implement firewall or security group rules to restrict access to port 5401 (TCP) to only trusted administrative IP addresses.
- Audit existing deployments to determine if the `docker-compose` configuration is exposing port 5401 to the internet or untrusted subnets.
- Monitor logs for unauthorized WebSocket connections to `/plugin/ws` if application-level logging is available for the LangBot runtime.
