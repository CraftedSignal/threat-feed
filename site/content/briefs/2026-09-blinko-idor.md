---
title: Blinko Authorization Bypass via Insecure Direct Object Reference
slug: 2026-09-blinko-idor
description: Blinko version 1.8.7 is vulnerable to an IDOR flaw in multiple tRPC procedures, allowing authenticated users to access, modify, or delete the AI chat history of other users.
date: "2026-09-04T15:27:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:blinko:blinko:1.8.7:*:*:*:*:*:*:*
vendors:
  - Blinko
products:
  - Blinko (1.8.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Any authenticated user can therefore read another user's full AI chat history, modify individual message content, and delete or wipe entire conversations by enumerating sequential integer IDs.
    confidence_band: high
cves:
  - id: CVE-2026-85607
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85607
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  hunt_leads:
    - lead: Authenticated user accounts accessing or modifying message/conversation IDs not associated with their user profile
      technique_id: T1068
      data_needed:
        - Application-level tRPC request logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Any authenticated user can... modify individual message content, and delete or wipe entire conversations by enumerating sequential integer IDs.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Blinko to the latest version that patches CVE-2026-85607
      owner: IT Operations
      addresses: CVE-2026-85607
      evidence: Source confirms IDOR vulnerability in version 1.8.7
---

Blinko version 1.8.7 contains an Insecure Direct Object Reference (IDOR) vulnerability within multiple tRPC procedures located in 'server/routerTrpc/message.ts' and 'server/routerTrpc/conversation.ts'. The affected procedures include message.list, message.update, message.delete, message.clearAfter, and conversation.clearMessages. While the application requires authentication to access these functions, the server fails to perform authorization checks to ensure the requested resource belongs to the authenticated user. By providing an arbitrary, enumerated conversation or message ID, an attacker can access the private AI chat history of any user on the system. This vulnerability enables unauthorized data exfiltration, the manipulation of sensitive conversation content, and the permanent destruction of user data through message or conversation deletion. Defenders should prioritize patching this vulnerability due to the potential for large-scale data compromise in multi-user Blinko environments.

## Impact

Successful exploitation allows any authenticated user to read, modify, or delete the private AI chat history of other users. In a multi-user deployment, this leads to unauthorized information disclosure and loss of data integrity, with the risk of clearing entire chat databases through sequential ID enumeration.

## Recommendation

Prioritize upgrading Blinko to the latest secure version addressing CVE-2026-85607. Monitor application-level logs for high-frequency tRPC request patterns where a single authenticated user session requests or deletes an abnormally high number of distinct conversation or message IDs within a short timeframe.
