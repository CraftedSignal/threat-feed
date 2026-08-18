---
title: Path Traversal Vulnerability in Wazuh Agent Enrollment
slug: 2026-08-wazuh-path-traversal
description: A path traversal vulnerability in Wazuh versions 4.0.0 through 4.14.5 allows unauthenticated remote attackers to trigger a denial of service by sending a specially crafted agent enrollment request.
date: "2026-08-18T18:56:02Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Wazuh
products:
  - Wazuh
cves:
  - id: CVE-2026-74038
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74038
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Wazuh manager to version 4.14.6 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-74038 patch availability
  mitigation_plan:
    - priority: immediate
      action: Restrict access to TCP port 1515
      owner: IT Operations
      addresses: CVE-2026-74038
      evidence: Unauthenticated remote access vector
---

Wazuh versions 4.0.0 through 4.14.5 are vulnerable to a path traversal flaw (CVE-2026-74038) that permits unauthenticated remote attackers to disrupt service operations. The vulnerability exists within the Wazuh enrollment process, specifically due to insufficient validation in the `OS_IsValidName()` function and unsafe path concatenation in the `delete_diff()` function. 

By providing an agent name containing dot-sequence characters such as ".." during the enrollment phase over the enrollment port, an attacker can escape the intended directory structure. This triggers an unintended deletion of critical subdirectories within the queue directory. The resulting loss of required operational files forces all Wazuh services to stop, requiring manual intervention and recovery by administrators. Given the requirement for unauthenticated access to the enrollment port, this vulnerability presents a significant risk to the availability of the Wazuh management infrastructure.

## Impact

Successful exploitation results in a complete denial of service of the Wazuh instance. Attackers can remotely halt all Wazuh services, requiring manual recovery efforts to restore system monitoring and logging capabilities. This vulnerability affects all Wazuh deployments prior to version 4.14.6.

## Recommendation

- Upgrade all Wazuh manager instances to version 4.14.6 or later immediately to incorporate the patch for CVE-2026-74038.
- Restrict network access to the Wazuh enrollment port (default TCP/1515) to trusted network segments to prevent unauthenticated remote access.
- Review Wazuh manager logs for anomalous agent enrollment attempts containing directory traversal sequences or unexpected character sets in the agent name field.
