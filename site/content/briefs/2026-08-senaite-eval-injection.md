---
title: Unauthenticated Remote Code Execution in senaite.core
slug: 2026-08-senaite-eval-injection
description: An unauthenticated remote code execution vulnerability in senaite.core allows attackers to execute arbitrary Python code via a two-request chain leveraging missing authorization and unsafe eval() usage in the JSON API.
date: "2026-08-26T20:20:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - injection
  - web-application
  - senaite
vendors:
  - SENAITE
products:
  - senaite.core (2.0.0 - 2.6.0)
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The eval() runs in the Zope worker process with full Python builtins available, so a payload such as __import__('os').popen('id').read() executes arbitrary system commands.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-jrw6-7x4q-w25j
rules:
  - title: Detect senaite.core Unauthenticated JSON API Update Attempt
    description: Detects POST requests to the vulnerable senaite.core JSON API update route, which may indicate exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch senaite.core to versions addressing the vulnerabilities identified in GHSA-jrw6-7x4q-w25j.
      owner: IT Operations
      due: 24h
      evidence: Source advisory explicitly recommends applying fixes to update routes and replacing eval().
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the /@@API/update and /manage endpoints.
      owner: IT Operations
      addresses: Unauthenticated RCE via JSON API
      evidence: Source confirms endpoints are reachable and exploitable by unauthenticated attackers.
---

The senaite.core library, used in laboratory information management systems (LIMS), is vulnerable to unauthenticated remote code execution due to a two-step flaw in its JSON API handling. An attacker can exploit this by first discovering the UID of a readable object using the standard Plone @@uuid view and subsequently submitting a crafted POST request to the /@@API/update route. The update route fails to perform required authorization checks, allowing anonymous users to interact with fields. The vulnerability is triggered when the API processes input fields of type RecordsField or RecordField; the application passes these raw request strings to a Python eval() function before verifying any write permissions. This allows the execution of arbitrary commands within the Zope worker process, granting the attacker full access to the ZODB database, filesystem, and network egress, effectively leading to total system compromise. This issue affects all versions of senaite.core from 2.0.0 through 2.6.0.

## Attack Chain

1. Attacker performs a GET request to the /@@uuid endpoint on an anonymously readable object (e.g., /senaite/bika_setup/@@uuid) to retrieve its unique identifier.
2. Attacker sends a malicious POST request to the /@@API/update endpoint, targeting the previously retrieved UID via the obj_uid parameter.
3. The request passes the /@@API/update route handler, which incorrectly permits unauthenticated users to invoke state-changing actions.
4. The application logic executes the set_fields_from_request function, which iterates through provided JSON API request fields.
5. The function identifies fields designated as RecordsField or RecordField and passes the attacker-supplied string directly to the Python eval() function.
6. The eval() function interprets and executes the malicious Python payload (e.g., subprocess calls) within the context of the Zope worker process.
7. The system processes the malicious code, establishing a reverse shell or exfiltrating data, even if the subsequent write to the database fails.
8. Attacker gains durable post-exploitation persistence by interacting with the Zope Management Interface (ZMI) or modifying administrative users.

## Impact

Successful exploitation results in full remote code execution in the context of the Zope worker process. This allows unauthorized attackers to read and modify sensitive laboratory data, compromise the ZODB database, access the underlying host filesystem, and use the compromised container for lateral movement or further network activity. As the vulnerability is unauthenticated and affects default configurations, any internet-facing instance of senaite.core 2.0.0-2.6.0 is at high risk.

## Recommendation

1. Immediately apply the vendor-recommended security patch to all senaite.core instances, ensuring that AccessJSONAPI permissions are enforced across all API routes and replacing eval() calls with json.loads().
2. Block external access to the /@@API/update, /@@API/update_many, /@@API/remove, and /@@API/doActionFor endpoints at the web application firewall (WAF) or reverse proxy level until patching is completed.
3. Deploy the Sigma rule below to monitor for suspicious POST requests targeting JSON API update routes.
4. Ensure that the Zope Management Interface (ZMI) at /manage is restricted to trusted administrative IP addresses and not exposed to the public internet.
