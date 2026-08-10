---
title: Remote Code Execution in SPIP SQLite Installations via CVE-2026-66738
slug: 2026-08-spip-rce
description: SPIP versions prior to 4.4.18 contain a code injection vulnerability in the navigation menu endpoint that allows authenticated editors to execute arbitrary OS commands on SQLite-backed installations.
date: "2026-08-10T17:33:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - rce
  - authentication-bypass
vendors:
  - SPIP
products:
  - SPIP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated attacker with at minimum editor (redacteur) privileges can submit a single crafted GET request to /ecrire/?exec=navigation to execute arbitrary OS commands in the web server process.
    confidence_band: high
cves:
  - id: CVE-2026-66738
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66738
rules:
  - title: Detect CVE-2026-66738 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2026-66738 by monitoring for array-typed input structures in requests to the /ecrire/ endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade SPIP to 4.4.18 or later.
      owner: IT Operations
      due: 48h
      evidence: SPIP before 4.4.18 contains a code injection vulnerability
  mitigation_plan:
    - priority: immediate
      action: Monitor /ecrire/?exec=navigation endpoint for array-type input.
      owner: SOC
      addresses: CVE-2026-66738
      evidence: The navigation menu endpoint improperly handles array-typed user input
---

SPIP versions prior to 4.4.18 are vulnerable to a remote code execution vulnerability identified as CVE-2026-66738. The flaw specifically impacts installations utilizing SQLite as a backend database. The vulnerability exists within the navigation menu functionality reachable via the /ecrire/?exec=navigation endpoint. 

An authenticated attacker with at minimum editor (redacteur) privileges can exploit this by providing crafted array-typed input to the endpoint. This input bypasses existing sanitization mechanisms, allowing the payload to break out of the intended quoted string context during PHP evaluation. Successful exploitation results in arbitrary command execution within the context of the web server process. This vulnerability does not impact MySQL-backed installations, limiting the attack surface to specific SPIP deployment configurations. Given the requirement for editor-level access, this threat is particularly relevant to environments where administrative or editorial accounts may be compromised via secondary vectors such as session hijacking or credential theft.

## Impact

Successful exploitation of CVE-2026-66738 allows an authenticated attacker to execute arbitrary OS commands, potentially leading to full system compromise of the web server. This provides the attacker the ability to exfiltrate sensitive data, install persistent backdoors, or pivot into the internal network. The impact is significant for organizations relying on SQLite-backed SPIP instances for their web presence.

## Recommendation

* Immediately upgrade all SPIP installations to version 4.4.18 or later to remediate CVE-2026-66738.
* Audit access logs for the /ecrire/?exec=navigation endpoint to identify potential exploitation attempts, specifically looking for array-typed query parameters.
* Audit editor-level account activity for anomalous access to administrative endpoints.
* If upgrading is not immediately possible, consider migrating SQLite-backed SPIP instances to a MySQL backend, as the reported vulnerability is specific to the SQLite implementation.
