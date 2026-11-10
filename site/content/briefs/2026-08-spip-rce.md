---
brief_id: brief-2026-08-spip-rce
event_id: brief-2026-08-spip-rce
revision: 2
activity_at: "2026-11-10T17:01:34Z"
revision_history:
  - revision: 2
    at: "2026-11-10T17:01:34Z"
    checksum: sha256:5438c2652fe0baa6cfaf56b12b2ddb6d858374c64d41bb630d0ce94ddce6c042
    summary: poc_available; spip version < 4.4.18
    changed_fields:
      - affected_products
      - claim_state
      - cpes
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=345DF3E7-56B8-5487-831A-A1CEB9B62D1E&utm_source=rss&utm_medium=rss
title: Remote Code Execution in SPIP SQLite Installations via CVE-2026-66738
slug: 2026-08-spip-rce
description: SPIP versions prior to 4.4.18 contain a code injection vulnerability in the navigation menu endpoint that allows authenticated editors to execute arbitrary OS commands on SQLite-backed installations.
date: "2026-08-10T17:33:39Z"
lastmod: "2026-11-10T16:59:51Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified against NVD
cpes:
  - cpe:2.3:a:spip:spip:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=345DF3E7-56B8-5487-831A-A1CEB9B62D1E&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - rce
  - authentication-bypass
vendors:
  - SPIP
products:
  - SPIP (< 4.4.18)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: An authenticated attacker with at minimum editor (redacteur) privileges can submit a single crafted GET request to /ecrire/?exec=navigation to execute arbitrary OS commands in the web server process.
    confidence_band: high
cves:
  - id: CVE-2026-66738
    cvss: 8.8
    epss: 0.00583
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66738
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0995/
  - https://sploitus.com/exploit?id=345DF3E7-56B8-5487-831A-A1CEB9B62D1E&utm_source=rss&utm_medium=rss
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
updates:
  - at: "2026-11-10T16:59:51Z"
    level: L2
    summary: poc_available; spip version < 4.4.18
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=345DF3E7-56B8-5487-831A-A1CEB9B62D1E&utm_source=rss&utm_medium=rss
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
