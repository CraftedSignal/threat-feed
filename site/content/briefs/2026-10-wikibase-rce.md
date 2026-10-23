---
brief_id: brief-2026-10-23-wikibase-rce
event_id: brief-2026-10-23-wikibase-rce
revision: 1
activity_at: "2026-10-23T17:43:59Z"
title: 'Wikibase: Remote Code Execution via Object Injection (CVE-2026-103441)'
slug: 2026-10-wikibase-rce
description: An object injection vulnerability in the Wikibase action=parse API enables attackers with low-privilege access to achieve remote code execution via serialized PHP entities.
date: "2026-10-23T17:43:59Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:wikimedia:wikibase:*:*:*:*:*:*:*:*
vendors:
  - Wikimedia
products:
  - Wikibase Repository
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The public action=parse API accepts PHP-serialized Wikibase entities, enabling object injection and potential remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Available PHP gadget chains in affected Wikimedia deployments can extend this object-injection path to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-103441
    epss: 0.00282
    kev_status: "false"
references:
  - https://bombobombone.github.io/posts/cve-2026-103441/
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BOMBOBOMBONE-CVE-2026-103441
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BOMBOBOMBONE-CVE-2026-103441&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all public-facing Wikibase instances
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects public-facing API endpoints
  hunt_leads:
    - lead: Hunt for suspicious POST requests to api.php containing serialized PHP data structures
      technique_id: T1190
      data_needed:
        - Web server access logs (cs-method, cs-uri-stem, cs-uri-query, request_body)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation requires passing serialized PHP entities via the action=parse API parameter
  mitigation_plan:
    - priority: immediate
      action: Apply security patches from Wikibase Gerrit repository
      owner: IT Operations
      addresses: CVE-2026-103441
      evidence: Official fix documented in Gerrit repository
---

CVE-2026-103441 is an object injection vulnerability affecting the Wikibase Repository action=parse API. The flaw stems from the API accepting PHP-serialized entities without sufficient validation. This allows attackers to trigger a Smarty destructor that performs unauthorized file operations. In configurations where PHP gadget chains are present, this primitive can be leveraged to achieve remote code execution. The vulnerability requires a low-privilege account to perform the injection via the request body.

## Impact

Successful exploitation allows for remote code execution under the context of the web server user. The vulnerability has been assigned a CVSS score of 8.7 (High).

## Recommendation

* Prioritize identification of Wikibase installations within the environment.
* Audit web application logs for POST requests to api.php targeting action=parse that contain serialized PHP structures.
* Apply patches released via the official Wikibase Gerrit repository to remediate the API handling of serialized objects.
