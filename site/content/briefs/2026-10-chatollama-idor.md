---
title: 'CVE-2026-111702: Insecure Direct Object Reference in ChatOllama'
slug: 2026-10-chatollama-idor
description: ChatOllama through commit 96c3ce5 contains an insecure direct object reference vulnerability that allows unauthenticated attackers to access private knowledge bases by enumerating sequential ID values.
date: "2026-10-16T18:50:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:chatollama:chatollama:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - idor
  - cve-2026-111702
vendors:
  - ChatOllama
products:
  - ChatOllama (<= 96c3ce5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ChatOllama through commit 96c3ce5 contains an insecure direct object reference vulnerability that allows remote attackers to access other users' private knowledge bases.
    confidence_band: high
cves:
  - id: CVE-2026-111702
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111702
rules:
  - title: Detect CVE-2026-111702 Exploitation - Sequential ID Enumeration
    description: Detects potential CVE-2026-111702 exploitation by monitoring for excessive requests to the knowledgebase API with sequential numeric identifiers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Monitor web access logs for unauthorized access to /api/knowledgebases/
      owner: SOC
      due: 24h
      evidence: Source identifies API endpoint as the source of vulnerability
  mitigation_plan:
    - priority: immediate
      action: Implement network-level access control to restrict access to ChatOllama API endpoints
      owner: IT Operations
      addresses: CVE-2026-111702
      evidence: Vulnerability allows unauthenticated access
---

ChatOllama through commit 96c3ce5 is affected by an insecure direct object reference (IDOR) vulnerability, tracked as CVE-2026-111702. This vulnerability allows remote, unauthenticated attackers to bypass authorization controls and access private knowledge bases stored within the application. By providing sequential numerical identifiers to the API, an attacker can enumerate and retrieve sensitive metadata and the content of documents associated with other users' knowledge bases. The vulnerability resides in how the application processes the {id} parameter in GET requests to the knowledgebase endpoint and the knowledgebaseId parameter in POST requests to the chat model interface. Given that these endpoints are typically exposed for API interaction, this flaw poses a significant risk to the confidentiality of organizational data processed by the ChatOllama platform.

## Impact

Successful exploitation of this vulnerability leads to unauthorized access and exfiltration of sensitive information stored within ChatOllama knowledge bases. As knowledge bases often contain internal documentation, private datasets, or proprietary information, this exposure can result in significant data breaches, potential compliance violations, and loss of intellectual property. Since the identifiers are sequential, an attacker can systematically scrape the entire knowledge base repository of an instance without requiring specific knowledge of existing IDs.

## Recommendation

Update ChatOllama installations to a version beyond commit 96c3ce5 once a security patch is provided by the vendor. In the interim, implement strict network-level access controls for the /api/knowledgebases and /api/models/chat endpoints to restrict traffic to known, trusted internal IP ranges.

## Detection

Because this vulnerability relies on sequential ID enumeration, detection teams should monitor web access logs for anomalous spikes in 200 OK responses from the /api/knowledgebases/ endpoint, specifically looking for high counts of distinct requested IDs originating from a single source IP.
