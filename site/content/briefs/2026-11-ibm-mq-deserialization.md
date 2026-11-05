---
brief_id: brief-2026-11-04-ibm-mq-deserialization
event_id: brief-2026-11-04-ibm-mq-deserialization
revision: 2
activity_at: "2026-11-05T00:08:59Z"
revision_history:
  - revision: 2
    at: "2026-11-05T00:08:59Z"
    checksum: sha256:217cb2cb7a7dbb7e590ccaa43385969d80f2211930d924ec23cfa5f3ffb7e042
    summary: added CVE-2026-13292
    changed_fields:
      - cpes
      - cves
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-13292
title: 'IBM MQ: Insecure deserialization remote code execution (CVE-2026-10859)'
slug: 2026-11-ibm-mq-deserialization
description: An authenticated attacker can execute arbitrary code on consumer applications using IBM MQ due to insecure deserialization of ObjectMessage payloads in specific LTS and CD versions.
date: "2026-11-04T22:07:08Z"
lastmod: "2026-11-05T00:06:50Z"
type: advisory
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ibm:mq:*:*:*:*:lts:*:*:*
  - cpe:2.3:a:ibm:mq:*:*:*:*:cd:*:*:*
  - cpe:2.3:a:ibm:mq:9.2.0.0:*:*:*:lts:*:*:*
  - cpe:2.3:a:ibm:mq:9.3.0.0:*:*:*:lts:*:*:*
  - cpe:2.3:a:ibm:mq:9.4.0.0:*:*:*:lts:*:*:*
  - cpe:2.3:a:ibm:mq:10.0.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:mq:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - dos
  - messaging
  - remote-code-execution
  - ibm-mq
vendors:
  - IBM
products:
  - MQ (9.2.0.0 through 9.2.0.44 LTS)
  - MQ (9.3.0.0 through 9.3.0.42 LTS)
  - MQ (9.4.0.0 through 9.4.0.26 LTS)
  - MQ (9.4.0.0 through 9.4.5.1 CD)
  - MQ (10.0.0.0 through 10.0.0.5 LTS and CD)
  - MQ (9.2.0.0-9.2.0.44 LTS)
  - MQ (9.3.0.0-9.3.0.42 LTS)
  - MQ (9.4.0.0-9.4.0.26 LTS)
  - MQ (9.4.0.0-9.4.5.1 CD)
  - MQ (10.0.0.0-10.0.0.5 LTS and CD)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated attacker can exploit this vulnerability to achieve remote code execution on consumer applications that process these malicious payloads.
    confidence_band: high
cves:
  - id: CVE-2026-10859
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-11376
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-13292
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10859
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11376
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13292
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory IBM MQ versions to identify instances matching the affected ranges for CVE-2026-10859.
      owner: IT Operations
      due: 48h
      evidence: IBM MQ 9.2, 9.3, 9.4, and 10.0 are vulnerable to insecure deserialization of ObjectMessage payloads.
    - action: Identify and inventory all IBM MQ instances across the enterprise infrastructure
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-11376 advisory affects multiple versions of IBM MQ
  hunt_leads:
    - lead: Identify authenticated users or systems pushing serialized objects to IBM MQ consumer queues.
      technique_id: T1059
      data_needed:
        - IBM MQ audit logs or application-level message processing logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An authenticated attacker can exploit this vulnerability to achieve remote code execution on consumer applications.
    - lead: Monitor IBM MQ error logs for unexpected crashes or errors occurring specifically during subscription request processing
      technique_id: T1190
      data_needed:
        - IBM MQ diagnostic and error logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability occurs when processing subscription requests with crafted buffer size values
  mitigation_plan:
    - priority: immediate
      action: Apply security patches provided by IBM for affected MQ versions as they become available.
      owner: IT Operations
      addresses: CVE-2026-10859
      evidence: IBM MQ 9.2.0.0 through 9.2.0.44 LTS, 9.3.0.0 through 9.3.0.42 LTS, 9.4.0.0 through 9.4.0.26 LTS, 9.4.0.0 through 9.4.5.1 CD, and 10.0.0.0 through 10.0.0.5 LTS and CD.
    - priority: immediate
      action: Apply patches provided by IBM as soon as they become available for the affected versions
      owner: IT Operations
      addresses: CVE-2026-11376
      evidence: NVD advisory for CVE-2026-11376
updates:
  - at: "2026-11-04T22:07:17Z"
    level: L2
    summary: added coverage for MQ (9.2.0.0-9.2.0.44 LTS) +4 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-11376
  - at: "2026-11-05T00:06:50Z"
    level: L2
    summary: added CVE-2026-13292
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-13292
---

IBM MQ versions 9.2.0.0 through 9.2.0.44 LTS, 9.3.0.0 through 9.3.0.42 LTS, 9.4.0.0 through 9.4.0.26 LTS, 9.4.0.0 through 9.4.5.1 CD, and 10.0.0.0 through 10.0.0.5 LTS and CD are vulnerable to an insecure deserialization flaw. An authenticated attacker can exploit this vulnerability by sending malicious ObjectMessage payloads that, when processed by consumer applications, result in remote code execution. No exploit code or specific mitigation patches were detailed in the initial disclosure.

## Impact

Authenticated attackers can achieve remote code execution on consumer applications processing maliciously crafted ObjectMessage payloads.

## Recommendation

- Inventory all IBM MQ instances within the environment to identify versions within the affected ranges.
- Monitor for administrative authentication and message processing activity originating from untrusted or unexpected sources.
- Coordinate with IT Operations to apply forthcoming vendor patches provided by IBM for the affected LTS and CD branches.
