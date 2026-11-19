---
brief_id: brief-2026-09-15-ibm-mq-vulnerabilities
event_id: brief-2026-09-15-ibm-mq-vulnerabilities
revision: 2
activity_at: "2026-11-19T18:13:06Z"
revision_history:
  - revision: 2
    at: "2026-11-19T18:13:06Z"
    checksum: sha256:4e825e4eb25c57aea5052de9d9d64ad04a8ed3e86f6150fb276e06e9c79a4c86
    summary: exploited:true; KEV CVE-2024-49035
    changed_fields:
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Multiple Vulnerabilities in IBM MQ
slug: 2026-09-ibm-mq-vulnerabilities
description: IBM MQ is affected by multiple vulnerabilities, including CVE-2024-49033, CVE-2024-49034, and CVE-2024-49035, which could allow a remote attacker to execute arbitrary code, cause a denial of service, disclose sensitive information, or manipulate data.
date: "2026-09-15T13:04:36Z"
lastmod: "2026-11-19T18:12:21Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2025-02-25T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source confirmed vulnerabilities but lacks specific exploit payloads for rules
cpes:
  - cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2021:*:*:*:*:-:*:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2021:*:*:*:*:macos:*:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2024:*:*:*:*:-:*:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2024:*:*:*:*:macos:*:*
  - cpe:2.3:a:microsoft:partner_center:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:word:2016:*:*:*:*:*:*:*
tags:
  - vulnerability
  - messaging-middleware
  - remote-code-execution
vendors:
  - IBM
products:
  - MQ
cves:
  - id: CVE-2024-49033
    cvss: 7.5
    epss: 0.02101
    kev_status: unknown
  - id: CVE-2024-49035
    cvss: 8.7
    epss: 0.013
    kev: true
    kev_status: "true"
  - id: CVE-2024-49034
    kev_status: unknown
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3365
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch IBM MQ instances to the versions identified in the IBM security bulletin
      owner: IT Operations
      due: 72h
      evidence: Source reports multiple vulnerabilities in IBM MQ
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to IBM MQ listeners
      owner: IT Operations
      addresses: CVE-2024-49033, CVE-2024-49034, CVE-2024-49035
      evidence: Source identifies multiple vulnerabilities that can be exploited by remote attackers
updates:
  - at: "2026-11-19T18:12:21Z"
    level: L3
    summary: exploited:true; KEV CVE-2024-49035
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

IBM has disclosed multiple security vulnerabilities affecting the IBM MQ messaging software. These flaws, tracked as CVE-2024-49033, CVE-2024-49034, and CVE-2024-49035, present significant risks to systems running the software. Successful exploitation of these vulnerabilities may allow an unauthenticated or authenticated attacker to achieve arbitrary remote code execution (RCE) on the underlying host, trigger a Denial of Service (DoS) condition, gain access to sensitive information, or perform unauthorized data manipulation. Defenders should prioritize patching and configuration reviews for all instances of IBM MQ, as these vulnerabilities impact the integrity and availability of messaging infrastructure, which often serves as a critical backbone for enterprise applications.

## Impact

Successful exploitation could result in the total compromise of the host system, loss of message confidentiality, and disruption of critical business services that rely on IBM MQ for communication. These vulnerabilities affect all deployments of the software, and organizations should apply vendor-provided security updates to mitigate these risks.

## Recommendation

- Identify all IBM MQ deployments across the environment using asset inventory systems.
- Review the IBM security advisory for the specific fixed versions associated with CVE-2024-49033, CVE-2024-49034, and CVE-2024-49035.
- Apply the latest security patches provided by IBM to all MQ instances.
- Implement network segmentation to limit access to MQ listener ports (typically 1414) to authorized clients only to reduce the attack surface.
