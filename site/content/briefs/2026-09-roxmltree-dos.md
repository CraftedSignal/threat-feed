---
title: Denial of Service Vulnerability in roxmltree
slug: 2026-09-roxmltree-dos
description: The roxmltree library is vulnerable to a denial of service attack due to quadratic-time attribute and namespace validation during XML parsing, allowing attackers to cause excessive CPU consumption.
date: "2026-09-17T16:02:03Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:roxmltree:roxmltree:*:*:*:*:*:*:*:*
vendors:
  - roxmltree
products:
  - roxmltree (<= 0.21.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can craft XML documents with tens of thousands of attributes on a single element to consume excessive CPU time and cause denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-92987
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92987
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Software Development
  immediate_actions:
    - action: Upgrade roxmltree to the latest patched version.
      owner: Software Development
      due: 72h
      evidence: CVE-2026-92987 remediation requires updating the affected library.
  mitigation_plan:
    - priority: immediate
      action: Implement strict validation on input XML size and attribute counts.
      owner: Software Development
      addresses: CVE-2026-92987
      evidence: Source notes lack of limits on attribute count as the primary vulnerability driver.
---

The roxmltree library (versions 0.21.1 and earlier) is susceptible to a denial of service vulnerability triggered by inefficient attribute and namespace validation during XML parsing. The implementation lacks sufficient limits on the number of attributes processed for a single XML element, resulting in quadratic-time complexity. An unauthenticated attacker can exploit this by submitting a specially crafted XML payload containing an extremely large number of attributes on a single node. When the application parses this malicious document, the CPU utilization spikes to maximum capacity, rendering the service unresponsive. This vulnerability poses a significant risk to any application that uses roxmltree to process user-supplied XML data without external validation or input size constraints.

## Impact

Successful exploitation results in service unavailability via resource exhaustion, specifically targeting the CPU. This impacts any environment utilizing affected versions of the roxmltree library for XML parsing, particularly internet-facing services that accept arbitrary XML input.

## Recommendation

- Upgrade the roxmltree library to a version containing the fix for CVE-2026-92987.
- Implement input validation on the application layer to restrict the maximum number of attributes allowed per XML element before passing the data to the parser.
- Monitor application logs and system performance metrics for sudden spikes in CPU utilization originating from service processes responsible for handling XML input.
