---
title: Denial of Service Vulnerability in eml_parser
slug: 2026-08-eml-parser-dos
description: The eml_parser library is vulnerable to a CPU exhaustion denial-of-service attack due to a regex-based algorithm in 'Received' header parsing that triggers quadratic complexity when processing deeply nested parentheses.
date: "2026-08-25T18:49:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
products:
  - eml_parser
references:
  - https://github.com/advisories/GHSA-g7gc-gmgp-wgqg
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55620
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade eml_parser to version 3.0.2 or later across all production pipelines
      owner: IT Operations
      due: 48h
      evidence: Patches for CVE-2026-55620 are included in version 3.0.2
  mitigation_plan:
    - priority: immediate
      action: Implement CPU utilization monitoring for mail parsing worker processes
      owner: SOC
      addresses: CVE-2026-55620
      evidence: Vulnerability allows CPU saturation via crafted EML files
---

The Python library `eml_parser` contains a vulnerability (CVE-2026-55620) where the logic used to strip parenthesized comments from `Received:` headers employs a fix-point loop with quadratic time complexity. When the parser encounters an EML file containing a `Received:` header with deeply nested parentheses, the processing time scales exponentially with the nesting depth. A header with 5,000 levels of nesting requires approximately 1.3 seconds of CPU time to parse. Because this library is frequently used in email gateways, security sandboxes, and automated triage pipelines, an attacker can intentionally craft malicious emails to induce significant latency. In synchronous processing architectures, this exhaustion of CPU resources leads to queue backpressure, worker starvation, and potential service-level denial of service.

## Impact

Successful exploitation results in a denial of service for email processing pipelines. Because the complexity is triggered per-message, an attacker sending a high volume of crafted EML files can permanently saturate available worker threads, preventing the delivery or analysis of legitimate communications. This affects any system relying on `eml_parser` versions prior to 3.0.2 to ingest or inspect inbound mail.

## Recommendation

Prioritize the immediate upgrade of the `eml_parser` library to version 3.0.2 or higher to implement the linear-time parsing algorithm. For environments unable to patch immediately, implement strict validation of incoming EML header length and nesting depth at the edge, or place email ingestion services behind a rate-limiting reverse proxy to mitigate the impact of CPU-heavy requests. Monitor for anomalous CPU spikes in mail processing worker nodes associated with the `eml_parser` library.
