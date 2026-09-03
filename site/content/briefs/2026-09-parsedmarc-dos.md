---
title: Denial of Service in parsedmarc via Unbounded Attachment Decompression
slug: 2026-09-parsedmarc-dos
description: The parsedmarc library before version 11.0.1 is vulnerable to remote denial-of-service exploitation via crafted email attachments that trigger memory exhaustion through unbounded decompression.
date: "2026-09-03T21:23:03Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:parsedmarc:parsedmarc:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - email-security
vendors:
  - parsedmarc
products:
  - parsedmarc (< 11.0.1)
cves:
  - id: CVE-2026-82520
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82520
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade parsedmarc to 11.0.1 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-82520 advisory remediation
  mitigation_plan:
    - priority: immediate
      action: Configure MTA-level attachment size limits for monitored mailboxes
      owner: IT Operations
      addresses: CVE-2026-82520
      evidence: Source describes unbounded read during decompression
---

The parsedmarc library, a utility used for parsing DMARC reports, contains a critical vulnerability (CVE-2026-82520) in versions prior to 11.0.1. The vulnerability stems from the library performing a single, unbounded read when decompressing gzip and ZIP email attachments. Because parsedmarc is designed to automatically ingest and process emails from monitored mailboxes without user interaction, an unauthenticated remote attacker can exploit this behavior by sending a specially crafted, highly compressed attachment.

When parsedmarc attempts to decompress the malicious payload, it allocates memory proportional to the potential uncompressed size of the data. By providing a 'zip bomb' or similar high-compression ratio file, an attacker forces the application to consume excessive system memory, resulting in process crashes or total exhaustion of host RAM. This vulnerability is particularly dangerous due to the automated nature of the software, which facilitates unauthenticated remote exploitation without requiring any victim action beyond the delivery of the email to the monitored inbox.

## Impact

Successful exploitation results in an immediate denial-of-service condition for the affected parsedmarc instance. Organizations relying on this tool for DMARC report processing will experience a loss of visibility into email authentication compliance and potential system instability for the host running the software. If the process is running on shared infrastructure, the memory exhaustion could impact other services co-located on the same host.

## Recommendation

1. Upgrade all instances of parsedmarc to version 11.0.1 or later to implement size limits on decompression.
2. Implement strict incoming email attachment size and content filtering at the Mail Transfer Agent (MTA) level to prevent highly compressed files from reaching the parsedmarc ingest mailbox.
3. Monitor system memory usage for the process handling parsedmarc execution to identify potential crash loops or anomalous spikes.
