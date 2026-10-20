---
brief_id: brief-2026-10-20-pillow-pdf-recursion
event_id: brief-2026-10-20-pillow-pdf-recursion
revision: 1
activity_at: "2026-10-20T23:53:38Z"
title: 'Pillow: PDF unbounded recursion in page tree and trailer parsing (CVE-2026-112895)'
slug: 2026-10-pillow-pdf-recursion
description: Pillow is vulnerable to denial of service through unbounded recursion when parsing malformed PDF files using Image.save with append=True due to insufficient depth checks in page tree and trailer chain traversals.
date: "2026-10-20T23:53:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: source material provides clear vulnerability scope and technical cause
cpes:
  - cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - python
  - library-vulnerability
products:
  - Pillow (>= 5.1.0, < 13.0.0)
cves:
  - id: CVE-2026-112895
    epss: 0.00291
    kev_status: "false"
  - id: CVE-2026-42310
    cvss: 5.5
    epss: 0.00177
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-p4wg-p73j-c528
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Pillow to 13.0.0 or later
      owner: IT Operations
      due: 48h
      evidence: Pillow version >= 5.1.0, < 13.0.0 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Apply resource constraints (CPU/Memory timeouts) to PDF processing services
      owner: Application Security
      addresses: CVE-2026-112895
      evidence: Unbounded recursion causes resource exhaustion
---

Pillow, a popular Python imaging library, contains vulnerabilities that allow an attacker to trigger unbounded recursion during the parsing of malformed PDF files. When an application utilizes `Image.save` with `append=True`, the library invokes `PdfParser` to process the existing PDF structure. Two specific areas of the parser lack necessary bounds: `linearize_page_tree` follows `/Kids` entries without tracking visited nodes or enforcing a depth limit, and `read_prev_trailer` permits long chains of unique `/Prev` offsets.

These vulnerabilities serve as an incomplete fix for CVE-2026-42310. An attacker can craft malicious PDF files containing cyclic page trees or extensively deep `/Prev` chains to drive the parsing process into high CPU and memory utilization, leading to application crashes or denial of service. The vulnerability affects all Pillow versions from 5.1.0 up to, but not including, 13.0.0. Defenders should note this impacts any service that processes user-supplied PDFs for operations such as stamping, watermarking, or merging.

## Impact

A successful exploit causes denial of service by exhausting stack space, CPU, and memory resources. Any service performing automated processing of user-provided PDFs - common in document management, e-signature, or image processing pipelines - is susceptible. The impact is significant for services where availability is critical and where the processing component shares memory or CPU resources with other application functions.

## Recommendation

* Upgrade the Pillow library to version 13.0.0 or later immediately to address CVE-2026-112895.
* Audit application code to identify endpoints that invoke `Image.save(..., format="PDF", append=True)` on untrusted user input.
* Implement input validation or limit file sizes and complexity for incoming PDF documents before passing them to the Pillow library.
* If upgrading is not immediately possible, implement a file-parsing timeout for any process handling PDF manipulation to mitigate the impact of CPU and memory exhaustion.
