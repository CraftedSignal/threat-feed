---
title: Remote Out-of-Bounds Write Vulnerability in OpenDKIM
slug: 2026-09-opendkim-oob-write
description: A memory corruption vulnerability in the OpenDKIM dkim_canon_selecthdrs function allows remote attackers to trigger an out-of-bounds write via crafted DKIM signature headers.
date: "2026-09-28T01:11:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:trusted_domain_project:opendkim:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - mail-infrastructure
vendors:
  - Trusted Domain Project
products:
  - OpenDKIM (<= 2.11.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-100888
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100888
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review mail server software configurations to identify usage of libopendkim.
      owner: SOC
      due: 48h
      evidence: Vulnerability affects OpenDKIM 2.11.0 and earlier.
  mitigation_plan:
    - priority: immediate
      action: Monitor for crashes or abnormal behavior in mail servers.
      owner: IT Operations
      addresses: CVE-2026-100888
      evidence: Public exploit code is available.
---

A security vulnerability (CVE-2026-100888) has been identified in the Trusted Domain Project OpenDKIM library up to version 2.11.0. The flaw resides within the dkim_canon_selecthdrs function located in libopendkim/dkim-canon.c, specifically within the DKIM Signature Header Selection component. By manipulating the 'h' argument in a malicious DKIM signature, a remote attacker can trigger an out-of-bounds write. This vulnerability is particularly concerning as public exploit code is already available, potentially enabling remote code execution in applications utilizing the affected library. The vendor was notified of the issue but has not provided a response or a patch as of the reporting date. Defenders should prioritize auditing mail infrastructure utilizing OpenDKIM for potential exploitation attempts or crashes indicating memory corruption.

## Impact

Successful exploitation of this vulnerability could lead to arbitrary code execution or service disruption of mail servers processing DKIM signatures. As OpenDKIM is a widely used library for DKIM verification, the impact is high for any organization relying on it for email authentication.

## Recommendation

Detection engineering teams should monitor for anomalous crashes or unexpected behavior in processes utilizing libopendkim. Given the lack of a vendor patch, consider isolating mail processing components or implementing strict input validation at the edge if possible.

- Monitor application logs and system crash reports for memory-related errors originating from mail-handling processes linked against libopendkim.
- Evaluate the necessity of OpenDKIM 2.11.0 or earlier in high-exposure segments and consider alternative configurations or temporary hardening measures if upgrading is not an option.
