---
title: ReDoS Vulnerability in NLTK TokenSearcher and Text findall Methods
slug: 2026-09-nltk-redos
description: The NLTK library is vulnerable to Regular Expression Denial of Service (ReDoS) due to unvalidated user-supplied regular expressions being processed without timeouts, allowing CPU exhaustion.
date: "2026-09-08T21:54:00Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:nltk:nltk:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - redos
  - application-vulnerability
products:
  - nltk (<= 3.9.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker can cause indefinite CPU saturation with one request, denying service to all other users of the Python process.
    confidence_band: high
cves:
  - id: CVE-2026-80205
    cvss: 7.5
    epss: 0.00489
references:
  - https://github.com/advisories/GHSA-rrv8-h7p8-rx55
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80205
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade nltk library to a version greater than 3.9.4 in all production environments.
      owner: IT Operations
      due: 48h
      evidence: 'Remediation section: This vulnerability was patched in commit d8e4753.'
  mitigation_plan:
    - priority: immediate
      action: Upgrade nltk to 3.10.0 or later
      owner: IT Operations
      addresses: CVE-2026-80205
      evidence: 'Remediation section: Users should update to the patched version.'
---

NLTK (Natural Language Toolkit) versions up to 3.9.4 contain a vulnerability in the `nltk.text.Text.findall()` and `TokenSearcher.findall()` methods. These methods accept user-supplied regular expressions and pass them directly to the Python `re` engine without applying any length validation, complexity checks, or timeouts. Because the underlying logic processes these regexps against a generated internal string representation of tokens, an attacker can provide a malicious pattern designed for catastrophic backtracking. This leads to indefinite CPU saturation, effectively causing a denial of service (DoS) for any application hosting the NLTK processing service. The vulnerability, tracked as CVE-2026-80205, remains exploitable in any environment that exposes the `findall` function to untrusted external input.

## Attack Chain

1. Attacker identifies a web application or API that utilizes the `nltk.Text.findall()` method to process user-provided inputs.
2. Attacker crafts a regex payload containing nested quantifiers or overlapping groups (e.g., `<((a+)+)b>`) designed for exponential backtracking.
3. Attacker submits the payload via the input field exposed by the vulnerable application.
4. The application triggers `nltk.Text.findall(regexp)`, which calls `TokenSearcher.findall()`.
5. The library performs internal string preprocessing to wrap tokens, which does not sanitize or validate the malicious regex structure.
6. The `re.findall()` function executes the malformed regex against the tokenized data string.
7. The Python process enters a high-CPU state due to the catastrophic backtracking behavior, causing the application to hang or crash and denying service to other users.

## Impact

Successful exploitation results in a complete denial of service for the affected Python process. Given that NLTK is frequently used in NLP-heavy backend services, this vulnerability can impact high-traffic web applications, causing system instability and availability loss for all users of the affected instance.

## Recommendation

Update the `nltk` package to a version beyond 3.9.4 immediately to include the patch applied in commit `d8e4753`. Organizations cannot rely on infrastructure-level blocks for this vulnerability, as the attack is inherently application-logic based.
