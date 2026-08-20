---
title: NLTK TweetTokenizer Regular Expression Denial of Service
slug: 2026-08-nltk-redos
description: The NLTK library's TweetTokenizer is vulnerable to a ReDoS attack due to an unbounded regular expression, allowing unauthenticated attackers to trigger CPU exhaustion.
date: "2026-08-20T23:26:38Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - NLTK Project
products:
  - NLTK (< 3.10.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The URLS regular expression... leads to exponential backtracking... allows an unauthenticated attacker to cause significant CPU exhaustion.
    confidence_band: high
cves:
  - id: CVE-2026-72818
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72818
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Update NLTK library to 3.10.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-72818 remediation
  mitigation_plan:
    - priority: immediate
      action: Implement input length limits and execution timeouts on text processing modules
      owner: Application Security
      addresses: CVE-2026-72818
      evidence: Mitigation of ReDoS CPU exhaustion
---

The NLTK library (versions prior to 3.10.1) contains a Regular Expression Denial of Service (ReDoS) vulnerability in the 'nltk/tokenize/casual.py' module. The 'URLS' regular expression, used by 'TweetTokenizer.WORD_RE' and 'casual_tokenize', features an unbounded domain-label repetition pattern '[a-z0-9]+(?:[.\-][a-z0-9]+)*'. Because the regex engine attempts to process crafted input strings by exploring all possible partition paths before eventually failing at the missing trailing top-level domain, an attacker can consume significant CPU cycles. A few kilobytes of specially formatted input can stall a single-threaded process for minutes. Since 'TweetTokenizer' is commonly used to process untrusted social-media input, any application exposing this functionality to the internet is susceptible to unauthenticated denial-of-service attacks. The vulnerability is remediated in NLTK version 3.10.1, which introduces bounds to the label repetition.

## Impact

Successful exploitation results in significant CPU exhaustion on systems utilizing the NLTK library to parse untrusted text. This impact is primarily observed in web services that provide social-media analysis or processing features. By submitting relatively small, malicious payloads, an attacker can effectively perform a denial-of-service attack, rendering the processing service unavailable or causing cascading latency issues in the application environment.

## Recommendation

* Upgrade the NLTK library to version 3.10.1 or later immediately to patch CVE-2026-72818.
* Audit application code to identify endpoints that pass user-submitted text directly to 'nltk.tokenize.casual_tokenize' or 'TweetTokenizer.tokenize'.
* Implement input length validation and timeout mechanisms on all text-processing endpoints to mitigate the impact of potential ReDoS attacks until patching can be completed.
