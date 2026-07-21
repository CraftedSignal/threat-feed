---
title: Linkify-it Denial of Service via Mailto Validator Quadratic Complexity
slug: 2026-07-linkify-it-dos
description: The JavaScript library linkify-it is vulnerable to a quadratic-complexity Denial of Service (DoS) (CVE-2026-59887) due to an inefficient regular expression in its `mailto:` schema validator, which allows an unauthenticated attacker to block application event loops by supplying specially crafted input with repeated 'mailto:' strings.
date: "2026-07-21T19:08:30Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - nodejs
  - web-application
  - vulnerability
  - redos
vendors:
  - linkify-it
products:
  - linkify-it <= 5.0.1
  - markdown-it 14.x
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: an unauthenticated attacker can block the single-threaded event loop for many seconds with a small input.
    confidence_band: high
cves:
  - id: CVE-2026-59887
    cvss: 7.5
    epss: 0.00346
references:
  - https://github.com/advisories/GHSA-v245-v573-v5vm
---

A high-severity quadratic-complexity Denial of Service (DoS) vulnerability, tracked as CVE-2026-59887, has been identified in the `linkify-it` JavaScript library, affecting all versions up to and including 5.0.1. This flaw stems from an inefficient regular expression used within the `mailto:` schema validator and an O(n) string copy operation, leading to O(n²) processing time when handling malicious input. Attackers can exploit this by crafting input text containing a large number of repeated "mailto:" strings, causing applications that use `linkify-it` (such as `markdown-it` 14.x for rendering user content) to experience significant delays and potentially block their single-threaded event loops for several seconds to tens of seconds. This unauthenticated attack vector impacts the availability of web applications like comment systems, chat platforms, forums, wikis, and note applications that process arbitrary user-supplied markdown.

## Attack Chain

1. An unauthenticated attacker crafts a malicious string containing numerous repetitions of "mailto:", for example, "mailto:mailto:mailto:...".
2. The attacker submits this specially crafted text to an application that uses `linkify-it` (e.g., via a comment system, forum post, or chat message) to process and render user content, such as `markdown-it` with linkification enabled.
3. The `linkify-it` library begins scanning the input text through its schema-scan loop to identify potential links.
4. Upon encountering each instance of "mailto:", the library invokes its `mailto:` schema validator.
5. Inside the validator function, a substring operation `text.slice(pos)` creates an O(n) copy of the entire remaining tail of the input string for each "mailto:" occurrence.
6. Subsequently, a greedy regular expression `self.re.mailto.test(tail)` attempts to match against this copied O(n) tail.
7. Due to the regex's character class `src_email_name` broadly matching common characters (including those in "mailto:") and the lack of an `@` symbol in the crafted string, the regex engine greedily scans the entire O(n) tail before failing.
8. With N occurrences of "mailto:" in the input, the combined O(n) copy and O(n) regex scan for each occurrence results in a total processing time complexity of N × O(n) = O(n²), blocking the application's event loop and causing a denial of service.

## Impact

This vulnerability directly impacts the availability of web applications and services that rely on `linkify-it` to process and render user-supplied text, particularly markdown-based content. Affected systems include comment systems, chat applications, forums, wikis, and note-taking platforms. Successful exploitation can lead to a significant degradation of service, as processing a relatively small input (e.g., 220 KB) can block the application's single-threaded event loop for approximately 5 seconds, with larger inputs causing tens of seconds of unresponsiveness. The primary consequence is service unavailability, severely hindering user interaction and business operations for affected platforms.

## Recommendation

* Update `linkify-it` to a patched version immediately to remediate CVE-2026-59887, which addresses the quadratic complexity issue.
* Monitor Node.js application processes for unusual CPU spikes or prolonged execution times, as this could indicate an attempted or successful DoS attack, even without specific Sigma rules for this particular vulnerability.
* Implement input validation or length restrictions on user-supplied text fields that are processed by `linkify-it` to mitigate the impact of excessively long strings containing repeated `mailto:` patterns.
