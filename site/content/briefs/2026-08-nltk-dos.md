---
title: Denial of Service Vulnerability in nltk PorterStemmer
slug: 2026-08-nltk-dos
description: An algorithmic complexity vulnerability in the nltk PorterStemmer module allows unauthenticated attackers to cause high CPU usage via specially crafted inputs.
date: "2026-08-27T19:13:59Z"
type: advisory
types:
  - advisory
severities:
  - low
products:
  - nltk (<= 3.10.2)
cves:
  - id: CVE-2026-81722
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81722
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade nltk library to version 3.10.3
      owner: Engineering
      addresses: CVE-2026-81722
      evidence: NVD advisory recommends update to 3.10.3.
---

The Natural Language Toolkit (nltk) library, specifically in versions 3.10.2 and earlier, is susceptible to an algorithmic complexity denial of service vulnerability (CVE-2026-81722). The vulnerability resides within the PorterStemmer.stem() method, where the _is_consonant() helper function exhibits O(n^2) performance degradation when processing tokens containing long sequences of the character 'y'. By providing a relatively small untrusted input (20-50 KB) consisting of a repeated 'y' string followed by a suffix such as 'ness', an attacker can force the application to consume significant CPU resources. This can pin a CPU core for extended periods, potentially leading to a denial of service if the application processes these inputs synchronously or within limited worker threads. Developers using nltk for text processing are advised to upgrade to version 3.10.3 to mitigate this performance-based attack vector.

## Impact

The vulnerability allows for resource exhaustion on systems utilizing the nltk library to process untrusted natural language input. This impacts applications that perform automated text analysis, sentiment analysis, or search indexing. Successful exploitation can lead to prolonged CPU spikes, reducing the availability of the target application for legitimate users. Given the nature of the exploit, it is particularly dangerous for multi-tenant web applications or services that accept user-provided text for automated processing.

## Recommendation

* Update the nltk library to version 3.10.3 or higher in all production environments.
* Implement input validation or length constraints for tokens processed by the PorterStemmer to prevent excessively long input strings.
* Monitor application servers for unexpected sustained high CPU usage originating from text-processing workers.
