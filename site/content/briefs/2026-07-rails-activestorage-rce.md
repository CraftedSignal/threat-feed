---
title: Remote Code Execution and Arbitrary File Read in Ruby on Rails Active Storage
slug: 2026-07-rails-activestorage-rce
description: A vulnerability (CVE-2026-66066) in Ruby on Rails Active Storage allows unauthenticated attackers to achieve arbitrary file read and remote code execution during the variant processing phase.
date: "2026-07-30T15:25:56Z"
lastmod: "2026-09-01T08:03:46Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=04CDB004-ADE7-5A64-924D-DAFA4290F817&utm_source=rss&utm_medium=rss
vendors:
  - Ruby on Rails
  - libvips
products:
  - Active Storage (8.0.x)
  - Active Storage (8.1.x)
  - Active Storage (7.2.x)
  - Ruby on Rails Active Storage (7.0.0 <= 7.2.3.1)
  - Ruby on Rails Active Storage (8.0.0 <= 8.0.5)
  - Ruby on Rails Active Storage (8.1.0 <= 8.1.3)
  - Ruby on Rails Active Storage (6.0.0 <= 6.1.7.10)
  - libvips (< 8.13)
  - ruby-vips (< 2.2.1)
  - Active Storage (7.2.3.2, 8.0.5.1, 8.1.3.1)
  - Rails Active Storage (< 7.2.3.2)
cves:
  - id: CVE-2026-66066
    epss: 0.27861
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0948/
  - https://discuss.rubyonrails.org/t/cve-2026-66066-possible-arbitrary-file-read-and-remote-code-execution-in-active-storage-variant-processing/91432
  - https://www.cve.org/CVERecord?id=CVE-2026-66066
  - https://www.rapid7.com/blog/post/etr-kindarails2shell-cve-2026-66066-critical-arbitrary-file-read-and-possible-remote-code-execution-in-ruby-on-rails
  - https://www.securityweek.com/ruby-on-rails-patches-critical-vulnerability/
  - https://sploitus.com/exploit?id=04CDB004-ADE7-5A64-924D-DAFA4290F817&utm_source=rss&utm_medium=rss
  - https://thehackernews.com/2026/09/attackers-exploit-critical-langflow-and.html
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=04CDB004-ADE7-5A64-924D-DAFA4290F817
ioc_counts:
  url: 1
updates:
  - at: "2026-07-30T21:28:59Z"
    level: L2
    summary: poc_available; added CVE-2026-66066
    sources:
      - rapid7
    source_urls:
      - https://www.rapid7.com/blog/post/etr-kindarails2shell-cve-2026-66066-critical-arbitrary-file-read-and-possible-remote-code-execution-in-ruby-on-rails
  - at: "2026-08-01T11:53:14Z"
    level: L1
    summary: new product
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/ruby-on-rails-patches-critical-vulnerability/
  - at: "2026-08-03T14:08:38Z"
    level: L1
    summary: new IOCs
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=04CDB004-ADE7-5A64-924D-DAFA4290F817&utm_source=rss&utm_medium=rss
  - at: "2026-09-01T08:03:46Z"
    level: L2
    summary: rails active storage version < 7.2.3.2
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/09/attackers-exploit-critical-langflow-and.html
---

A critical vulnerability, tracked as CVE-2026-66066, has been identified in the Ruby on Rails Active Storage component. The flaw arises from improper handling of image variants during the processing phase. An attacker can exploit this weakness to perform arbitrary file reads or achieve remote code execution (RCE) on the underlying server hosting the application. This vulnerability is particularly dangerous as it targets the file processing pipeline, which is a common feature in web applications handling user-uploaded content. Impacted versions include Active Storage 8.0.x versions prior to 8.0.5.1, 8.1.x versions prior to 8.1.3.1, and versions prior to 7.2.3.2. Organizations utilizing these affected versions of Rails are encouraged to update immediately to the patched releases provided by the Ruby on Rails security team to prevent potential exploitation.

## Impact

The vulnerability poses a severe risk to web applications, potentially leading to total system compromise via RCE and unauthorized access to sensitive application data through arbitrary file read. Successful exploitation allows an attacker to bypass standard application security controls to access internal configuration files, environment variables, or credentials.

## Recommendation

* Update Ruby on Rails Active Storage to the latest non-vulnerable versions: 8.0.5.1, 8.1.3.1, or 7.2.3.2 as specified in the vendor security bulletin.
* Audit application logs for unusual request patterns directed at image processing or variant endpoints, particularly those containing unexpected file path references or system-level commands.
* Restrict outbound network traffic from web servers to prevent post-exploitation activities such as reverse shells or data exfiltration.
* Apply principle of least privilege to the application process to limit the impact of potential code execution.
