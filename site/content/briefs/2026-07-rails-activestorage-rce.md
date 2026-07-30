---
title: Remote Code Execution and Arbitrary File Read in Ruby on Rails Active Storage
slug: 2026-07-rails-activestorage-rce
description: A vulnerability (CVE-2026-66066) in Ruby on Rails Active Storage allows unauthenticated attackers to achieve arbitrary file read and remote code execution during the variant processing phase.
date: "2026-07-30T15:25:56Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Ruby on Rails
products:
  - Active Storage (8.0.x)
  - Active Storage (8.1.x)
  - Active Storage (7.2.x)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0948/
  - https://discuss.rubyonrails.org/t/cve-2026-66066-possible-arbitrary-file-read-and-remote-code-execution-in-active-storage-variant-processing/91432
  - https://www.cve.org/CVERecord?id=CVE-2026-66066
---

A critical vulnerability, tracked as CVE-2026-66066, has been identified in the Ruby on Rails Active Storage component. The flaw arises from improper handling of image variants during the processing phase. An attacker can exploit this weakness to perform arbitrary file reads or achieve remote code execution (RCE) on the underlying server hosting the application. This vulnerability is particularly dangerous as it targets the file processing pipeline, which is a common feature in web applications handling user-uploaded content. Impacted versions include Active Storage 8.0.x versions prior to 8.0.5.1, 8.1.x versions prior to 8.1.3.1, and versions prior to 7.2.3.2. Organizations utilizing these affected versions of Rails are encouraged to update immediately to the patched releases provided by the Ruby on Rails security team to prevent potential exploitation.

## Impact

The vulnerability poses a severe risk to web applications, potentially leading to total system compromise via RCE and unauthorized access to sensitive application data through arbitrary file read. Successful exploitation allows an attacker to bypass standard application security controls to access internal configuration files, environment variables, or credentials.

## Recommendation

* Update Ruby on Rails Active Storage to the latest non-vulnerable versions: 8.0.5.1, 8.1.3.1, or 7.2.3.2 as specified in the vendor security bulletin.
* Audit application logs for unusual request patterns directed at image processing or variant endpoints, particularly those containing unexpected file path references or system-level commands.
* Restrict outbound network traffic from web servers to prevent post-exploitation activities such as reverse shells or data exfiltration.
* Apply principle of least privilege to the application process to limit the impact of potential code execution.
