---
title: Multiple Vulnerabilities in Cpanel::JSON::XS Perl Module
slug: 2026-10-cpanel-json-xs-vulnerabilities
description: The Perl module Cpanel::JSON::XS contains multiple security vulnerabilities in versions prior to 4.80, including information disclosure, denial-of-service, and type confusion.
date: "2026-10-19T20:10:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:cpanel:cpanel_json_xs:*:*:*:*:*:*:*:*
tags:
  - library-vulnerability
  - perl
  - cpan
  - json-parsing
vendors:
  - cPanel
products:
  - Cpanel::JSON::XS (< 4.80)
cves:
  - id: CVE-2026-110672
  - id: CVE-2026-110673
  - id: CVE-2026-110674
references:
  - https://seclists.org/oss-sec/2026/q4/230
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Upgrade Cpanel::JSON::XS to 4.80 or later
      owner: IT Operations
      due: 72h
      evidence: Source notes version 4.80 addresses the listed CVEs.
  mitigation_plan:
    - priority: immediate
      action: Update Cpanel::JSON::XS to 4.80 or later
      owner: IT Operations
      addresses: CVE-2026-110672, CVE-2026-110673, CVE-2026-110674
      evidence: Upstream vendor security release
---

The Perl module Cpanel::JSON::XS has been identified as vulnerable to a series of security defects in all versions prior to 4.80. The disclosed vulnerabilities include CVE-2026-110672, which allows for the leakage of decoded keys when an object is rejected due to duplicate keys or missing colons during the parsing process. CVE-2026-110673 introduces a potential denial-of-service condition through stack exhaustion when processing deeply nested tagged values with the allow_tags feature enabled. Additionally, CVE-2026-110674 affects versions from 4.33 through 4.79, where a failure to properly handle duplicate non-ASCII bare keys can lead to type confusion vulnerabilities. These flaws reside within the JSON decoding logic, potentially impacting any application that utilizes this library to parse untrusted JSON input. Organizations using applications or scripts that rely on Cpanel::JSON::XS are advised to update the module to version 4.80 or later to mitigate these risks.

## Impact

Successful exploitation of these vulnerabilities can lead to sensitive information disclosure, application crashes due to stack exhaustion, or unpredictable program behavior via type confusion. These risks are inherent to any service processing JSON data using the affected library, potentially affecting a broad range of Perl-based web applications, backend automation tools, and system management scripts.

## Recommendation

- Audit application dependencies to identify the use of Cpanel::JSON::XS versions earlier than 4.80.
- Update Cpanel::JSON::XS to version 4.80 or later across all environments.
- Patch CVE-2026-110672, CVE-2026-110673, and CVE-2026-110674 by applying the upstream library update.
