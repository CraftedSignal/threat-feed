---
title: Oj Gem Use-After-Free Vulnerability (CVE-2026-54898)
slug: 2026-06-oj-use-after-free
description: A heap use-after-free vulnerability (CVE-2026-54898) in the Oj gem's Oj::Parser#parse method allows an attacker to trigger memory corruption and potential arbitrary code execution or denial of service when a SAJ/SAJ2 callback mutates the input JSON string during parsing, causing a dangling pointer and subsequent read of freed memory.
date: "2026-06-19T19:54:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - use-after-free
  - ruby
  - gem
  - memory-corruption
vendors:
  - Oj
products:
  - oj gem (< 3.17.2)
references:
  - https://github.com/advisories/GHSA-q2gm-54r6-8fwm
rules:
  - title: Detects CVE-2026-54898 Exploitation — Oj Gem Application Crash (Windows)
    description: Detects the creation of crash dump files (*.dmp) by a Ruby process, which could indicate a denial-of-service or memory corruption exploit related to CVE-2026-54898 in the Oj gem.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
      - T1499.001
    data_sources:
      - file_event
      - windows
  - title: Detects CVE-2026-54898 Exploitation — Suspicious Child Process from Ruby Interpreter
    description: Detects the execution of known suspicious processes (e.g., command shells, scripting interpreters) as direct child processes of the Ruby interpreter. This could indicate successful arbitrary code execution via CVE-2026-54898.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1204
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `Oj` gem, a fast JSON parser and serializer for Ruby, is affected by a heap use-after-free vulnerability, identified as CVE-2026-54898. This flaw resides within the `Oj::Parser#parse` method, specifically when processing JSON via SAJ/SAJ2 callbacks. An attacker can trigger this vulnerability by providing a crafted JSON input where a callback, such as `hash_start`, intentionally mutates the input JSON string (e.g., by using `String#replace` with a larger value). This mutation causes Ruby to reallocate the string's internal buffer and free the old one. However, the C engine within `Oj` retains a raw `const byte *` pointer to the now-freed memory, leading to a use-after-free condition when the parser attempts to read the next character. This vulnerability affects all versions of the `oj` gem that include `ext/oj/parser.c` (confirmed in 3.17.1 and earlier versions < 3.17.2). Successful exploitation can lead to application crashes (denial of service) or potentially arbitrary code execution.

## Attack Chain

1.  An attacker delivers a crafted JSON input to a Ruby application utilizing the `Oj` gem for parsing.
2.  The `Oj::Parser#parse` method begins processing the JSON string, and its internal C engine obtains a direct `const byte *` pointer to the Ruby string's backing buffer.
3.  During parsing, a malicious JSON structure triggers a SAJ/SAJ2 callback (e.g., `hash_start`) with a key controlled by the attacker.
4.  The invoked callback function, manipulated by the attacker, executes `String#replace` or a similar method on the *original input JSON string*, replacing its content with a larger string.
5.  This action causes the Ruby runtime to reallocate the input string's internal buffer and subsequently free the original buffer, to which the `Oj` C parser still holds a dangling pointer.
6.  As the `Oj` parser continues its execution loop (`parser.c:607`), it attempts to read the next character from the dangling pointer, resulting in a heap use-after-free error.
7.  This memory corruption can lead to application crashes (denial of service) or, in advanced scenarios, potentially arbitrary code execution within the context of the vulnerable application.

## Impact

The successful exploitation of CVE-2026-54898 can result in a denial of service (DoS) for applications relying on the `Oj` gem for JSON parsing. An attacker can reliably trigger application crashes, making the service unavailable to legitimate users. In more sophisticated exploitation scenarios, a use-after-free vulnerability can be leveraged to achieve arbitrary code execution, granting attackers control over the compromised system. This could lead to data exfiltration, further lateral movement within the network, or the deployment of additional malicious payloads. While specific victim counts or targeted sectors are not yet available, any Ruby application using vulnerable versions of the `Oj` gem to parse untrusted JSON input is at risk.

## Recommendation

1.  Immediately update the `oj` gem to version 3.17.2 or later to patch CVE-2026-54898.
2.  Deploy the Sigma rules in this brief to your SIEM to detect potential exploitation attempts or indicators of compromise.
3.  Enable crash dump generation for Ruby applications or web servers (e.g., Passenger, Unicorn) and monitor for `*.dmp` or `core` files with the `Detects CVE-2026-54898 Exploitation — Oj Gem Application Crash (Windows)` Sigma rule.
4.  Monitor for suspicious child processes spawned by Ruby interpreter executables using the `Detects CVE-2026-54898 Exploitation — Suspicious Child Process from Ruby Interpreter` Sigma rule.
