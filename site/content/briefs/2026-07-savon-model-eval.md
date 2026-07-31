---
title: Remote Code Execution in Savon::Model via WSDL Injection
slug: 2026-07-savon-model-eval
description: The Savon Ruby library is vulnerable to remote code execution (CVE-2026-53510) due to insecure use of module_eval when processing untrusted WSDL operation names.
date: "2026-07-31T19:45:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ruby
  - remote-code-execution
  - vulnerability
  - cve-2026-53510
products:
  - Savon (< 2.17.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Savon::Model generated SOAP operation methods by interpolating operation names into Ruby source passed to module_eval.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mx5j-mp4f-g8jg
---

Savon, a popular Ruby client for SOAP web services, contains a critical vulnerability (CVE-2026-53510) in its `Savon::Model` component. The flaw exists in the `.all_operations` class method, which is designed to automatically register SOAP operations by parsing a WSDL document. During this process, the library interpolates operation names directly into a string that is passed to Ruby's `module_eval` function. An attacker capable of influencing the WSDL source (e.g., providing a URL to a malicious WSDL file or intercepting a legitimate service response) can inject arbitrary Ruby code. This code executes with the privileges of the application process. The vulnerability affects all versions of the `savon` gem from 0.9.8 up to 2.17.2. Applications that manually define operations via the `.operations` method are not affected, as this approach avoids the insecure string evaluation of untrusted metadata.

## Impact

Successful exploitation allows for full remote code execution within the context of the Ruby application process. Depending on the environment, this could lead to sensitive data exfiltration, unauthorized modification of application logic, or complete system compromise. Organizations relying on automated service discovery via `Savon::Model` using user-supplied or network-reachable WSDL files are at high risk.

## Recommendation

* Upgrade the `savon` gem to version 2.17.2 or later immediately to patch CVE-2026-53510.
* For applications that cannot immediately upgrade, transition away from the `all_operations` method in `Savon::Model` and explicitly define service operations using the `.operations` method with trusted input.
* Audit applications utilizing `Savon::Model` to identify instances where the WSDL source is fetched from external or untrusted origins.
