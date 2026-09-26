---
title: Argument Injection in CliInvoke Extensibility Runner Factory
slug: 2026-09-cliinvoke-argument-injection
description: The CliInvoke NuGet package is vulnerable to argument injection due to improper sanitization when constructing process arguments, potentially allowing attackers to execute arbitrary commands by manipulating command-line tokens.
date: "2026-09-26T02:07:19Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:alastair_lundy:cliinvoke:*:*:*:*:*:*:*:*
vendors:
  - Alastair Lundy
products:
  - CliInvoke (>= 2.0.0, <= 2.8.4)
  - CliInvoke (>= 2.9.0, <= 2.9.3)
  - CliInvoke (>= 2.10.0, <= 2.10.4)
  - CliInvoke (>= 3.0.0-alpha.1, <= 3.0.0-beta.1)
  - AlastairLundy.CliInvoke (>= 2.0.0-alpha.1, <= 2.0.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The OS command-line parser re-tokenizes the string before the runner sees it. A double quote in the target or in any argument closes the OS-level quoted region and lets the next character enter argv as a separate element.
    confidence_band: high
cves:
  - id: CVE-2026-100369
    cvss: 8.4
references:
  - https://github.com/advisories/GHSA-j73w-8hfr-4gc9
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100369
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade vulnerable NuGet packages to the latest patched versions.
      owner: IT Operations
      due: 48h
      evidence: Source provided specific patched version numbers for 2.x and 3.x lines.
  mitigation_plan:
    - priority: immediate
      action: Sanitize all input passed to CliInvoke factories by stripping double quotes.
      owner: Application Security
      addresses: CVE-2026-100369
      evidence: Source suggests stripping quotes as a temporary partial mitigation.
---

The CliInvoke package, used for extensibility and runner management, contains an argument-injection vulnerability (CVE-2026-100369) within its process factory components, specifically the `RunnerProcessFactory` (2.x versions) and the `RunnerConfigurationFactory` (3.x versions). The vulnerability stems from the way these factories join runner arguments, targets, and caller arguments into a single string for `ProcessStartInfo.Arguments`.

When this string is passed to the operating system, the command-line parser re-tokenizes it. Because the library fails to sanitize input, an attacker can embed double quotes (`"`) into a target or argument to close the intended quoted region prematurely. This allows subsequent characters to be interpreted by the OS as separate command-line arguments, potentially resulting in arbitrary command execution. This flaw affects multiple versions of `CliInvoke` and `AlastairLundy.CliInvoke`. Defenders should prioritize upgrading to the patched versions specified in the remediation section.

## Impact

Successful exploitation allows for argument injection, which can be leveraged to execute arbitrary commands or manipulate program flow within the context of the calling application. This vulnerability impacts any application using the affected `CliInvoke` libraries to execute external processes with user-supplied input. There are currently no reports of widespread in-the-wild exploitation, but the ease of triggering this via malicious input makes it a significant risk for enterprise applications utilizing this library.

## Recommendation

- Upgrade the `CliInvoke` package to the patched versions immediately: 2.8.5, 2.9.4, 2.10.5, or 3.0.0-beta.2.
- Audit applications utilizing `CliInvoke` for user-controllable input that is passed to the `RunnerProcessFactory` or `RunnerConfigurationFactory`.
- As a temporary mitigation, implement strict input validation to strip double quotes (`"`) from all target and argument strings before they are passed to the factory.
- If using shell runners, also strip common shell meta-characters including `;`, `|`, `&`, `$`, backticks, and parentheses.
- Transition to building `ProcessConfiguration` objects directly by setting `ArgumentList` explicitly, which avoids the flawed string concatenation approach used by the factory.
