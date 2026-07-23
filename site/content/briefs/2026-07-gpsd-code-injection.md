---
title: GPSD Code Injection Vulnerability in gpsprof (CVE-2026-60122)
slug: 2026-07-gpsd-code-injection
description: A high-severity code injection vulnerability, CVE-2026-60122, exists in the gpsprof utility of gpsd through version 3.27.5, allowing an attacker to achieve arbitrary OS command execution by injecting malicious content into GPS input data processed by gnuplot.
date: "2026-07-23T20:19:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - command-injection
  - gpsd
  - gnuplot
  - linux
  - macos
  - privilege-escalation
vendors:
  - gpsd project
products:
  - gpsd (<= 3.27.5)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker who controls GPS input data to execute arbitrary OS commands by injecting malicious content into the SKY.satellites[].used field, which is inserted unsanitized into a gnuplot heredoc data block. Attackers can supply a used value containing the string EOD to terminate the heredoc early and append gnuplot system() calls, achieving OS command execution as the user running gpsprof when the generated plot script is processed by gnuplot in polar mode.
    confidence_band: high
cves:
  - id: CVE-2026-60122
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60122
rules:
  - title: Detect Gnuplot Spawning Suspicious Child Processes
    description: Detects CVE-2026-60122 exploitation - Identifies gnuplot executing shell processes, which indicates arbitrary OS command execution via injected malicious GPS data.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A significant code injection vulnerability, identified as CVE-2026-60122, has been discovered in the `gpsprof` utility within the `gpsd` project, affecting versions up to 3.27.5. This flaw enables a malicious actor, capable of controlling the input GPS data, to execute arbitrary operating system commands. The vulnerability stems from `gpsprof` unsafely incorporating attacker-controlled content into a `gnuplot` heredoc data block. Specifically, by injecting the string "EOD" into the `SKY.satellites[].used` field, attackers can prematurely terminate the heredoc and append `gnuplot system()` calls. These injected commands are then executed by `gnuplot` when it processes the generated plot script in polar mode, running with the privileges of the user who initiated `gpsprof`. This could lead to full system compromise or data exfiltration on affected Linux and macOS systems.

## Attack Chain

1. An attacker prepares malicious GPS input data.
2. The attacker injects specific malicious content into the `SKY.satellites[].used` field of the GPS input data.
3. The injected content includes the string "EOD" to prematurely terminate a `gnuplot` heredoc block.
4. The attacker appends `gnuplot system()` calls containing desired OS commands immediately after the "EOD" string.
5. A legitimate user executes the `gpsprof` utility to process the attacker-controlled GPS input data.
6. `gpsprof` generates a `gnuplot` script, incorporating the unsanitized malicious content and `system()` calls into it.
7. `gpsprof` invokes `gnuplot` to execute the generated script in polar mode.
8. `gnuplot` processes the script, encounters the `system()` calls, and executes the arbitrary OS commands with the privileges of the user running `gpsprof`.

## Impact

Successful exploitation of CVE-2026-60122 allows for arbitrary OS command execution on the system where `gpsprof` is run. This grants the attacker the ability to take control of the affected system, potentially leading to unauthorized data access, modification, or deletion, installation of further malicious software, or lateral movement within the network. The impact is direct system compromise as the user running the `gpsprof` utility. While no specific victim counts are available, any system running the vulnerable versions of `gpsd` with `gpsprof` exposed to untrusted GPS data is at risk.

## Recommendation

* Patch CVE-2026-60122 immediately by upgrading `gpsd` to a version beyond 3.27.5 or applying commit 4c06658.
* Deploy the Sigma rule "Detect Gnuplot Spawning Suspicious Child Processes" to your SIEM to identify `gnuplot` initiating unexpected shell processes, which is a strong indicator of exploitation.
* Enable process creation logging for `gnuplot` and `gpsprof` on Linux and macOS systems to ensure the detection rule has the necessary telemetry.
* Review execution logs for `gpsprof` and `gnuplot` processes for any unusual arguments or child processes.
