---
title: CVE-2026-58459 - gpsd gpsprof Command Injection
slug: 2026-07-gpsd-cmd-injection
description: A command injection vulnerability, CVE-2026-58459, exists in the gpsprof utility of gpsd through version 3.27.5, allowing an attacker to exploit this by controlling the GPS device subtype value and embedding backtick payloads within the gnuplot plot title, which leads to arbitrary shell command execution as the user running gnuplot when a victim renders a generated plot via the gpsprof and gnuplot workflow due to improper escaping.
date: "2026-07-09T17:19:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - execution
  - linux
  - macos
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
    evidence: Attacker embedding backtick payloads in the gnuplot plot title without proper escaping allows execution of arbitrary shell commands as the user running gnuplot.
    confidence_band: high
cves:
  - id: CVE-2026-58459
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58459
rules:
  - title: Detects CVE-2026-58459 Exploitation - gnuplot Spawning Suspicious Processes
    description: Detects CVE-2026-58459 exploitation where the gnuplot process, invoked by gpsprof, spawns suspicious child processes indicative of command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detects CVE-2026-58459 Exploitation (macOS) - gnuplot Spawning Suspicious Processes
    description: Detects CVE-2026-58459 exploitation where the gnuplot process, invoked by gpsprof, spawns suspicious child processes indicative of command injection on macOS.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

gpsd, an open-source service daemon for GPS receivers, through release 3.27.5, contains a critical command injection vulnerability, CVE-2026-58459, within its `gpsprof` utility. This flaw allows an attacker to achieve arbitrary shell command execution on systems that process potentially untrusted GPS device subtype values. The vulnerability arises when the `gpsprof` utility generates gnuplot programs for data visualization. Specifically, if a maliciously crafted GPS device subtype value, sourced from a DEVICES JSON log entry or an NMEA PGRMT sentence, contains backtick payloads, `gpsprof` will embed these unescaped payloads directly into the `set title` statement of the gnuplot script. When a victim subsequently renders this generated plot using the `gnuplot` program, the embedded shell commands are executed with the privileges of the user running `gnuplot`. This impacts systems that use `gpsprof` to analyze GPS data, potentially leading to full system compromise or data exfiltration by exploiting an often overlooked data processing workflow.

## Attack Chain

1. An attacker crafts a malicious GPS device subtype value containing shell command payloads (e.g., `test`\`id`\`). This value can be embedded in a DEVICES JSON log entry or an NMEA PGRMT sentence.
2. The malicious GPS data is provided to a system running `gpsd`.
3. The `gpsprof` utility is invoked on the system to process the GPS data and generate a gnuplot program.
4. `gpsprof` reads the malicious device subtype value and, due to improper escaping, embeds the backtick payload directly into a `set title` statement within the generated gnuplot script.
5. A legitimate user or automated process attempts to render the generated plot by executing the crafted gnuplot program using the `gnuplot` application.
6. Upon execution, the `gnuplot` application interprets the backtick payload within the `set title` command, leading to the execution of the attacker's arbitrary shell commands with the privileges of the user running `gnuplot`.
7. The attacker's commands execute, potentially leading to system compromise, data exfiltration, or further lateral movement.

## Impact

Successful exploitation of CVE-2026-58459 grants an attacker arbitrary shell command execution as the user running the `gpsprof` and `gnuplot` workflow. This can lead to complete compromise of the affected system, allowing for data exfiltration, installation of additional malware, or further lateral movement within the network. While no specific victim count or targeted sectors have been disclosed, any organization or individual processing potentially untrusted GPS data using `gpsd` versions through 3.27.5 is at risk. The ease of exploitation by simply controlling an input value makes this a significant threat.

## Recommendation

* Patch CVE-2026-58459 immediately by upgrading `gpsd` to a version beyond 3.27.5, or applying commit 4c06658.
* Deploy the Sigma rule "Detects CVE-2026-58459 Exploitation - gnuplot Spawning Suspicious Processes" in this brief to your SIEM to detect suspicious process execution originating from `gnuplot` on Linux and macOS systems.
* Enable `process_creation` logging for Linux and macOS endpoints to ensure telemetry is available for the provided detection rule.
* Review and restrict execution of `gpsprof` and `gnuplot` to trusted data sources and environments where untrusted input cannot be processed.
