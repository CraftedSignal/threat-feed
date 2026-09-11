---
title: Detection of Web Server-Created High-Entropy Files
slug: 2026-09-linux-web-shell-entropy
description: Detection of web server processes creating high-entropy files with web-executable extensions, a behavior indicative of uploading obfuscated or packed web shells for persistence.
date: "2026-09-11T12:49:44Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: An attacker may save an obfuscated PHP web shell as a .phtml file under the document root, then invoke it over HTTP to establish persistent remote access.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: After exploiting a vulnerable upload endpoint, an attacker may save an obfuscated PHP web shell.
    confidence_band: high
rules:
  - title: Detect High Entropy File Created by Web Server
    description: Detects when a Linux web server process creates a new file with high entropy and a web-executable extension, indicating potential web shell creation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable advanced file entropy collection in EDR policies.
      owner: Detection Engineering
      due: 72h
      evidence: Required for rule efficacy.
  hunt_leads:
    - lead: Search for high-entropy files created in web document roots over the past 30 days.
      technique_id: T1505.003
      data_needed:
        - File creation logs with entropy metrics
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: High-entropy files are a strong indicator of packed/obfuscated web shells.
  mitigation_plan:
    - priority: immediate
      action: Restrict web-write access to non-essential directories.
      owner: IT Operations
      addresses: T1505.003
      evidence: Prevents unauthorized file placement in execution paths.
---

This threat brief focuses on detecting the creation of suspicious files by web server processes on Linux systems. Attackers frequently exploit vulnerabilities in public-facing applications to upload malicious payloads. When these payloads are obfuscated, encrypted, or packed to evade signature-based detection, they often exhibit high file entropy. By monitoring for the creation of files with high entropy (typically defined as >= 6.0 in this context) and web-executable extensions (such as .php, .jsp, or .aspx) within directories accessible to web server processes, security operations teams can identify potential web shell plants or unauthorized backdoors. This technique is a common precursor to establishing persistent remote access and conducting further lateral movement within a compromised environment. Defenders should focus on correlating file creation events with web access logs and process execution metadata to confirm malicious intent.

## Attack Chain

1. Attacker identifies a public-facing web application with an insecure file upload or remote code execution vulnerability.
2. Attacker crafts a malicious web shell payload, potentially using obfuscation or packing techniques to bypass basic security controls.
3. Attacker sends an HTTP request to the vulnerable application endpoint, triggering the web server process to write the payload to disk.
4. The web server process, running with its associated service account, creates a new file in a web-accessible directory.
5. The file exhibits high entropy due to the encoded or encrypted nature of the malicious code.
6. Attacker invokes the newly created file over HTTP to execute arbitrary commands on the underlying host.
7. Attacker establishes persistent remote code execution and may proceed to move laterally within the network.

## Impact

Successful exploitation allows attackers to achieve persistent remote code execution, leading to data exfiltration, internal network reconnaissance, and potential full system compromise. The impact is significant for organizations relying on public-facing web applications, as these serve as initial entry points for broad-spectrum compromises.

## Recommendation

1. Deploy the provided detection logic to identify high-entropy files created by web server processes.
2. Configure endpoint security agents to enable advanced file metadata capture (e.g., `linux.advanced.events.populate_file_data` set to `true` for Elastic Defend).
3. Correlate alerts triggered by this rule with web server and reverse-proxy logs to identify the source IP addresses and specific HTTP requests associated with the file creation.
4. Perform periodic audits of web-accessible directories to detect unauthorized file additions that do not correlate with legitimate CI/CD or deployment pipelines.
5. Harden web server configurations to prevent execution in file upload directories and enforce strict file extension and content validation.
