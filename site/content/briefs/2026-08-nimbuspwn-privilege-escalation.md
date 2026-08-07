---
title: Nimbuspwn Privilege Escalation Vulnerability
slug: 2026-08-nimbuspwn-privilege-escalation
description: Nimbuspwn refers to a collection of Linux privilege escalation vulnerabilities in the networkd-dispatcher service that attackers can exploit via directory traversal to achieve root-level code execution.
date: "2026-08-07T15:16:13Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:microsoft:windows_defender_for_endpoint:*:*:*:*:*:linux:*:*
  - cpe:2.3:a:microsoft:windows_defender_for_endpoint:-:*:*:*:*:linux:*:*
vendors:
  - Systemd
products:
  - networkd-dispatcher
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The following analytic detects directory traversal attempts associated with Nimbuspwn, a Linux privilege escalation vulnerability.
    confidence_band: high
cves:
  - id: CVE-2022-29799
    cvss: 5.5
    epss: 0.11667
  - id: CVE-2022-29800
    cvss: 4.7
    epss: 0.07104
references:
  - https://www.microsoft.com/security/blog/2022/04/26/microsoft-finds-new-elevation-of-privilege-linux-vulnerability-nimbuspwn/
rules:
  - title: Detect Nimbuspwn Directory Traversal Attempts
    description: Detects directory traversal attempts against the networkd-dispatcher service consistent with Nimbuspwn exploitation (CVE-2022-29799, CVE-2022-29800).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch all instances of networkd-dispatcher
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies high-severity vulnerabilities CVE-2022-29799 and CVE-2022-29800.
  hunt_leads:
    - lead: Search logs for process command-line containing '../*' associated with networkd-dispatcher
      technique_id: T1068
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic provided by Splunk specifically targets this pattern.
---

Nimbuspwn, identified via CVE-2022-29799 and CVE-2022-29800, involves significant security flaws within the networkd-dispatcher service on Linux systems. The vulnerability resides in how the service handles D-Bus messages and performs directory traversal when scripts are executed. An attacker can exploit this by manipulating the service to execute arbitrary scripts with elevated privileges, effectively escalating access to root. This threat is particularly concerning for defenders as it allows for full system compromise, the installation of persistent backdoors, and the potential deployment of further malicious payloads. The exploitation mechanism relies on triggering the service's logic to traverse directories to an attacker-controlled path, where malicious code is then executed by the service as the root user.

## Attack Chain

1. Attacker gains low-privileged access to the target Linux system.
2. Attacker identifies the running networkd-dispatcher service as a target for privilege escalation.
3. Attacker creates a malicious script or payload to be executed with elevated privileges.
4. Attacker utilizes directory traversal techniques (e.g., using '../*' sequences) to bypass intended path restrictions.
5. Attacker triggers a D-Bus message or service function that forces networkd-dispatcher to execute the attacker's script from the traversed path.
6. The networkd-dispatcher service executes the malicious script under the context of the root user.
7. Attacker successfully gains root-level access for further exploitation or persistence.

## Impact

Successful exploitation allows a low-privileged user to escalate to root, granting them full control over the affected system. This facilitates the deployment of persistent threats, theft of sensitive information, and potential lateral movement within the network. Although specific victim counts are not cited, the ubiquity of systemd-based Linux distributions makes this a critical risk for enterprise environments.

## Recommendation

* Deploy the provided Sigma rule to monitor for suspicious command-line patterns involving networkd-dispatcher.
* Patch all affected Linux distributions to the latest version, as the vendor has released security updates addressing these vulnerabilities.
* Enable Sysmon for Linux process-creation logging to ensure full visibility into command-line arguments.
* Conduct a threat hunt for historical occurrences of directory traversal strings originating from the networkd-dispatcher process.
