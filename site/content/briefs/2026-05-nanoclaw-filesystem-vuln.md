---
title: NanoClaw Host/Container Filesystem Boundary Vulnerability
slug: 2026-05-nanoclaw-filesystem-vuln
description: NanoClaw is vulnerable to a host/container filesystem boundary vulnerability in outbound attachment handling and outbox cleanup, potentially allowing a compromised container to read arbitrary host files or cause recursive deletion of paths outside the intended cleanup target.
date: "2026-05-06T17:16:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - filesystem boundary vulnerability
  - container escape
  - privilege escalation
vendors:
  - NanoClaw
products:
  - NanoClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7875
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7875
rules:
  - title: Detect Container File Access Outside Defined Paths
    description: Detects processes within containers accessing files outside of defined container paths, indicating potential escape attempts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Symlink Creation in Container Outbox
    description: Detects the creation of symbolic links within container outbox directories, a potential indicator of filesystem boundary exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

NanoClaw is susceptible to a critical vulnerability (CVE-2026-7875) residing in its handling of outbound attachments and outbox cleanup processes. This flaw allows a compromised or prompt-injected container to bypass filesystem boundaries, gaining unauthorized access to files outside of its designated outbox directory. This can be achieved through the manipulation of `messages_out.id` and `content.files` values or by the creation of symlinked outbox files. Successful exploitation allows attackers to trigger host-side reads of arbitrary files and in certain scenarios, execute recursive deletion operations beyond the intended cleanup scope. This poses a significant risk to the confidentiality and integrity of the host system.

## Attack Chain

1. The attacker compromises a container running NanoClaw through various means, such as exploiting an application vulnerability or leveraging prompt injection.
2. The attacker crafts a malicious `messages_out.id` value within the compromised container, pointing to a file outside the intended outbox directory.
3. Alternatively, the attacker creates a symbolic link (symlink) within the outbox directory, redirecting to a target file or directory on the host filesystem.
4. The attacker crafts a malicious `content.files` value to include the manipulated `messages_out.id` or the malicious symlink.
5. When NanoClaw processes the outbound attachment, it incorrectly resolves the crafted path due to the filesystem boundary vulnerability.
6. NanoClaw reads the arbitrary file on the host system, exposing sensitive data to the attacker.
7. In cases involving recursive deletion during outbox cleanup, NanoClaw follows the malicious symlink or resolves the crafted path, potentially leading to the deletion of unintended files or directories on the host.
8. The attacker gains access to sensitive information or causes denial-of-service conditions by deleting critical system files, depending on the exploited scenario.

## Impact

Successful exploitation of this vulnerability (CVE-2026-7875) can result in the unauthorized disclosure of sensitive information stored on the host system. It can also lead to data loss or system instability due to the potential for recursive deletion of critical files and directories. The severity of the impact depends on the specific files and directories accessible to the compromised container and the extent of the attacker's malicious activities.

## Recommendation

*   Deploy the Sigma rules provided below to detect exploitation attempts based on suspicious file access patterns within container environments.
*   Implement strict input validation and sanitization for `messages_out.id` and `content.files` to prevent path traversal attacks related to CVE-2026-7875.
*   Enforce proper filesystem isolation and access controls to restrict container access to only necessary resources to mitigate the impact of compromised containers.
*   Regularly audit and monitor container activity for suspicious behavior, such as unexpected file reads or deletions, to identify and respond to potential attacks exploiting CVE-2026-7875.
