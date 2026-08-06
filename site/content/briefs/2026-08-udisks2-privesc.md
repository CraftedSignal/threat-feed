---
title: Local Privilege Escalation in udisks2 via D-Bus Mount Injection
slug: 2026-08-udisks2-privesc
description: A local privilege escalation vulnerability in udisks2 allows authenticated console users to bypass authorization checks in the org.freedesktop.UDisks2.Filesystem.Mount() D-Bus method to mount filesystems as privileged users.
date: "2026-08-06T23:33:26Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Freedesktop
products:
  - udisks2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This allows the attacker to spoof the 'as-user' parameter, mounting filesystems on behalf of arbitrary users, including privileged accounts.
    confidence_band: high
cves:
  - id: CVE-2026-7867
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7867
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch udisks2 on all Linux systems
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-7867 identified as high-severity privilege escalation
  mitigation_plan:
    - priority: immediate
      action: Patch udisks2 via distribution package manager
      owner: IT Operations
      addresses: CVE-2026-7867
      evidence: NVD advisory for CVE-2026-7867
---

CVE-2026-7867 describes an authorization bypass vulnerability in udisks2, a core system component responsible for storage management on many Linux distributions. The vulnerability resides within the D-Bus method org.freedesktop.UDisks2.Filesystem.Mount(). A local attacker who maintains an active console session can manipulate the 'as-user' parameter during the mounting process. By providing unauthorized user identifiers to this parameter, an attacker can influence the mount operation to execute within the context of arbitrary, higher-privileged accounts. Successful exploitation grants the attacker the ability to inject mount points and manipulate the mount namespace of privileged users, effectively leading to full local privilege escalation. This issue is particularly critical in multi-user environments or shared workstations where local console access is available to unprivileged users.

## Impact

Successful exploitation of CVE-2026-7867 allows an unprivileged local user to escalate their privileges to those of other users, including root or service accounts. The impact involves potential system-wide compromise, unauthorized data access, and persistence through the manipulation of mount configurations. The scope of targeting includes any Linux environment utilizing udisks2 with default configurations where D-Bus access is permitted for local console users.

## Recommendation

* Identify and audit systems running udisks2 using package management logs or inventory tools.
* Monitor D-Bus communication logs for suspicious calls to org.freedesktop.UDisks2.Filesystem.Mount(), specifically looking for anomalous values passed to the 'as-user' parameter.
* Patch the udisks2 package to the version provided by the distribution maintainer that addresses CVE-2026-7867.
* Restrict access to system D-Bus interfaces if not strictly required for local user sessions.
