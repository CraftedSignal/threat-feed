---
title: Privilege Escalation Vulnerability in Performance Co-Pilot linux_sockets Module
slug: 2026-07-pcp-privesc
description: A file descriptor leak in the Performance Co-Pilot (PCP) linux_sockets module allows an attacker with initial code execution to escalate privileges to root.
date: "2026-07-30T07:20:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - linux
  - cve-2026-16526
vendors:
  - Red Hat
products:
  - Performance Co-Pilot (PCP)
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
  - Red Hat Enterprise Linux 10
  - Red Hat OpenShift Container Platform 4
affected_os:
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
  - Red Hat Enterprise Linux 10
cves:
  - id: CVE-2026-16526
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16526
  - https://access.redhat.com/security/cve/CVE-2026-16526
  - https://bugzilla.redhat.com/show_bug.cgi?id=2506026
---

A security vulnerability identified as CVE-2026-16526 exists within the Performance Co-Pilot (PCP) linux_sockets module, specifically categorized as CWE-403: Exposure of File Descriptor to Unintended Control Sphere. This vulnerability stems from an insecure internal connection that leaks file descriptors. An attacker who has already obtained initial low-privilege code execution on a target system can exploit this leak to interact with privileged internal PCP processes. By successfully abusing this communication channel, an unprivileged user can escalate their permissions to root, allowing for the execution of arbitrary commands with full system control. The vulnerability affects multiple versions of Red Hat Enterprise Linux and Red Hat OpenShift Container Platform utilizing the PCP package.

## Impact

Successful exploitation of this vulnerability results in full local privilege escalation. In environments where PCP is deployed, this poses a high risk to system integrity, as attackers can bypass standard access controls to execute unauthorized code as the root user. This could lead to data exfiltration, backdooring of the host, or total system compromise.

## Recommendation

1. Identify all systems running the affected 'pcp' package across the environment using your asset inventory or package management logs.
2. Apply security updates provided by Red Hat to resolve CVE-2026-16526 as documented in the Red Hat Security Advisory.
3. Until patching is complete, restrict access to the PCP monitoring services to authorized administrative users only.
4. Ensure that auditd or system-level process monitoring is configured to detect unexpected privilege changes or suspicious activities originating from the 'pcp' service user context.
