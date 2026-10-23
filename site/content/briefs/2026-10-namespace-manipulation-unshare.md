---
brief_id: brief-2026-10-23-namespace-manipulation-unshare
event_id: brief-2026-10-23-namespace-manipulation-unshare
revision: 1
activity_at: "2026-10-23T14:42:31Z"
title: Linux Namespace Manipulation Using Unshare
slug: 2026-10-namespace-manipulation-unshare
description: Threat actors utilize the Linux 'unshare' utility to manipulate system namespaces for container escapes and privilege escalation, allowing unauthorized access to host resources.
date: "2026-10-23T14:42:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h410c_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h300s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h700s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h300e_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h500e_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h700e_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h410s_firmware:-:*:*:*:*:*:*:*
cves:
  - id: CVE-2022-0185
    cvss: 8.4
    epss: 0.25151
    kev_status: "false"
references:
  - https://man7.org/linux/man-pages/man1/unshare.1.html
  - https://www.crowdstrike.com/blog/cve-2022-0185-kubernetes-container-escape-using-linux-kernel-exploit/
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_unshare_namespace_manipulation.toml
---

The `unshare` command in Linux is used to create new namespaces, isolating processes from the rest of the system. While this mechanism is used for containerization and security, it can be exploited to break out of containers or elevate privileges by bypassing security controls.

## Investigative Context
Legitimate system management tools (such as `udevadm`, `systemd-udevd`, and `snap` package management) may invoke `unshare` as part of normal operations. Investigations should focus on the process tree, user account context, and command-line arguments to distinguish between administrative tasks and malicious activity.
