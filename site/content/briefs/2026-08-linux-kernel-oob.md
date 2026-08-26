---
title: Linux Kernel Out-of-Bounds Write Vulnerability (CVE-2022-0995)
slug: 2026-08-linux-kernel-oob
description: The Linux Kernel contains an out-of-bounds memory write vulnerability that enables a local attacker to achieve privilege escalation or cause a system denial of service.
date: "2026-08-26T20:17:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.17:rc1:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.17:rc2:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.17:rc3:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.17:rc4:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.17:rc5:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.17:rc6:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.17:rc7:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h300e_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h300s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h410c_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h410s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h500e_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h610c_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h610s_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h615c_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h700e_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:netapp:h700s_firmware:-:*:*:*:*:*:*:*
vendors:
  - Linux
products:
  - Kernel
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Linux Kernel contains an out-of-bounds memory write vulnerability which could allow a local user to gain privileged access
    confidence_band: high
cves:
  - id: CVE-2022-0995
    cvss: 7.8
    epss: 0.06344
references:
  - https://www.cve.org/CVERecord?id=CVE-2022-0995
  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=93ce93587d36493f2f86921fa79921b3cba63fbb
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://nvd.nist.gov/vuln/detail/CVE-2022-0995
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Linux systems to a non-vulnerable kernel version as mandated by CISA BOD 26-04
      owner: IT Operations
      due: "2026-09-09"
      evidence: CISA BOD 26-04 directive referenced in source
  mitigation_plan:
    - priority: immediate
      action: Identify internet-facing assets running susceptible kernels
      owner: IT Operations
      addresses: CVE-2022-0995
      evidence: BOD 26-04 prioritization guidance
---

CVE-2022-0995 is an out-of-bounds write vulnerability within the Linux Kernel. This vulnerability exists in the implementation of the watch_queue subsystem, where improper management of memory offsets during certain pipe operations can be exploited. Because this occurs at the kernel level, a local attacker with non-privileged access to the system can trigger the memory corruption to overwrite sensitive kernel structures. This capability allows the attacker to gain elevated (root) privileges or force a kernel panic, resulting in a denial-of-service condition. Given that the Linux Kernel serves as the foundation for a vast array of enterprise, cloud, and embedded systems, the security impact is broad. Organizations are required to identify and patch vulnerable kernel versions in accordance with CISA BOD 26-04 mandates.

## Attack Chain

1. The attacker gains initial local access to the target Linux system via a separate entry point or low-privileged account.
2. The attacker interacts with the kernel's watch_queue mechanism by executing system calls specifically designed to invoke the flawed memory write operation.
3. The attacker provides crafted inputs to the pipe buffer, triggering an out-of-bounds write beyond the allocated kernel memory region.
4. The memory corruption is used to overwrite kernel function pointers or task structures in memory.
5. The kernel executes the hijacked function pointers, redirecting the control flow to attacker-supplied shellcode or payload.
6. The shellcode completes, granting the attacker root privileges on the compromised system.
7. The final objective is achieved, such as establishing persistence, data exfiltration, or further lateral movement within the network.

## Impact

Successful exploitation allows for full system compromise via privilege escalation, which can lead to complete loss of confidentiality, integrity, and availability of the host. The number of potentially impacted systems is extensive due to the ubiquity of the affected Linux Kernel versions. The vulnerability also poses a significant risk to cloud environments and enterprise infrastructure that rely on kernel-level security for process isolation.

## Recommendation

Prioritize the identification and patching of Linux distributions currently running kernel versions susceptible to CVE-2022-0995. Ensure compliance with CISA BOD 26-04 for internet-facing assets and implement the required forensic triage measures if unauthorized privilege escalation is suspected. Organizations should audit all internal systems to determine if they rely on affected kernels and apply vendor-supplied security updates immediately.
