---
title: Container Escape Vulnerability in IBM Aspera Enterprise WebApps
slug: 2026-09-ibm-aspera-escape
description: IBM Aspera Enterprise WebApps versions 1.0.0 through 1.0.5 are susceptible to a container escape vulnerability via unrestricted system calls, potentially allowing a local attacker to gain unauthorized host access.
date: "2026-09-10T23:10:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ibm:aspera_enterprise_webapps:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Aspera Enterprise WebApps (1.0.0 through 1.0.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: IBM Aspera Enterprise WebApps 1.0.0 through 1.0.5 could allow a local attacker to escape container protections due to unrestricted system calls being permitted within the container.
    confidence_band: high
cves:
  - id: CVE-2026-75777
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75777
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade IBM Aspera Enterprise WebApps to the version addressing CVE-2026-75777
      owner: IT Operations
      addresses: CVE-2026-75777
      evidence: Source explicitly identifies vulnerable version range 1.0.0-1.0.5
---

IBM Aspera Enterprise WebApps versions 1.0.0 through 1.0.5 contain a security flaw that permits a local attacker with access to the application container to escape its security boundaries. The vulnerability arises because the container runtime environment permits unrestricted system calls (syscalls) that should be blocked by standard container hardening practices. By invoking these prohibited system calls, an attacker can interact directly with the underlying host kernel, potentially bypassing container isolation. This vulnerability poses a significant risk to host integrity in multi-tenant or shared-infrastructure environments where Aspera Enterprise WebApps is deployed.

## Impact

Successful exploitation of this vulnerability allows a local attacker to escape the container environment, gaining unauthorized access to the host operating system. This could lead to full system compromise, data exfiltration from the host, or lateral movement within the network. The scope of impact is limited to organizations running the vulnerable 1.0.0 through 1.0.5 versions of the software in containerized environments.

## Recommendation

* Update IBM Aspera Enterprise WebApps to the latest available version that patches CVE-2026-75777.
* Audit container security configurations to restrict syscalls via Seccomp profiles or AppArmor/SELinux policies.
* Apply the principle of least privilege by running containers with non-root users where possible, limiting the potential impact of an escape.
