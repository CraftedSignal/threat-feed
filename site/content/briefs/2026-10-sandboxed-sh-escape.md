---
title: Container Escape in sandboxed.sh via nsenter Misconfiguration
slug: 2026-10-sandboxed-sh-escape
description: CVE-2026-109569 is a container escape vulnerability in sandboxed.sh versions up to 1.3.0, allowing containerized code to bypass isolation and access the host filesystem via misconfigured nsenter calls.
date: "2026-10-12T22:43:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sandboxed:sandboxed.sh:*:*:*:*:*:*:*:*
vendors:
  - sandboxed.sh
products:
  - sandboxed.sh (<= 1.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: Agent-run code in a container workspace can resolve absolute paths on the host to read and modify host files, bypassing documented isolation.
    confidence_band: high
cves:
  - id: CVE-2026-109569
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109569
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade sandboxed.sh to the latest version to resolve CVE-2026-109569.
      owner: IT Operations
      addresses: CVE-2026-109569
      evidence: sandboxed.sh through 1.3.0 contains a container escape vulnerability
---

CVE-2026-109569 is a critical vulnerability affecting sandboxed.sh versions 1.3.0 and earlier. The flaw exists due to the improper invocation of the nsenter utility within the sandboxed environment. Specifically, the tool attaches to namespaces without the --root flag, which is required to enforce proper path isolation. As a result, code executing within a container workspace can resolve absolute paths that traverse out of the containerized environment and into the host filesystem. An attacker who gains execution within a workspace - typically through legitimate product workflows - can leverage this flaw to read, modify, or delete sensitive host files, effectively neutralizing the security boundary provided by the sandboxed.sh containerization layer.

## Impact

Successful exploitation allows a user with access to a workspace environment to gain unauthorized read and write access to the host machine. This could lead to full system compromise, exfiltration of host-level secrets, or persistent unauthorized access to the underlying infrastructure, impacting all organizations deploying sandboxed.sh in multi-tenant or untrusted user environments.

## Recommendation

* Upgrade sandboxed.sh to a patched version once released by the maintainer.
* Audit host-level logs for unauthorized file access by processes spawned by the sandboxed.sh agent.
* Restrict container workspace privileges using Linux kernel features such as seccomp or AppArmor profiles to prevent the execution of privileged utilities like nsenter if not explicitly required by the workspace design.
