---
title: 'CVE-2026-69096: OS Command Injection in OpenWrt luci-app-dockerman'
slug: 2026-08-openwrt-luci-cmd-injection
description: An authenticated OS command injection vulnerability in the docker_rpc.uc backend of luci-app-dockerman allows attackers with read-only ACLs to execute arbitrary commands as root via the /ubus RPC endpoint.
date: "2026-08-03T16:06:45Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - OpenWrt
products:
  - luci-app-dockerman
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The run_ttyd handler builds a shell command from the request-controlled id, cmd, and uid fields and passes it to system() without quoting.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated attacker holding only the luci-app-dockerman read ACL can inject shell metacharacters... to execute arbitrary commands as root.
    confidence_band: high
cves:
  - id: CVE-2026-69096
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69096
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review current OpenWrt firmware versions to identify affected snapshot releases.
      owner: IT Operations
      due: 24h
      evidence: openwrt-25.12 and master snapshots are explicitly listed as affected.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /ubus and the web interface to authorized administrative IP addresses.
      owner: IT Operations
      addresses: CVE-2026-69096
      evidence: Exploitation requires authentication and access to the /ubus RPC endpoint.
---

CVE-2026-69096 describes a critical OS command injection vulnerability within the luci-app-dockerman package for OpenWrt, specifically affecting LuCI master and openwrt-25.12 snapshot releases. The vulnerability originates in the ucode-based docker_rpc.uc RPC backend, which was introduced during a recent transition from JS to ucode. Due to an overly permissive read ACL, the docker.container.ttyd_start method is exposed to users who should only possess read-only privileges. 

The vulnerable code within the run_ttyd handler fails to properly sanitize or quote input parameters - specifically 'id', 'cmd', and 'uid' - before passing them to the system() function. Because the rpcd process operates with root-level privileges, an authenticated attacker can leverage this misconfiguration to perform arbitrary command execution. This flaw is restricted to versions containing the new ucode backend, meaning older stable releases like openwrt-24.10 and openwrt-23.05 remain unaffected. As of the initial advisory, no patch has been released to mitigate this issue.

## Impact

Successful exploitation grants an authenticated attacker full root-level control over the OpenWrt device. This allows for total system compromise, including the interception of network traffic, persistence installation, and potential lateral movement into the local network. Given the nature of OpenWrt deployments as edge routers and gateways, this vulnerability significantly increases the risk of man-in-the-middle attacks and internal network exposure.

## Recommendation

* Audit existing OpenWrt deployments to identify the use of the luci-app-dockerman package on openwrt-25.12 or LuCI master snapshots.
* Monitor ubus request logs for suspicious JSON-RPC calls targeting the docker.container.ttyd_start method, specifically observing unexpected shell metacharacters in parameter fields.
* If the package is not required, uninstall luci-app-dockerman until a vendor-supplied patch is available.
* Implement strict firewall controls to limit access to the web interface (LuCI) and the ubus RPC endpoint to trusted internal management subnets only.
