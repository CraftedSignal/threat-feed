---
title: Authentication Bypass in KubeEdge CloudCore Node Task Reporting
slug: 2026-08-kubeedge-auth-bypass
description: KubeEdge CloudCore versions through 1.23.1 contain an authentication bypass vulnerability allowing unauthenticated remote attackers to manipulate node upgrade status reports via port 10002.
date: "2026-08-29T17:41:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cncf:kubeedge_cloudcore:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud-native
  - kubernetes
vendors:
  - CNCF
products:
  - KubeEdge CloudCore (<= 1.23.1)
cves:
  - id: CVE-2026-82473
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82473
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Infrastructure Security
  immediate_actions:
    - action: Upgrade KubeEdge CloudCore to version 1.23.2 or later to address CVE-2026-82473
      owner: IT Operations
      due: 48h
      evidence: Source specifies vulnerable versions up to 1.23.1
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to port 10002 on CloudCore hosts
      owner: Infrastructure Security
      addresses: CVE-2026-82473
      evidence: The vulnerability allows unauthenticated access to the HTTPS server on port 10002
---

KubeEdge CloudCore versions up to 1.23.1 are susceptible to an authentication bypass vulnerability. The CloudCore component exposes an HTTPS server on port 10002 that fails to properly verify the authenticity of incoming node task status reports. An unauthenticated attacker with network access to this port can submit crafted requests to the control plane, masquerading as a node. By injecting false success or failure status messages for node upgrade jobs, an attacker can deceive the control plane's state machine. This manipulation disrupts the orchestration logic, effectively causing a denial of service regarding the automated scheduling and execution of future node upgrades within the KubeEdge cluster. The issue represents a significant risk to environment management and fleet maintenance operations.

## Impact

Successful exploitation allows an unauthorized party to disrupt cluster management operations by poisoning the status of node upgrade tasks. This results in the blocking of legitimate upgrade schedules across the affected KubeEdge deployment, potentially leaving nodes running outdated, vulnerable, or incompatible software versions. While no massive data breach is immediately associated with this vulnerability, the loss of control over cluster state management poses a high impact to system availability and maintenance integrity in environments relying on KubeEdge for automated lifecycle management.

## Recommendation

Prioritize the immediate mitigation of the vulnerability identified in CVE-2026-82473.

* Upgrade KubeEdge CloudCore to a version greater than 1.23.1 immediately to incorporate the necessary authentication checks for task status reports.
* Restrict network access to CloudCore port 10002. Only trusted edge node communication paths should be permitted to reach this port at the network layer.
* Implement host-based or network-level firewall policies to prevent unauthorized subnets or external entities from reaching the management interface of the CloudCore service.
