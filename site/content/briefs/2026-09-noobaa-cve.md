---
title: OS Command Injection in NooBaa cluster_internal_api
slug: 2026-09-noobaa-cve
description: CVE-2026-86330 is an OS command injection vulnerability in the NooBaa cluster_internal_api component of Red Hat OpenShift Data Foundation, allowing authenticated administrative attackers to execute arbitrary system commands.
date: "2026-09-28T14:15:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:openshift_data_foundation:*:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:noobaa:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - openshift
vendors:
  - Red Hat
products:
  - OpenShift Data Foundation
  - NooBaa
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability occurs because the hostname parameter is passed directly to a shell command without proper sanitization.
    confidence_band: high
cves:
  - id: CVE-2026-86330
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86330
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Red Hat OpenShift Data Foundation to the version remediating CVE-2026-86330.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-86330 mitigation requires software updates.
  mitigation_plan:
    - priority: immediate
      action: Restrict administrative access to the NooBaa management API.
      owner: IT Operations
      addresses: CVE-2026-86330
      evidence: Exploitation requires authenticated administrative privileges.
---

CVE-2026-86330 is a high-severity OS command injection vulnerability identified in the set_hostname_internal function within the cluster_internal_api component of NooBaa. NooBaa serves as the Multi-Cloud Object Gateway for Red Hat OpenShift Data Foundation. The vulnerability stems from the direct and unsanitized passage of the hostname parameter into a shell execution context. This flaw permits an authenticated user possessing administrative privileges to inject shell metacharacters into the hostname field, resulting in the execution of arbitrary commands on the underlying host. The injected commands run with the privileges assigned to the NooBaa process, posing a significant risk to the integrity and confidentiality of the storage gateway environment.

## Impact

Successful exploitation of this vulnerability allows an authenticated administrative attacker to gain arbitrary code execution on the host system running the NooBaa component. This can lead to full compromise of the Multi-Cloud Object Gateway, unauthorized access to stored data, or lateral movement within the OpenShift environment. The vulnerability impacts deployments of Red Hat OpenShift Data Foundation utilizing the affected NooBaa version.

## Recommendation

Detection engineering teams should monitor for suspicious process executions originating from the NooBaa process space.
- Audit administrative access to the cluster_internal_api to identify potential abuse of configuration parameters.
- Apply security patches provided by Red Hat for OpenShift Data Foundation to address CVE-2026-86330.
- Implement process-level monitoring on the NooBaa controller to detect unexpected shell invocations (e.g., /bin/sh or /bin/bash) triggered by the NooBaa process.
