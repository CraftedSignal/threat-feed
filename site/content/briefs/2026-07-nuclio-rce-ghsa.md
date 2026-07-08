---
title: Nuclio Controller Vulnerability Leads to Persistent Kubernetes RCE (GHSA-v5px-423j-pf7p)
slug: 2026-07-nuclio-rce-ghsa
description: The Nuclio controller improperly sanitizes user-controlled input (cron trigger event headers and body) before injecting it into `curl` commands executed by Kubernetes CronJobs, allowing remote attackers to perform command injection and achieve remote code execution (RCE) by breaking quoting contexts in header keys or utilizing shell command substitution in event bodies, leading to arbitrary command execution with root privileges and potential persistence within the Kubernetes cluster.
date: "2026-07-08T20:26:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - kubernetes
  - cloud-native
  - command-injection
  - persistence
  - critical-vulnerability
  - ghsa
vendors:
  - Nuclio
products:
  - Nuclio <= 1.15.27
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The entire concatenated string — including any injected content — is executed by the shell.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: The CronJob created by the controller carries no `ownerReferences` linking it to the NuclioFunction... the CronJob continues executing on its schedule indefinitely.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 50
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-v5px-423j-pf7p
iocs:
  - type: attack_string
    value: X-Inject"; echo "===RCE_CONFIRMED==="; id; cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 50; echo "
  - type: attack_string
    value: $(id 1>&2; echo BODY_INJECTION_PROOF)
ioc_counts:
  attack_string: 2
rules:
  - title: Detect Nuclio CronJob RCE via Header Key Injection (GHSA-v5px-423j-pf7p)
    description: Detects creation or modification of Kubernetes CronJobs by Nuclio where the container arguments indicate command injection via unsanitized `event.headers` keys, as described in GHSA-v5px-423j-pf7p. This is characterized by a double-quote break followed by shell commands.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - execution
      - persistence
    techniques:
      - T1003
      - T1059.004
      - T1543.003
    data_sources:
      - audit_log
      - kubernetes
  - title: Detect Nuclio CronJob RCE via Body Command Substitution (GHSA-v5px-423j-pf7p)
    description: Detects creation or modification of Kubernetes CronJobs by Nuclio where the container arguments indicate command injection via unsanitized `event.body` using shell command substitution, as described in GHSA-v5px-423j-pf7p.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.004
      - T1543.003
    data_sources:
      - audit_log
      - kubernetes
rules_count: 2
---

A critical vulnerability (GHSA-v5px-423j-pf7p, CWE-78) has been identified in the Nuclio controller, affecting all versions up to and including 1.15.27. This flaw stems from inadequate sanitization of user-provided input, specifically `event.headers` keys and `event.body` content within cron trigger specifications for NuclioFunctions. When the controller generates a Kubernetes CronJob, it constructs a `curl` invocation string that incorporates these unsanitized values directly into a shell command executed by `/bin/sh -c`. Attackers can exploit this by injecting shell metacharacters - either by breaking the double-quote context in `headerKey` or by using command substitution in `event.body` - to execute arbitrary commands within the CronJob's container. These CronJobs typically run with root privileges and, notably, lack Kubernetes `ownerReferences`, allowing them to persist indefinitely even if the original NuclioFunction is deleted, posing a significant risk for persistent remote code execution within the cluster.

## Attack Chain

1. An attacker, with permissions to create or modify NuclioFunctions in the Kubernetes cluster, crafts a malicious NuclioFunction definition.
2. The attacker includes a `cron` trigger with a specially crafted `event.headers` key (e.g., `X-Inject"; ARBITRARY_COMMAND; echo "`) or a malicious `event.body` (e.g., `$(ARBITRARY_COMMAND)`) within the function's specification.
3. The Nuclio controller reconciles the malicious NuclioFunction, invoking `generateCronTriggerCronJobSpec` to construct the internal `curl` command string.
4. During command construction, the unsanitized `headerKey` or `eventBody` is injected directly into the shell command argument passed to `/bin/sh -c`. For `headerKey`, double quotes are improperly handled, allowing direct shell command injection; for `eventBody`, `strconv.Quote` fails to escape `$(...)`, enabling command substitution.
5. The controller creates a Kubernetes CronJob resource with its container `args` explicitly configured as `/bin/sh -c <malicious_curlCommand>`, where `malicious_curlCommand` now contains the injected arbitrary commands.
6. The Kubernetes scheduler activates the CronJob, causing the CronJob pod to execute the `sh -c` command, leading to the execution of arbitrary commands (e.g., `id`, `cat /var/run/secrets/...`) within the pod. These pods often run with root privileges.
7. The created CronJob lacks Kubernetes `ownerReferences`, allowing it to persist and continue executing its schedule indefinitely, even if the original NuclioFunction or its Deployment is subsequently removed.
8. The attacker leverages this RCE to exfiltrate sensitive data (such as Kubernetes service account tokens), establish a persistent foothold, or further compromise the Kubernetes cluster.

## Impact

Successful exploitation of this vulnerability grants remote attackers persistent remote code execution within the target Kubernetes cluster, typically with root privileges. This allows for arbitrary command execution, sensitive data exfiltration (e.g., Kubernetes service account tokens), and potential for broader compromise of cluster resources. The lack of `ownerReferences` on the created CronJobs means that even if a compromised NuclioFunction is deleted, the malicious CronJob can continue to run indefinitely, ensuring persistence for the attacker. The vulnerability carries a CVSS 3.1 score of 9.9 (Critical), indicating severe consequences for confidentiality, integrity, and availability of the affected system.

## Recommendation

* **Patch CVE-XXXX-YYYY immediately**: Upgrade Nuclio to a patched version once available. Monitor official Nuclio channels for security updates addressing GHSA-v5px-423j-pf7p.
* **Deploy the Sigma rules in this brief**: Implement the `Detect Nuclio CronJob RCE via Header Key Injection` and `Detect Nuclio CronJob RCE via Body Command Substitution` rules to identify attempts at exploiting this vulnerability at the Kubernetes API server audit log level.
* **Review Kubernetes audit logs**: Actively monitor for suspicious `create`, `update`, or `patch` events on `batch/v1/cronjobs` resources, especially those originating from the Nuclio controller, for `args` fields containing the patterns identified in the IOCs.
* **Restrict NuclioFunction deployment permissions**: Limit permissions to create or modify `NuclioFunction` resources to trusted administrators, reducing the attack surface for this vulnerability.
