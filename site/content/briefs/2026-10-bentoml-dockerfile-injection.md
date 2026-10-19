---
title: CVE-2026-112264 - Dockerfile Instruction Injection in BentoML
slug: 2026-10-bentoml-dockerfile-injection
description: BentoML versions through 1.4.39 are vulnerable to Dockerfile instruction injection, allowing attackers to execute arbitrary commands during the containerization process by exploiting improper newline handling in template files.
date: "2026-10-19T16:08:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bentoml:bentoml:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - container-security
  - injection
  - cve
vendors:
  - BentoML
products:
  - BentoML (<= 1.4.39)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can supply a crafted bentofile.yaml or imported bento archive so that bentoml containerize executes injected RUN instructions during docker build.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply a crafted bentofile.yaml or imported bento archive so that bentoml containerize executes injected RUN instructions during docker build.
    confidence_band: high
cves:
  - id: CVE-2026-112264
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112264
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade BentoML instances to a version later than 1.4.39
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-112264 vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Upgrade BentoML to a patched version
      owner: IT Operations
      addresses: CVE-2026-112264
      evidence: NVD vulnerability details
---

BentoML versions up to and including 1.4.39 contain a critical Dockerfile instruction injection vulnerability tracked as CVE-2026-112264. The vulnerability exists within the legacy 'base.j2' template used during the containerization process. Specifically, the system fails to properly sanitize newline characters when processing 'docker.env' mapping keys. 

An attacker can supply a specially crafted 'bentofile.yaml' or an imported bento archive that includes newline characters within these keys. When the 'bentoml containerize' command is executed, the template engine renders a malicious Dockerfile that incorporates unintended build instructions. This flaw allows an attacker to execute arbitrary commands during the 'docker build' phase. This is a significant risk for CI/CD pipelines, as successful exploitation can lead to the exfiltration of build-time secrets, unauthorized modification of container images (image poisoning), and potential compromise of the build environment or the resulting containerized service.

## Attack Chain

1. Attacker crafts a malicious 'bentofile.yaml' containing a 'docker.env' mapping key that includes newline characters and injected Docker instructions (e.g., a RUN command).
2. Attacker provides the malicious file to a developer or uploads it to a source repository, or distributes a crafted bento archive.
3. A user or automated CI/CD pipeline triggers the 'bentoml containerize' command using the malicious configuration.
4. The BentoML template engine processes the 'base.j2' file and fails to sanitize the injected newline characters in the environment mapping keys.
5. The rendering process writes the injected instructions into the generated Dockerfile as valid Docker build commands.
6. The system executes 'docker build' using the compromised Dockerfile.
7. The Docker engine executes the injected RUN instruction with the privileges of the build process.
8. Final objective achieved: Exfiltration of build environment secrets, image poisoning, or code execution within the CI/CD pipeline.

## Impact

Successful exploitation allows for the execution of arbitrary commands during container image creation. In enterprise environments, this impacts the integrity of the software supply chain. Attackers may gain access to build-time environment variables, credentials, or API keys defined in the CI/CD pipeline. Additionally, attackers can poison the final container image, leading to downstream execution of malicious code in production environments that deploy the compromised BentoML container.

## Recommendation

- Upgrade BentoML to a version beyond 1.4.39 to ensure the fix for CVE-2026-112264 is applied.
- Audit CI/CD pipeline configurations that use 'bentoml containerize' for any untrusted input in 'bentofile.yaml' files.
- Implement strict code review processes for any changes to 'bentofile.yaml' or related bento archive imports.
- Restrict access to build secrets; use short-lived credentials for CI/CD tasks to limit the impact of potential secret exfiltration via build-time injection.
