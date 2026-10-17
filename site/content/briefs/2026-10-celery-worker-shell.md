---
title: Shell Execution via Celery Worker Processes
slug: 2026-10-celery-worker-shell
description: Detection of system shell spawning from Celery worker processes indicates potential command or prompt injection exploitation within Python-based AI agent task frameworks.
date: "2026-10-17T15:43:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - celery
  - python
  - command-injection
  - execution
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects a system shell interpreter being spawned directly by a Celery worker process.
    confidence_band: high
rules:
  - title: Detect Shell Spawned by Celery Worker Process
    description: Detects a system shell interpreter being spawned directly by a Celery worker process, indicating potential command or prompt injection exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for shell spawning by Celery workers.
      owner: Detection Engineering
      due: 48h
      evidence: Rule targets high-risk post-exploitation behavior.
  hunt_leads:
    - lead: Search for shell process creation events where the parent process includes 'celery' in the command line.
      technique_id: T1059.004
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source document identifies this as a potential post-exploitation indicator.
  mitigation_plan:
    - priority: short_term
      action: Audit Python Celery task functions for 'os.system' or 'shell=True' usage.
      owner: IT Operations
      addresses: General vulnerability patterns
      evidence: Source identifies these as common entry points for RCE.
---

This threat brief addresses the detection of unauthorized shell execution originating from Celery worker processes, a common pattern observed in recent AI-agent prompt injection attacks. When Celery - a popular distributed task queue for Python - is utilized to power LLM-based agents, malicious input passed as tasks can trigger the evaluation of raw strings in a shell context. This vulnerability typically arises when developers utilize insecure methods like `os.system` or `shell=True` in subprocess calls while processing untrusted LLM outputs. This activity is critical to monitor as it represents a post-exploitation phase where an attacker upgrades a prompt injection vulnerability into arbitrary code execution on the worker infrastructure, enabling data exfiltration or internal network pivoting.

## Attack Chain

1. Attacker crafts a malicious prompt targeting an LLM-powered agent application.
2. The LLM processes the input and returns a string containing shell metacharacters intended for system execution.
3. The agent backend receives the untrusted output and passes it as an argument to a Celery task.
4. The Celery worker process picks up the task from the message broker (e.g., Redis or RabbitMQ).
5. The Python task function executes the untrusted string via `os.system`, `subprocess.call` with `shell=True`, or similar insecure APIs.
6. A child shell process (e.g., `/bin/bash` or `/bin/sh`) is spawned directly from the Python worker process.
7. The attacker executes arbitrary commands within the spawned shell to maintain persistence or exfiltrate environment variables.

## Impact

Successful exploitation results in full remote code execution on the worker infrastructure. Depending on the environment, this can lead to the exfiltration of sensitive LLM credentials, access to internal APIs, and further movement within the organization's cloud or container environment.

## Recommendation

1. Deploy the provided Sigma rule to identify unauthorized shell spawning from Python-based Celery worker processes.
2. Audit codebases for the use of `shell=True` or `os.system` within task functions, ensuring that task arguments are properly sanitized or passed as command lists to avoid shell interpretation.
3. Implement strict network segmentation and apply the principle of least privilege to the service accounts running the Celery workers.
4. Enable system-level process monitoring (e.g., Auditd or eBPF-based agents) to capture the full command-line arguments of spawned shells.
