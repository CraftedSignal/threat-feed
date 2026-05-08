---
title: LangChain Unsafe Deserialization Vulnerability
slug: 2024-01-04-langchain-deserialization
description: LangChain is vulnerable to unsafe deserialization of attacker-controlled objects through overly broad `load()` allowlists, potentially leading to persistent chat-history poisoning, prompt injection, credential disclosure, or server-side requests.
date: "2024-01-04T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - langchain
  - deserialization
  - vulnerability
vendors:
  - LangChain
products:
  - langchain-core
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-pjwx-r37v-7724
rules:
  - title: Detect LangChain Deserialization via Process Creation
    description: Detects process creation events potentially related to LangChain deserialization attacks by monitoring for processes that interact with serialized LangChain objects.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect LangChain Object Instantiation via Command Line
    description: Detects LangChain object instantiation patterns in command-line arguments, which might be indicative of deserialization attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

LangChain contains older runtime code paths that deserialize run inputs, run outputs, or other application-controlled payloads using overly broad object allowlists. These paths may call `load()` with `allowed_objects='all'`, allowing any trusted LangChain-serializable object to be revived with attacker-supplied constructor arguments. The vulnerability exists when applications accept untrusted structured input (e.g., JSON), fail to validate it before invoking LangChain, preserve attacker-controlled nested dictionaries/lists in LangChain run data, and use affected API paths like `RunnableWithMessageHistory`, `astream_log()`, or `astream_events(version="v1")`. A related secret-marker validation bypass in the serialization layer also contributes to the issue. This vulnerability affects `langchain-core` versions >= 1.0.0 and <= 1.3.2, as well as versions <= 0.3.84.

## Attack Chain

1.  The attacker crafts a malicious JSON payload containing a LangChain serialized constructor dictionary, e.g., for an `AIMessage` object with attacker-controlled content.
2.  The attacker submits the crafted JSON payload to a vulnerable application endpoint that accepts structured input.
3.  The application, without proper validation or canonicalization, processes the untrusted input and passes it to LangChain.
4.  The attacker-controlled nested dictionaries or lists are preserved in LangChain run inputs or outputs.
5.  The application invokes an affected API path, such as `RunnableWithMessageHistory`, `astream_log()`, or `astream_events(version="v1")`, which uses `load()` with a broad object allowlist.
6.  LangChain deserializes the malicious payload, instantiating the attacker-specified object (e.g., `AIMessage`) with attacker-controlled constructor arguments.
7.  The instantiated object's content is then used in subsequent application logic, potentially leading to prompt injection, chat history poisoning, or other malicious outcomes.
8.  If the instantiated object reads environment credentials, creates clients, or contacts attacker-controlled endpoints during initialization, credential disclosure or server-side request forgery may occur.

## Impact

Successful exploitation allows an attacker to inject LangChain serialized constructor payloads, potentially leading to persistent chat-history poisoning (if revived messages are stored by `RunnableWithMessageHistory`), prompt injection, or the instantiation of unexpected LangChain objects with attacker-controlled arguments. This may lead to credential disclosure, server-side request forgery, or further exploitation within the application. The number of affected applications is currently unknown, but the impact could be significant given the widespread use of LangChain.

## Recommendation

*   Migrate away from the deprecated APIs: `RunnableWithMessageHistory`, `astream_log()`, and `astream_events(version="v1")` to the newer, recommended streaming and memory patterns.
*   Update LangChain to a patched version that tightens deserialization behavior.
*   Do not pass user-controlled data to `load()` or `loads()`. Only use these functions with trusted LangChain manifests or serialized objects from trusted storage.
*   Use a narrow `allowed_objects` value appropriate for the specific trusted manifest being loaded, instead of relying on broad defaults or `allowed_objects="all"`.
*   Deploy the Sigma rule to detect suspicious process creation involving deserialization of LangChain objects.
