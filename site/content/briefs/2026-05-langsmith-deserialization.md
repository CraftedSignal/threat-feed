---
title: LangSmith SDK Untrusted Manifest Deserialization Vulnerability
slug: 2026-05-langsmith-deserialization
description: The LangSmith SDK is vulnerable to untrusted manifest deserialization when pulling public prompts via `pull_prompt`, potentially leading to SSRF, prompt injection, or sensitive data exposure; CVE-2026-45134.
date: "2026-05-13T15:33:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - deserialization
  - ssrf
  - prompt-injection
vendors:
  - LangChain
products:
  - langsmith
  - langchain-classic
  - langchain
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-3644-q5cj-c5c7
  - CVE-2026-45134
rules:
  - title: Detect LangSmith Public Prompt Pull Opt-In
    description: Detects calls to LangSmith SDK's `pull_prompt` or `pullPrompt` methods with the explicit opt-in flag for pulling public prompts, requiring further investigation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect LangSmith Secrets From Env Usage
    description: Detects calls to LangSmith SDK's `pull_prompt` or `pullPrompt` methods with `secrets_from_env=True`, potentially leading to environment variable leakage.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The LangSmith SDK is susceptible to a deserialization vulnerability when fetching public prompts. Specifically, the `pull_prompt` and `pull_prompt_commit` methods in Python, and `pullPrompt` and `pullPromptCommit` in JS/TS, fetch and deserialize prompt manifests from the LangSmith Hub. These manifests can contain serialized LangChain objects and model configurations, effectively making them executable configuration. When pulling a public prompt using the `owner/name` identifier, the SDK doesn't adequately distinguish this from pulling a prompt within the caller's own organization, leading to potential security risks. An attacker publishing a malicious prompt to LangSmith Hub can affect applications that pull that prompt by `owner/name`. This vulnerability affects LangSmith SDK Python versions prior to 0.8.0 and JS/TS versions prior to 0.6.0, as well as langchain-classic < 1.0.7 and langchain < 0.3.30. This allows an attacker to control the behavior of applications using LangSmith.

## Attack Chain

1.  An attacker creates a malicious prompt manifest containing a serialized LangChain object with a modified `base_url` parameter pointing to an attacker-controlled server.
2.  The attacker publishes this malicious prompt to the LangSmith Hub, making it available to the public.
3.  A victim application calls `pull_prompt` (Python) or `pullPrompt` (JS/TS) using the `owner/name` identifier of the attacker's malicious prompt.
4.  The LangSmith SDK fetches the malicious prompt manifest from the LangSmith Hub.
5.  The SDK deserializes the manifest, instantiating the LangChain object with the attacker-supplied `base_url`.
6.  The victim application sends requests to the configured LLM client. Due to the malicious `base_url`, these requests are redirected to the attacker-controlled server.
7.  The attacker's server intercepts the redirected requests, potentially capturing prompt contents, system prompts, retrieved context, model parameters, provider credentials, or other secrets.
8.  The attacker gains unauthorized access to sensitive information or manipulates the application's behavior.

## Impact

Successful exploitation of this vulnerability can lead to severe consequences, including Server-Side Request Forgery (SSRF), where outbound requests are redirected to attacker-controlled servers, potentially exposing sensitive information. Prompt injection and behavior manipulation are also possible by embedding attacker-controlled system messages or prompt templates. The impact extends to applications using vulnerable versions of LangSmith SDK, with the potential for data breaches and unauthorized access. This vulnerability is tracked as CVE-2026-45134 and has a high severity rating.

## Recommendation

-   Upgrade to LangSmith SDK Python version 0.8.0 or later, or JS/TS version 0.6.0 or later, to address the vulnerability.
-   Explicitly acknowledge the trust boundary when pulling public prompts by passing `dangerously_pull_public_prompt=True` (Python) or `dangerouslyPullPublicPrompt: true` (JS/TS) to the `pull_prompt` or `pullPrompt` methods.
-   Review and validate the contents of public prompts before using them, especially those pulled using the `owner/name` identifier.
-   Avoid passing `secrets_from_env=True` (Python) when pulling untrusted prompts to prevent environment variable leakage during deserialization.
-   Treat prompts as executable configuration and apply thorough review and audit practices, especially within your own organization, as compromised API keys can lead to malicious prompt injection.
-   Deploy the Sigma rule "Detect LangSmith Public Prompt Pull Opt-In" to monitor for explicit opt-in to pulling public prompts, indicating a potential risk area.
