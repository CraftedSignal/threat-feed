---
title: OpenAM Pre-Auth RCE via WebAuthn Java Deserialization (CVE-2026-45051)
slug: 2026-07-openam-rce
description: A critical deserialization of untrusted data vulnerability, identified as CVE-2026-45051, in OpenAM's WebAuthn authentication module (openam-auth-webauthn) allows for pre-authentication arbitrary code execution (RCE) on the application server if an attacker can first write controlled data to a user's storage attribute, impacting OpenAM Community Edition through version 16.0.6.
date: "2026-07-03T10:48:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - deserialization
  - RCE
  - OpenAM
  - WebAuthn
  - CVE
  - application-exploitation
vendors:
  - Open Identity Platform
products:
  - OpenAM Community Edition <= 16.0.6
  - openam-auth-webauthn <= 16.0.6
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploitation of Public-Facing Application
    evidence: A deserialization of untrusted data vulnerability... exists in OpenAM's WebAuthn authentication module. ... This may allow an attacker to achieve arbitrary code execution in the context of the application server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This may allow an attacker to achieve arbitrary code execution in the context of the application server.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6c99-87fr-6q7r
---

A critical security vulnerability, CVE-2026-45051, has been disclosed in OpenAM Community Edition affecting versions up to 16.0.6. The flaw resides in the WebAuthn authentication module, specifically within the `openam-auth-webauthn` component, and is categorized as a deserialization of untrusted data (CWE-502). This vulnerability can lead to pre-authentication arbitrary code execution (RCE) in the context of the application server. Exploitation requires a specific pre-condition: an attacker must first be able to write attacker-controlled serialized Java objects to a user's storage attribute that is subsequently read by the WebAuthn module. While this is not the default configuration, it is feasible in deployments where the storage attribute is made user-writable through misconfiguration or other vulnerabilities. The vulnerability has been addressed in OpenAM Community Edition version 16.1.1.

## Attack Chain

1.  **Initial Compromise/Pre-condition fulfillment**: An attacker gains the ability to write arbitrary data to an OpenAM user's storage attribute. This could occur through various means such as abusing delegated administration privileges, gaining write access to the backing LDAP/directory user record, exploiting a separate vulnerability like legacy REST self-registration, or due to an unsafe reconfiguration of the `userAttribute` to an attacker-writable string attribute.
2.  **Payload Injection**: The attacker crafts a malicious serialized Java object (gadget payload) specifically designed for arbitrary code execution on the application server.
3.  **Data Modification**: The attacker leverages their acquired write access to modify a target user's storage attribute within OpenAM, embedding the crafted serialized Java object as the attribute's value.
4.  **Authentication Flow Initiation**: The attacker initiates a WebAuthn authentication flow, either by attempting to authenticate as the modified user or by triggering any process within OpenAM that involves the retrieval and processing of the modified user's WebAuthn-related data.
5.  **Vulnerable Deserialization**: OpenAM's WebAuthn module, while processing the authentication flow, attempts to deserialize the content of the compromised storage attribute, which now contains the attacker's malicious serialized Java object.
6.  **Code Execution**: During the deserialization process, the malicious Java gadget payload embedded within the storage attribute is executed by the underlying Java Virtual Machine on the OpenAM application server, resulting in arbitrary code execution with the privileges of the application server user.

## Impact

If successfully exploited, CVE-2026-45051 grants an attacker arbitrary code execution on the OpenAM application server. This means an attacker could completely compromise the identity management system, gaining control over user accounts, accessing sensitive information, manipulating authentication processes, or establishing persistent access within the targeted organization's network. While the vulnerability requires a pre-condition where a storage attribute becomes user-writable (which is not the default), the product allows administrators to configure this attribute freely without warnings or enforcement, making such misconfigurations feasible in real-world deployments. The impact extends to all data and systems relying on the compromised OpenAM instance for authentication and authorization.

## Recommendation

*   Immediately update OpenAM Community Edition to version 16.1.1 or later to patch CVE-2026-45051.
*   Review OpenAM configurations to ensure that the WebAuthn user storage attribute is not set to an attacker-writable string attribute and is managed only by server-side processes.
*   Scrutinize all administrative access and delegated administration privileges to prevent unauthorized modification of user attributes.
*   Implement rigorous logging and monitoring for attempts to modify user attributes, especially those related to WebAuthn, within OpenAM and its backing directories (e.g., LDAP).
