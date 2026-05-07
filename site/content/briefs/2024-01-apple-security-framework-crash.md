---
title: Apple Security Framework Crash due to Uninitialized Pointer
slug: 2024-01-apple-security-framework-crash
description: A crash was identified in Apple's Security framework due to an uninitialized pointer in the SecError function, leading to the dereference of an invalid memory address.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - security-framework
  - crash
  - uninitialized-pointer
  - macos
vendors:
  - Apple
products:
  - Security Framework
affected_os:
  - macos
references:
  - https://objective-see.org/blog/blog_0x2D.html
rules:
  - title: Detect Security Framework Crashes due to Uninitialized Pointer
    description: Detects crashes in Apple's Security framework due to dereferencing an uninitialized CFErrorRef pointer in SecError.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - macos
  - title: Detect Security Framework Crashes
    description: Detects crashes in Apple's Security framework based on exception type and module
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

A vulnerability exists within Apple's Security framework that can lead to application crashes. The issue stems from an uninitialized pointer, `CFErrorRef *error`, within the `SecCDSAKeyCopyPublicKey` function. This function is part of the Swift framework responsible for handling cryptographic operations, specifically dealing with certificate authorities and key generation. When an error occurs during the execution of `SecCDSAKeyCopyPublicKey`, a catch block is invoked. This catch block then calls the `SecError` function with the uninitialized `CFErrorRef` pointer. The `SecError` function attempts to dereference this uninitialized pointer, resulting in an attempt to access an invalid memory address and triggering an `EXC_BAD_ACCESS` exception, ultimately crashing the application. This vulnerability was discovered during the development of a security utility named "Do Not Disturb (DND)".

## Attack Chain

1.  Application invokes the `SecCDSAKeyCopyPublicKey` function within Apple's Security framework.
2.  An error occurs during the execution of `SecCDSAKeyCopyPublicKey`, triggering a `MacOSError`, `CommonError`, `std::bad_alloc`, or other exception.
3.  The `BEGIN_SECKEYAPI` and `END_SECKEYAPI` macros wrap the function in a try/catch block.
4.  The catch block is executed due to the error.
5.  Within the catch block, the `SecError` function is called.
6.  The `SecError` function receives an uninitialized `CFErrorRef *error` pointer because it was declared but not assigned a valid memory address within `SecCDSAKeyCopyPublicKey`.
7.  `SecError` attempts to dereference the invalid `CFErrorRef *error` pointer.
8.  This dereference operation results in an `EXC_BAD_ACCESS` exception, causing the application to crash.

## Impact

The vulnerability leads to application crashes on macOS. While the source does not specify the number of victims or sectors targeted, any application utilizing the vulnerable `SecCDSAKeyCopyPublicKey` function within Apple's Security framework is susceptible to this crash. A successful exploitation of this vulnerability results in a denial-of-service condition for the affected application.

## Recommendation

*   Monitor for crash reports indicating `EXC_BAD_ACCESS` exceptions originating within the `SecError` function of Apple's Security framework, specifically when called from `SecCDSAKeyCopyPublicKey`.
*   Examine the logs for exceptions or errors occurring within cryptographic functions that may trigger the described crash within `SecCDSAKeyCopyPublicKey`.
*   Deploy the Sigma rule "Detect Security Framework Crashes due to Uninitialized Pointer" to identify potential exploitation attempts.
*   Implement runtime monitoring to detect attempts to call `SecError` with invalid `CFErrorRef` pointers.
