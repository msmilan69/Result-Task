
# Overview

This document summarizes the key security weaknesses identified in the
reviewed frontend logic.\
The goal of this version is clarity --- explaining not just *what* is
wrong, but *why it matters* and *how it can be exploited* in real-world
conditions.



# Critical Issues

## 1. Missing Signature Verification

The application checks whether a signature exists but does not verify
that it was signed by the connected wallet.

### Why This Is Dangerous

A signature must always be cryptographically validated.\
Without verification:

-   Anyone can reuse another user's signature
-   Predictions may be submitted on behalf of someone else
-   Authorization integrity is compromised

### Real Risk

If an attacker obtains a valid signature from User A, they can submit it
while connected as User B.\
If the smart contract does not perform internal verification, this
becomes a full authorization bypass.

### Recommendation

Before submission:

1.  Recreate the original signed message.
2.  Recover the signer address from the signature.
3.  Compare it with the connected wallet address.
4.  Reject the transaction if they do not match.

Severity: **Critical**


## 2. No Contract Address Validation

The `getContract` utility accepts an address without validating its
format or legitimacy.

### Why This Is Critical

Interacting with the wrong contract address can lead to:

-   Lost funds
-   Interaction with malicious contracts
-   Silent transaction failures
-   Configuration tampering attacks

### Real Risk Example

If a contract address is mistyped or replaced by an attacker in
configuration, the frontend will still connect to it without warning.

### Recommendation

Before instantiating a contract:

-   Validate address format
-   Reject the zero address
-   Normalize to checksum format
-   Optionally verify bytecode exists at the address

Severity: **Critical**



# High Severity Issues

## 3. Deadline Not Validated

The deadline parameter is only checked for existence --- not
correctness.

### Risk

-   Expired timestamps may still be submitted
-   Extremely distant future deadlines may break logic
-   Replay risk increases if contracts rely on weak validation

### Recommendation

Validate that:

-   Deadline is in the future
-   Deadline is within a reasonable time window

Severity: **High**



## 4. IPFS Hash Not Validated

The IPFS hash is submitted without format validation.

### Risk

-   Malformed CID values
-   Contract reverts
-   Storing corrupted data references

### Recommendation

Validate CID format before submission.

Severity: **High**



## 5. Type Safety Disabled with @ts-ignore

TypeScript safety checks are intentionally suppressed.

### Why This Matters

TypeScript prevents:

-   Incorrect argument ordering
-   Undefined values
-   ABI mismatches

Suppressing it removes an important defensive layer.

Severity: **High**



## 6. No Chain ID Verification

The code checks that a chain exists, but not that it is the correct one.

### Risk

Users may unknowingly submit transactions on the wrong network.

Severity: **High**



# Medium Severity Issues

## 7. Generic Error Handling

Errors are handled generically without distinguishing between:

-   Signature failures
-   Network errors
-   Contract reverts

This reduces observability and debugging effectiveness.

Severity: **Medium**


## 8. No Rate Limiting on Submissions

Users can rapidly click submit, triggering multiple transaction
attempts.

### Risk

-   Gas waste
-   Duplicate submissions
-   Increased RPC load

Severity: **Medium**



# Remediation Priority

## Immediate

-   Signature verification
-   Address validation
-   Deadline validation
-   Chain ID enforcement

## Short-Term

-   IPFS validation
-   Remove @ts-ignore
-   Improve error handling

## Follow-Up

-   Add submission cooldown
-   Expand security testing



# Final Security Note

Most issues stem from trusting frontend state without verification.\
In Web3 systems, all user-controlled inputs must be treated as
adversarial.

Implementing these changes will significantly reduce the attack surface
and strengthen transaction integrity before production deployment.
