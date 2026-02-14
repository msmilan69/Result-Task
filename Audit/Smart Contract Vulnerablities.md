
# Overview

Signature-based authorization is powerful --- but dangerous if
implemented incorrectly.

Below are the most common vulnerability patterns found in contracts that
use off-chain signatures.

For each pattern, we explain:

-   What the mistake is
-   Why it is dangerous
-   What attack it enables
-   How to fix it properly



# Pattern 1 -- Signature Parameter Ignored

## The Mistake

A contract accepts a `signature` parameter but never verifies it.

### Why This Is Critical

If the contract never validates the signature:

-   Anyone can submit any signature
-   Authorization is completely bypassed
-   The signature becomes meaningless

Risk Level: **Critical**

## Secure Approach

Always:

-   Construct a message hash
-   Recover the signer using `ecrecover` or OpenZeppelin ECDSA
-   Ensure `signer == msg.sender`



# Pattern 2 -- Missing Deadline Check

## The Mistake

The contract accepts a `deadline` but does not check it.

### Why This Is Dangerous

A signature meant to expire in 30 days could still be used years later.

This enables long-term replay and delayed abuse.

Risk Level: **High**

## Secure Approach

Always include:

require(block.timestamp \<= deadline, "Signature expired");



# Pattern 3 -- No Nonce / Replay Protection

## The Mistake

The contract verifies a signature but does not include a nonce.

### Why This Is Dangerous

If the signed message does not include a nonce:

-   The same signature can be reused
-   The exact same transaction can be replayed
-   Duplicate submissions may occur

Risk Level: **High**

## Secure Approach

-   Include `nonce[msg.sender]` in the signed message
-   Increment nonce after successful submission

This ensures every signature can only be used once.



# Pattern 4 -- Missing Chain Binding

## The Mistake

The signed message does not include `block.chainid`.

### Why This Is Dangerous

A valid signature from one chain can be replayed on another chain.

Example:

-   User signs on Ethereum (chainId 1)
-   Attacker replays on Arbitrum (chainId 42161)
-   Signature still valid if chainId not included

Risk Level: **High**

## Secure Approach

Include `block.chainid` in the signed message or use EIP-712 domain
separation.



# Pattern 5 -- No Duplicate Prevention

## The Mistake

The contract allows multiple submissions for the same logical action.

### Why This Is Problematic

Even with valid signatures:

-   Users may overwrite previous submissions
-   Duplicate entries may be recorded
-   Data integrity becomes unclear

Risk Level:  **Medium**

## Secure Approach

Track submission state:

mapping(address =\> mapping(string =\> bool)) public hasSubmitted;

Check before accepting:

require(!hasSubmitted\[msg.sender\]\[key\], "Already submitted");



# Security Maturity Levels

## Critical Risk (Unsafe)

If your contract only stores data without verifying signatures, it is
critically vulnerable.

## Partially Secure

If you verify signatures but lack nonce, chain binding, or duplicate
checks, risk remains moderate.

## Secure Implementation

A secure contract must include:

-   Signature recovery
-   Deadline enforcement
-   Nonce tracking
-   Chain ID binding
-   Duplicate prevention
-   EIP-712 domain separation


# Testing Checklist

A secure contract should fail when:

-   Signature is expired
-   Signature is reused
-   Nonce is incorrect
-   Chain ID does not match
-   Duplicate submission attempted
-   Signature signer does not match msg.sender

If all of these revert correctly, your signature system is robust.


# Final Advice

Signature-based authorization is only secure when:

-   The signed message is unique
-   The message cannot be replayed
-   The message is bound to the contract
-   The message is bound to the chain
-   The message has an expiration
-   The contract verifies everything on-chain

Never rely on frontend validation alone.

On-chain verification is mandatory for trustless security.
