# Executive Overview

The system currently presents critical security risks depending on how
the smart contract handles signature verification.

The most important factor:

-   If the smart contract does NOT verify signatures → Risk is CRITICAL.
-   If the smart contract properly verifies signatures (EIP-712 +
    nonce + deadline) → Risk reduces significantly.

At present, the frontend assumes trust in signatures without enforcing
full validation guarantees.



# Key Risk Areas

## 1. Signature Handling

The frontend checks whether a signature exists, but does not guarantee:

-   The signature belongs to the connected wallet
-   The signature is bound to a specific contract
-   The signature is bound to a specific chain
-   The signature has not been replayed

Without on-chain validation, this enables signature spoofing and replay
attacks.

Risk Level: **Critical if contract lacks verification**


## 2. Replay Attack Risk

There is no visible nonce mechanism in the current design.

Without nonce tracking:

-   A valid signature can be reused
-   Transactions can be replayed
-   Duplicate submissions may be accepted

Replay protection must be implemented at the smart contract level.



## 3. Cross-Chain Replay Risk

If chain ID is not included in the signed message:

-   A signature generated on one chain may be replayed on another
-   Cross-network duplication becomes possible

Binding signatures to `block.chainid` prevents this issue.



## 4. Contract Address Binding

If the signed message does not include the verifying contract address:

-   A signature intended for one contract may be reused on another
-   Malicious contracts may accept otherwise valid signatures

Using EIP-712 domain separation prevents this vulnerability.



# Smart Contract Requirements (Mandatory)

A secure implementation MUST include:

-   EIP-712 domain separator
-   Nonce per user
-   Deadline validation (`block.timestamp <= deadline`)
-   Signature recovery (`ecrecover`)
-   Signer validation (`signer == msg.sender`)
-   Replay prevention (nonce increment)
-   Duplicate prevention mapping
-   Chain ID binding

If any of the above are missing, risk remains high.



# Frontend Responsibilities

Even if the contract verifies signatures, the frontend should still:

-   Validate chain ID before submission
-   Validate deadline before submission
-   Verify signature before sending transaction
-   Use a contract address allowlist
-   Provide clear error feedback
-   Implement rate limiting

Frontend validation improves UX and reduces accidental misuse but should
never replace on-chain verification.



# Risk Matrix

 
  
  Signature Spoofing         Critical      Prevented
  Replay Attack              High          Prevented
  Cross-Chain Replay         High          Prevented
  Duplicate Submission       High          Prevented
  Wrong Contract Execution   High          Prevented



# Professional Assessment

If the smart contract does NOT perform signature verification:

Risk Rating: **Critical (CVSS \~9.2)**\
Impact: Full authorization bypass possible.

If the smart contract DOES perform full EIP-712 verification with nonce
and deadline:

Risk Rating: **Medium**\
Impact: Limited to frontend validation weaknesses.



# Immediate Action Items

1.  Review the `saveStamp()` function in the smart contract.
2.  Confirm whether `ecrecover` or EIP-712 verification is implemented.
3.  Confirm nonce tracking and increment logic exists.
4.  Confirm deadline validation exists.
5.  Confirm chain ID binding exists.

If any of these checks fail, contract upgrade is required immediately.



# Final Conclusion

Security severity depends primarily on smart contract validation.

Frontend improvements reduce risk but do not eliminate it.

In Web3 systems, only on-chain verification guarantees trustlessness.

A complete code review of the smart contract is required before final
risk classification.
