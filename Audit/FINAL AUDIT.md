
# 1. Current Assessment Position

The frontend security review has been completed and multiple high-risk
findings have been identified and documented. However, the final overall
risk rating cannot be determined without reviewing the implementation of
the smart contract function:

    saveStamp(string key, string ipfsHash, uint256 deadline, bytes signature)

The security posture of the entire platform now depends on how this
function handles signature verification and replay protection.


# 2. Confirmed Frontend Findings

The following issues are confirmed within the frontend layer:

-   Signature is not verified prior to submission\
-   Deadline is not validated client-side\
-   Chain ID is not cryptographically bound to signature\
-   Contract address is not validated before instantiation\
-   Replay protection is not visible at the frontend layer

These issues increase risk exposure. However, if the smart contract
properly enforces validation, overall risk may be reduced.



# 3. Critical Unknown: Smart Contract Verification Logic

The central question is:

**Does `saveStamp()` properly verify signatures and prevent replay?**

A secure implementation must include:

-   Signature recovery using `ecrecover` or OpenZeppelin ECDSA\
-   `require(signer == msg.sender)` validation\
-   Deadline enforcement (`block.timestamp <= deadline`)\
-   Nonce tracking and increment\
-   Duplicate submission prevention\
-   Chain ID binding within the signed payload

Without confirmation of these controls, final severity cannot be
assigned.



# 4. Scenario-Based Risk Analysis

## Scenario A -- No On-Chain Verification

If the smart contract does not validate signatures:

-   Frontend does not verify\
-   Contract does not verify\
-   Any signature may be submitted\
-   Authorization is effectively bypassed

**Risk Level: Critical**\
**Exploitability: High**

Immediate contract remediation required.


## Scenario B -- Partial Verification (No Nonce)

If the contract verifies signature ownership but does not include nonce
tracking:

-   Signature reuse remains possible\
-   Replay attacks may occur\
-   Duplicate submissions possible

**Risk Level: High**\
**Exploitability: Moderate**

Nonce mechanism and replay protection must be added.


## Scenario C -- Full EIP-712 Implementation

If the contract includes:

-   EIP-712 domain separation\
-   Nonce tracking\
-   Deadline validation\
-   Chain ID binding\
-   Duplicate prevention

Then frontend weaknesses become secondary.

**Risk Level: Medium**\
**Exploitability: Low**

Frontend validation improvements still recommended for defense-in-depth.


# 5. Required Smart Contract Review Items

Please provide:

-   Full implementation of `saveStamp()`\
-   Any helper functions used for signature recovery\
-   Nonce mappings\
-   Duplicate submission mappings\
-   Contract deployment status\
-   Whether it has undergone prior audit


# 6. Code Review Checklist

The following controls must be present for a secure implementation:

-   Signature recovery logic\
-   Signer equality check\
-   Deadline enforcement\
-   Nonce mapping and increment\
-   Duplicate submission mapping\
-   Chain ID binding in message hash\
-   Use of EIP-712 domain separator\
-   Event emission for auditability


# 7. Interim Conclusion

The frontend assessment is complete. However, without reviewing the
smart contract code, the total platform risk remains indeterminate.

The final severity rating will be one of:

-   Critical\
-   High\
-   Medium

Pending smart contract verification.


