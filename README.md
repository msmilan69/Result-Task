# Airdrop platform

This is a blockchain-based airdrop platform that integrates with smart contracts, wallet authentication, and user management systems.

## Your Task

Review this codebase and identify potential security vulnerabilities related to:

1. **Smart Contract Security**
   - Verify signature validation in `components/qatar/Prediction.tsx` - check if signatures are properly verified against the signer's address
   - Ensure contract address validation in `utils/getContract.ts`

2. **Authentication & Authorization**
   - Check token revocation and expiration handling

3. **Input Validation**
   - Complete profile update endpoints for XSS/injection
   - Complete password reset flow for missing validation checks

## Assessment Details

- **Duration**: 4 hours from the time you receive invitation from GitHub
- **Format**: Take-home project
- **Submission**: Upon completion, make a public repository, submit your deliverables with your name on GitHub and contact **gauge@crewspacex.com**

## Tech Stack

**Frontend:**
- Next.js 13, React 18, TypeScript
- wagmi, viem (Web3 interactions)
- Tailwind CSS, Framer Motion
- Recoil (state management)

**Backend:**
- Node.js, Express.js
- MongoDB (Mongoose)
- JWT authentication
- Cloudinary (image uploads)

**Blockchain:**
- Ethereum/EVM chains
- SIWE (Sign-In with Ethereum)
- Smart contract integration

## Key Features

1. **User Registration & Authentication**
   - Traditional email/password registration
   - Sign-In with Ethereum (SIWE) for wallet-based authentication
   - JWT token-based session management

2. **Smart Contract Interactions**
   - Airdrop claim functionality
   - Collaboration stamp system
   - Prediction submissions with signature verification

3. **Developer & Gamer Verification**
   - Steam account verification for developers
   - Email verification for gamers
   - Signature-based ownership proof


## Getting Started

- Node.js (v16 or higher)
- npm (v7 or higher for workspace support)

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build
```

## Environment Setup

Create a `.env` file in the backend directory with:
- `JWT_SECRET`: Secret key for JWT tokens
- `JWT_EXPIRE`: Token expiration time
- `COOKIE_EXPIRES_TIME`: Cookie expiration in days
- Database connection strings
- Cloudinary credentials for image uploads
---

**Good luck with your assessment!**
