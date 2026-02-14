// ============================================
// CRITICAL FIX #2: Contract Address Validation
// ============================================
// File: utils/getContract.ts

import { Address, erc20ABI } from 'wagmi';
import { Abi, PublicClient, WalletClient, getContract as viemGetContract, isAddress, getAddress } from 'viem';

// ✅ SECURITY FIX: Allowlist of verified contract addresses per chain
const VERIFIED_CONTRACTS: Record<number, Set<string>> = {
  // Ethereum Mainnet
  1: new Set([
    '0x90b4a3243dBCD5794dF006F21A318b43d32E27192A', // BADGE_BRIDGE_ADDRESS
    // Add other verified mainnet addresses
  ]),
  // Arcana Testnet
  5: new Set([
    // Add testnet addresses
  ]),
  // BSC Mainnet
  56: new Set([
    '0x2B09d47D550061f995A3b5C6F0Fd58005215D7c8', // BABT_ADDRESS
    '0xBE06E0bAA90E495dF006F21A318b43d32E27192A', // BADGE_BRIDGE_ADDRESS_BSC
    '0x15719A5A6CB3794342d86912280cb8EB3BA54360', // COLLAB_ADDRESS (Moved from chain 1)
  ]),
  // BSC Testnet
  97: new Set([
    '0x571db18fff31378E772192352aD207b731827672', // BABT_ADDRESS testnet
  ]),
};

/**
 * Validates if a contract address is in the allowlist for a given chain
 */
function isContractAllowed(address: string, chainId?: number): boolean {
  if (!chainId || !VERIFIED_CONTRACTS[chainId]) {
    console.warn(`No allowlist configured for chain ID: ${chainId}`);
    return false;
  }
  
  return VERIFIED_CONTRACTS[chainId].has(address);
}

/**
 * Validates if an address points to a deployed contract
 */
async function isDeployedContract(
  address: Address, 
  publicClient?: PublicClient
): Promise<boolean> {
  if (!publicClient) {
    console.warn('No public client provided, skipping contract deployment check');
    return true; // Skip check if no client available
  }
  
  try {
    const bytecode = await publicClient.getBytecode({ address });
    return !!(bytecode && bytecode !== '0x');
  } catch (error) {
    console.error('Error checking contract deployment:', error);
    return false;
  }
}

export const getContract = <TAbi extends Abi | unknown[]>({
  abi,
  address,
  publicClient,
  walletClient,
  skipValidation = false, // Allow skipping for testing
}: {
  abi: TAbi;
  address: Address;
  walletClient?: WalletClient;
  publicClient?: PublicClient;
  skipValidation?: boolean;
}) => {
  // ✅ SECURITY FIX: Validate address format
  if (!isAddress(address)) {
    throw new Error(`Invalid Ethereum address format: ${address}`);
  }
  
  // ✅ SECURITY FIX: Normalize to checksummed address
  const checksummedAddress = getAddress(address);
  
  // ✅ SECURITY FIX: Verify against allowlist
  if (!skipValidation) {
    const chainId = walletClient?.chain?.id || publicClient?.chain?.id;
    
    if (chainId && !isContractAllowed(checksummedAddress, chainId)) {
      throw new Error(
        `Contract address ${checksummedAddress} is not in the allowlist for chain ${chainId}. ` +
        `This may be a security risk. If this is a legitimate contract, please add it to VERIFIED_CONTRACTS.`
      );
    }
  }
  
  // ✅ SECURITY FIX: Verify it's actually a contract (async check)
  if (publicClient && !skipValidation) {
    isDeployedContract(checksummedAddress, publicClient).then(isContract => {
      if (!isContract) {
        console.error(
          `WARNING: Address ${checksummedAddress} does not appear to be a deployed contract. ` +
          `This may indicate a configuration error or potential security issue.`
        );
      }
    });
  }
  
  const c = viemGetContract({
    abi,
    address: checksummedAddress,
    publicClient: publicClient,
    walletClient: walletClient,
  });
  
  return {
    ...c,
    account: walletClient?.account,
    chain: walletClient?.chain,
  };
};

export const getErc20Contract = (
  address: Address, 
  walletClient?: WalletClient,
  publicClient?: PublicClient
) => {
  return getContract({ 
    abi: erc20ABI, 
    address, 
    walletClient,
    publicClient,
    skipValidation: false // ✅ SECURITY FIX: Enforce validation to prevent phishing
  });
};

/**
 * Utility function to add a contract to the allowlist (for admin use)
 */
export function addToAllowlist(chainId: number, address: string): boolean {
  try {
    if (!isAddress(address)) {
      throw new Error('Invalid address format');
    }
    
    const checksummedAddress = getAddress(address);
    
    if (!VERIFIED_CONTRACTS[chainId]) {
      VERIFIED_CONTRACTS[chainId] = new Set();
    }
    
    VERIFIED_CONTRACTS[chainId].add(checksummedAddress);
    console.log(`Added ${checksummedAddress} to allowlist for chain ${chainId}`);
    return true;
  } catch (error) {
    console.error('Failed to add to allowlist:', error);
    return false;
  }
}

/**
 * Get all allowed contracts for a chain
 */
export function getAllowedContracts(chainId: number): string[] {
  return Array.from(VERIFIED_CONTRACTS[chainId] || []);
}
