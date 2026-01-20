/**
 * Legacy Symmio MultiAccount Integration
 * 
 * @deprecated Use InstantLayerClient for new integrations
 * This module is kept for backward compatibility with older MultiAccount deployments
 */

import { ethers } from 'ethers';
import type { NetworkConfig } from './types';

/**
 * @deprecated Use INSTANT_LAYER_ABI from './instant-layer' instead
 */
export const MULTI_ACCOUNT_ABI = [
  'function delegateAccesses(address subAccount, address target, bytes4[] selectors, bool enable) external',
  'function proposeToRevokeAccesses(address subAccount, address target, bytes4[] selectors) external',
  'function revokeAccesses(address subAccount, address target, bytes4[] selectors) external',
  'function getDelegatedAccesses(address subAccount, address target) external view returns (bytes4[])',
  'function isAccessDelegated(address subAccount, address target, bytes4 selector) external view returns (bool)',
  'function revokeCooldown() external view returns (uint256)',
];

/**
 * @deprecated Use InstantLayerClient instead
 */
export class SymmioClient {
  private provider: ethers.Provider;
  private contract: ethers.Contract;
  private chainId: number;

  constructor(
    providerOrSigner: ethers.Provider | ethers.Signer,
    multiAccountAddress: string,
    chainId: number
  ) {
    if ('provider' in providerOrSigner && providerOrSigner.provider) {
      this.provider = providerOrSigner.provider;
    } else {
      this.provider = providerOrSigner as ethers.Provider;
    }
    
    this.chainId = chainId;
    this.contract = new ethers.Contract(
      multiAccountAddress,
      MULTI_ACCOUNT_ABI,
      providerOrSigner
    );
  }

  static fromNetwork(chainId: number): SymmioClient {
    throw new Error('Use InstantLayerClient.fromNetwork() instead');
  }

  async delegateAccesses(
    signer: ethers.Signer,
    subAccount: string,
    target: string,
    selectors: string[],
    enable: boolean
  ): Promise<ethers.TransactionReceipt> {
    const contract = this.contract.connect(signer);
    const tx = await contract.delegateAccesses(subAccount, target, selectors, enable);
    return tx.wait();
  }
}
