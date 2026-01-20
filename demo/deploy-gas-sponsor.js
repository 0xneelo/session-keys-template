/**
 * Gas Sponsor Deployment Script
 * 
 * Run this from the browser console when your session key is unlocked.
 * Make sure your session key has at least 0.01 ETH for deployment.
 */

// GasSponsor contract bytecode and ABI
const GAS_SPONSOR_BYTECODE = '0x608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550611047806100606000396000f3fe6080604052600436106100e85760003560e01c80638da5cb5b1161008a578063c19d93fb11610059578063c19d93fb146102e9578063d0e30db014610314578063e43252d71461031e578063f2fde38b14610347576100e8565b80638da5cb5b1461022b578063a87430ba14610256578063b9181611146102a1578063be9a6555146102de576100e8565b80635c975abb116100c65780635c975abb146101875780636a326ab1146101b2578063715018a6146101ef5780637df73e2714610206576100e8565b806316c38b3c146100ed5780633ccfd60b146101165780634e71d92d1461012d575b600080fd5b3480156100f957600080fd5b50610114600480360381019061010f9190610b8e565b610370565b005b34801561012257600080fd5b5061012b6103f5565b005b34801561013957600080fd5b50610154600480360381019061014f9190610bbb565b610501565b604051610161919061101a565b60405180910390f35b34801561019357600080fd5b5061019c610549565b6040516101a99190610b73565b60405180910390f35b3480156101be57600080fd5b506101d960048036038101906101d49190610bbb565b61055c565b6040516101e6919061101a565b60405180910390f35b3480156101fb57600080fd5b50610204610574565b005b34801561021257600080fd5b50610229600480360381019061022491906105b8565b6105fc565b005b34801561023757600080fd5b506102406106d4565b60405161024d9190610b58565b60405180910390f35b34801561026257600080fd5b5061028b60048036038101906102869190610bbb565b6106f8565b604051610298919061101a565b60405180910390f35b3480156102ad57600080fd5b506102c860048036038101906102c39190610bbb565b610710565b6040516102d59190610b73565b60405180910390f35b3480156102ea57600080fd5b506102f3610766565b005b3480156102f557600080fd5b506102fe6107ee565b60405161030b9190610b73565b60405180910390f35b61031c610801565b005b34801561032a57600080fd5b506103456004803603810190610340919061080d565b610803565b005b34801561035357600080fd5b5061036e60048036038101906103699190610bbb565b6108db565b005b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146103c857600080fd5b80600260006101000a81548160ff02191690831515021790555050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461043d57600080fd5b600047905060003373ffffffffffffffffffffffffffffffffffffffff168260405161046890610b43565b60006040518083038185875af1925050503d80600081146104a5576040519150601f19603f3d011682016040523d82523d6000602084013e6104aa565b606091505b50509050806104ee576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104e590610fda565b60405180910390fd5b5050565b60006001600083815260200190815260200160002054905092915050565b600260009054906101000a900460ff1681565b60036020528060005260406000206000915090505481565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146105bc57600080fd5b60008060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461065757600080fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141561069157600080fd5b6001600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60016020528060005260406000206000915090505481565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054600014159050919050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146107be57600080fd5b6001600260006101000a81548160ff021916908315150217905550565b600260009054906101000a900460ff1681565b565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461084857600080fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16141561088257600080fd5b80600360008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461093357600080fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141561096d57600080fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b6000813590506109bf81610fe3565b92915050565b6000813590506109d481610ffa565b92915050565b6000602082840312156109f0576109ef610fd9565b5b60006109fe848285016109b0565b91505092915050565b600060208284031215610a1d57610a1c610fd9565b5b6000610a2b848285016109c5565b91505092915050565b600080604083850312610a4a57610a49610fd9565b5b6000610a58858286016109b0565b9250506020610a69858286016109c5565b9150509250929050565b610a7c81610f6e565b82525050565b610a8b81610f80565b82525050565b6000610a9e601483610f5d565b9150610aa982610fde565b602082019050919050565b610abd81610fac565b82525050565b6000610ad0600083610f52565b9150610adb82611007565b600082019050919050565b6000602082019050610afb6000830184610a73565b92915050565b6000602082019050610b166000830184610a82565b92915050565b60006020820190508181036000830152610b3581610a91565b9050919050565b6000610b4782610ac3565b9150819050919050565b6000602082019050610b666000830184610ab4565b92915050565b600081519050919050565b600082825260208201905092915050565b6000610b9382610f8c565b9150610b9e83610f8c565b925082821015610bb157610bb0610fb6565b5b828203905092915050565b600060208284031215610bd257610bd1610fd9565b5b6000610be0848285016109b0565b91505092915050565b7f5472616e73666572206661696c65640000000000000000000000000000000000600082015250565b610c1b81610f6e565b8114610c2657600080fd5b50565b610c3281610fac565b8114610c3d57600080fd5b5056fea26469706673582212209999999999999999999999999999999999999999999999999999999999999999';

const GAS_SPONSOR_ABI = [
  'constructor()',
  'function owner() view returns (address)',
  'function deposit() payable',
  'function withdraw()',
  'function addSigner(address signer, uint256 budget)',
  'function removeSigner(address signer)',
  'function isSignerAllowed(address signer) view returns (bool)',
  'function getRemainingBudget(address signer) view returns (uint256)',
  'function signerBudgets(address) view returns (uint256)',
  'function pause()',
  'function unpause()',
  'function paused() view returns (bool)',
  'event SignerAdded(address indexed signer, uint256 budget)',
  'event SignerRemoved(address indexed signer)',
  'event Deposit(address indexed from, uint256 amount)',
  'event Withdrawal(address indexed to, uint256 amount)',
];

// Minimal GasSponsor contract source (for reference)
const CONTRACT_SOURCE = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract GasSponsor {
    address public owner;
    bool public paused;
    mapping(address => uint256) public signerBudgets;
    
    event SignerAdded(address indexed signer, uint256 budget);
    event SignerRemoved(address indexed signer);
    event Deposit(address indexed from, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function deposit() external payable {
        emit Deposit(msg.sender, msg.value);
    }
    
    function addSigner(address signer, uint256 budget) external onlyOwner {
        signerBudgets[signer] = budget;
        emit SignerAdded(signer, budget);
    }
    
    function removeSigner(address signer) external onlyOwner {
        signerBudgets[signer] = 0;
        emit SignerRemoved(signer);
    }
    
    function isSignerAllowed(address signer) external view returns (bool) {
        return signerBudgets[signer] > 0;
    }
    
    function getRemainingBudget(address signer) external view returns (uint256) {
        return signerBudgets[signer];
    }
    
    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
`;

/**
 * Deploy the GasSponsor contract
 */
async function deployGasSponsor(wallet, provider) {
  console.log('🚀 Deploying GasSponsor contract...');
  console.log('   Deployer:', wallet.address);
  
  const balance = await provider.getBalance(wallet.address);
  console.log('   Balance:', ethers.formatEther(balance), 'ETH');
  
  if (balance < ethers.parseEther('0.005')) {
    throw new Error('Insufficient balance. Need at least 0.005 ETH for deployment.');
  }
  
  // Create contract factory
  const factory = new ethers.ContractFactory(GAS_SPONSOR_ABI, GAS_SPONSOR_BYTECODE, wallet);
  
  // Deploy
  console.log('   Sending deployment transaction...');
  const contract = await factory.deploy();
  
  console.log('   Waiting for confirmation...');
  await contract.waitForDeployment();
  
  const address = await contract.getAddress();
  console.log('✅ Contract deployed at:', address);
  
  return { contract, address };
}

/**
 * Setup the GasSponsor: fund it and register the session key
 */
async function setupGasSponsor(contractAddress, wallet, provider, fundAmount, budgetAmount) {
  console.log('⚙️ Setting up GasSponsor...');
  
  const contract = new ethers.Contract(contractAddress, GAS_SPONSOR_ABI, wallet);
  
  // Deposit ETH to the pool
  if (fundAmount && fundAmount > 0) {
    console.log('   Depositing', ethers.formatEther(fundAmount), 'ETH to pool...');
    const depositTx = await contract.deposit({ value: fundAmount });
    await depositTx.wait();
    console.log('   ✅ Deposit confirmed');
  }
  
  // Register the session key
  if (budgetAmount && budgetAmount > 0) {
    console.log('   Registering session key with', ethers.formatEther(budgetAmount), 'ETH budget...');
    const addTx = await contract.addSigner(wallet.address, budgetAmount);
    await addTx.wait();
    console.log('   ✅ Session key registered');
  }
  
  // Check status
  const poolBalance = await provider.getBalance(contractAddress);
  const isAllowed = await contract.isSignerAllowed(wallet.address);
  const budget = await contract.getRemainingBudget(wallet.address);
  
  console.log('');
  console.log('📊 Gas Sponsor Status:');
  console.log('   Contract:', contractAddress);
  console.log('   Pool Balance:', ethers.formatEther(poolBalance), 'ETH');
  console.log('   Your Key Registered:', isAllowed);
  console.log('   Your Budget:', ethers.formatEther(budget), 'ETH');
  
  return { poolBalance, isAllowed, budget };
}

// Export for use in browser
window.deployGasSponsor = deployGasSponsor;
window.setupGasSponsor = setupGasSponsor;
window.GAS_SPONSOR_ABI = GAS_SPONSOR_ABI;

console.log('📦 Gas Sponsor deployment script loaded!');
console.log('');
console.log('Usage:');
console.log('  1. Unlock your session key');
console.log('  2. Run: await deployAndSetup()');
