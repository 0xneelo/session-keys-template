// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title GasSponsor
 * @notice Sponsors gas for session key transactions via meta-transactions
 * @dev Session keys sign messages, relayers submit them, contract pays gas
 * 
 * Flow:
 * 1. Session key signs a meta-transaction off-chain
 * 2. Anyone (relayer) submits the signed tx to this contract
 * 3. Contract verifies signature and executes the call
 * 4. Contract pays gas from its ETH balance
 */
contract GasSponsor is Ownable, ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /* ═══════════════════════════════════════════════════════════════════════════
     * STATE
     * ═══════════════════════════════════════════════════════════════════════════ */

    /// @notice Nonce for each signer to prevent replay attacks
    mapping(address => uint256) public nonces;

    /// @notice Whitelist of allowed signers (session keys)
    mapping(address => bool) public allowedSigners;

    /// @notice Maximum gas limit per transaction
    uint256 public maxGasLimit = 500000;

    /// @notice Daily gas budget per signer (in wei)
    uint256 public dailyGasBudget = 0.01 ether;

    /// @notice Gas used today by each signer
    mapping(address => uint256) public dailyGasUsed;

    /// @notice Last reset timestamp for each signer
    mapping(address => uint256) public lastResetTimestamp;

    /* ═══════════════════════════════════════════════════════════════════════════
     * EVENTS
     * ═══════════════════════════════════════════════════════════════════════════ */

    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event MetaTransactionExecuted(
        address indexed signer,
        address indexed target,
        uint256 value,
        uint256 gasUsed,
        bool success
    );
    event Deposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);

    /* ═══════════════════════════════════════════════════════════════════════════
     * ERRORS
     * ═══════════════════════════════════════════════════════════════════════════ */

    error InvalidSignature();
    error SignerNotAllowed(address signer);
    error InvalidNonce(uint256 expected, uint256 provided);
    error DeadlineExpired(uint256 deadline);
    error GasLimitExceeded(uint256 requested, uint256 max);
    error DailyBudgetExceeded(uint256 used, uint256 budget);
    error InsufficientBalance(uint256 required, uint256 available);
    error CallFailed(bytes returnData);

    /* ═══════════════════════════════════════════════════════════════════════════
     * CONSTRUCTOR
     * ═══════════════════════════════════════════════════════════════════════════ */

    constructor() Ownable(msg.sender) {}

    /* ═══════════════════════════════════════════════════════════════════════════
     * ADMIN FUNCTIONS
     * ═══════════════════════════════════════════════════════════════════════════ */

    /**
     * @notice Add a session key as an allowed signer
     * @param signer The session key address
     */
    function addSigner(address signer) external onlyOwner {
        allowedSigners[signer] = true;
        emit SignerAdded(signer);
    }

    /**
     * @notice Remove a session key from allowed signers
     * @param signer The session key address
     */
    function removeSigner(address signer) external onlyOwner {
        allowedSigners[signer] = false;
        emit SignerRemoved(signer);
    }

    /**
     * @notice Batch add multiple signers
     * @param signers Array of session key addresses
     */
    function addSigners(address[] calldata signers) external onlyOwner {
        for (uint256 i = 0; i < signers.length; i++) {
            allowedSigners[signers[i]] = true;
            emit SignerAdded(signers[i]);
        }
    }

    /**
     * @notice Update gas limits and budgets
     * @param _maxGasLimit Maximum gas per transaction
     * @param _dailyGasBudget Daily gas budget per signer
     */
    function setLimits(uint256 _maxGasLimit, uint256 _dailyGasBudget) external onlyOwner {
        maxGasLimit = _maxGasLimit;
        dailyGasBudget = _dailyGasBudget;
    }

    /**
     * @notice Withdraw ETH from contract
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function withdraw(address payable to, uint256 amount) external onlyOwner {
        if (amount > address(this).balance) {
            revert InsufficientBalance(amount, address(this).balance);
        }
        to.transfer(amount);
        emit Withdrawn(to, amount);
    }

    /* ═══════════════════════════════════════════════════════════════════════════
     * META-TRANSACTION EXECUTION
     * ═══════════════════════════════════════════════════════════════════════════ */

    /**
     * @notice Execute a meta-transaction signed by a session key
     * @param signer The session key that signed the transaction
     * @param target The contract to call
     * @param value ETH value to send (from contract balance)
     * @param data Calldata for the target
     * @param deadline Timestamp after which the tx expires
     * @param nonce Replay protection nonce
     * @param signature EIP-191 signature from the signer
     */
    function executeMetaTransaction(
        address signer,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant returns (bytes memory) {
        uint256 gasStart = gasleft();

        // Verify signer is allowed
        if (!allowedSigners[signer]) {
            revert SignerNotAllowed(signer);
        }

        // Verify deadline
        if (block.timestamp > deadline) {
            revert DeadlineExpired(deadline);
        }

        // Verify nonce
        if (nonce != nonces[signer]) {
            revert InvalidNonce(nonces[signer], nonce);
        }

        // Verify signature
        bytes32 messageHash = getMessageHash(signer, target, value, data, deadline, nonce);
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        address recovered = ethSignedHash.recover(signature);
        
        if (recovered != signer) {
            revert InvalidSignature();
        }

        // Increment nonce
        nonces[signer]++;

        // Check and update daily budget
        _checkAndUpdateBudget(signer, gasStart);

        // Check contract balance
        if (value > address(this).balance) {
            revert InsufficientBalance(value, address(this).balance);
        }

        // Execute the call
        (bool success, bytes memory returnData) = target.call{value: value}(data);

        uint256 gasUsed = gasStart - gasleft();
        emit MetaTransactionExecuted(signer, target, value, gasUsed, success);

        if (!success) {
            revert CallFailed(returnData);
        }

        return returnData;
    }

    /**
     * @notice Execute a simple ETH transfer (no calldata)
     * @param signer The session key that signed
     * @param to Recipient address
     * @param value Amount to send
     * @param deadline Expiry timestamp
     * @param nonce Replay protection
     * @param signature EIP-191 signature
     */
    function executeTransfer(
        address signer,
        address payable to,
        uint256 value,
        uint256 deadline,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant {
        uint256 gasStart = gasleft();

        if (!allowedSigners[signer]) revert SignerNotAllowed(signer);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline);
        if (nonce != nonces[signer]) revert InvalidNonce(nonces[signer], nonce);

        // For transfers, we hash: signer, to, value, deadline, nonce
        bytes32 messageHash = keccak256(abi.encodePacked(
            "SessionKeyTransfer:",
            signer,
            to,
            value,
            deadline,
            nonce,
            block.chainid,
            address(this)
        ));
        
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        if (ethSignedHash.recover(signature) != signer) revert InvalidSignature();

        nonces[signer]++;
        _checkAndUpdateBudget(signer, gasStart);

        if (value > address(this).balance) {
            revert InsufficientBalance(value, address(this).balance);
        }

        (bool success, ) = to.call{value: value}("");
        
        uint256 gasUsed = gasStart - gasleft();
        emit MetaTransactionExecuted(signer, to, value, gasUsed, success);

        if (!success) revert CallFailed("");
    }

    /* ═══════════════════════════════════════════════════════════════════════════
     * VIEW FUNCTIONS
     * ═══════════════════════════════════════════════════════════════════════════ */

    /**
     * @notice Get the message hash for a meta-transaction
     */
    function getMessageHash(
        address signer,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "SessionKeyMetaTx:",
            signer,
            target,
            value,
            keccak256(data),
            deadline,
            nonce,
            block.chainid,
            address(this)
        ));
    }

    /**
     * @notice Get transfer message hash
     */
    function getTransferHash(
        address signer,
        address to,
        uint256 value,
        uint256 deadline,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "SessionKeyTransfer:",
            signer,
            to,
            value,
            deadline,
            nonce,
            block.chainid,
            address(this)
        ));
    }

    /**
     * @notice Check if a signer is allowed
     */
    function isSignerAllowed(address signer) external view returns (bool) {
        return allowedSigners[signer];
    }

    /**
     * @notice Get remaining daily budget for a signer
     */
    function getRemainingBudget(address signer) external view returns (uint256) {
        if (block.timestamp >= lastResetTimestamp[signer] + 1 days) {
            return dailyGasBudget;
        }
        if (dailyGasUsed[signer] >= dailyGasBudget) {
            return 0;
        }
        return dailyGasBudget - dailyGasUsed[signer];
    }

    /* ═══════════════════════════════════════════════════════════════════════════
     * INTERNAL FUNCTIONS
     * ═══════════════════════════════════════════════════════════════════════════ */

    function _checkAndUpdateBudget(address signer, uint256 gasStart) internal {
        // Reset daily budget if 24 hours have passed
        if (block.timestamp >= lastResetTimestamp[signer] + 1 days) {
            dailyGasUsed[signer] = 0;
            lastResetTimestamp[signer] = block.timestamp;
        }

        // Estimate gas cost
        uint256 estimatedGas = gasStart * tx.gasprice;
        
        if (dailyGasUsed[signer] + estimatedGas > dailyGasBudget) {
            revert DailyBudgetExceeded(dailyGasUsed[signer] + estimatedGas, dailyGasBudget);
        }

        dailyGasUsed[signer] += estimatedGas;
    }

    /* ═══════════════════════════════════════════════════════════════════════════
     * RECEIVE
     * ═══════════════════════════════════════════════════════════════════════════ */

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }
}
