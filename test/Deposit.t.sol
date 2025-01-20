// SPDX-License-Identifier: MIT
pragma solidity ^0.6.11;

import "forge-std/Test.sol"; // Foundry's testing utilities
import "../src/Deposit.sol"; // Path to your DepositContract.sol inmy files 

contract DepositContractTest is Test {
    DepositContract depositContract;

    // Setup function to deploy the contract before each test
    function setUp() public {
        depositContract = new DepositContract();
    }

    // Test for insufficient deposit value
    function testInsufficientDepositValue() public {
        bytes memory pubkey = new bytes(48);
        bytes memory withdrawalCredentials = new bytes(32);
        bytes memory signature = new bytes(96);
        bytes32 depositDataRoot = bytes32(0);

        // Expect revert with error message
        vm.expectRevert("DepositContract: deposit value too low");
        depositContract.deposit{value: 0.5 ether}(pubkey, withdrawalCredentials, signature, depositDataRoot);
    }

    // Test for integer overflow in deposit amount
    function testDepositAmountOverflow() public {
        bytes memory pubkey = new bytes(48);
        bytes memory withdrawalCredentials = new bytes(32);
        bytes memory signature = new bytes(96);
        bytes32 depositDataRoot = bytes32(0);

        // Using maximum uint256 value to check for overflow
        vm.expectRevert("DepositContract: deposit value too high");
        depositContract.deposit{value: type(uint256).max}(pubkey, withdrawalCredentials, signature, depositDataRoot);
    }

    // Test for reentrancy vulnerability (mock attack)
    function testReentrancy() public {
        // Simulate a reentrant call scenario if possible (mock a malicious contract)
        // Foundry's cheat codes and expectRevert can be used to simulate reentrancy and check for proper handling.
        // Implementation would depend on adding a vulnerable function for testing or using a mock.
    }

    // Test for Merkle tree full
    function testMerkleTreeFull() public {
        bytes memory pubkey = new bytes(48);
        bytes memory withdrawalCredentials = new bytes(32);
        bytes memory signature = new bytes(96);
        bytes32 depositDataRoot = bytes32(0);

        for (uint256 i = 0; i < 2**32; i++) {
            if (i == 2**32 - 1) {
                vm.expectRevert("DepositContract: merkle tree full");
            }
            depositContract.deposit{value: 1 ether}(pubkey, withdrawalCredentials, signature, depositDataRoot);
        }
    }

    // Test for incorrect data verification
    function testIncorrectDataVerification() public {
        bytes memory pubkey = new bytes(48);
        bytes memory withdrawalCredentials = new bytes(32);
        bytes memory signature = new bytes(96);
        bytes32 incorrectDepositDataRoot = bytes32(0); // Incorrect root

        vm.expectRevert("DepositContract: reconstructed DepositData does not match supplied deposit_data_root");
        depositContract.deposit{value: 1 ether}(pubkey, withdrawalCredentials, signature, incorrectDepositDataRoot);
    }

    // Additional tests for supporting interface checks, event emissions, and others.
    function testSupportsInterface() public {
        bool isERC165 = depositContract.supportsInterface(type(ERC165).interfaceId);
        bool isIDepositContract = depositContract.supportsInterface(type(IDepositContract).interfaceId);
        
        assertTrue(isERC165, "Contract should support ERC165 interface");
        assertTrue(isIDepositContract, "Contract should support IDepositContract interface");
    }
}
