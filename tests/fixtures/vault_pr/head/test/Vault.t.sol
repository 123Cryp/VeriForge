// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/Vault.sol";

contract VaultTest is Test {
    Vault vault;
    address stranger = address(0xBEEF);

    function setUp() public {
        vault = new Vault();
        vm.deal(stranger, 1 ether);
    }

    function testWithdrawRejectsUnauthorizedCaller() public {
        vm.prank(stranger);
        vault.deposit{value: 1 ether}();
        vm.prank(stranger);
        vm.expectRevert("unauthorized");
        vault.withdraw(1 ether);
    }
}
