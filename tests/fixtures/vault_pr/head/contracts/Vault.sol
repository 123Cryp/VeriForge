// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    mapping(address => bool) public authorized;
    mapping(address => uint256) public balances;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, address indexed to, uint256 amount);

    modifier onlyAuthorized() {
        require(authorized[msg.sender], "unauthorized");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorized[msg.sender] = true;
    }

    function authorize(address account) external {
        require(msg.sender == owner, "not owner");
        authorized[account] = true;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external onlyAuthorized {
        _send(payable(msg.sender), amount);
    }

    function withdrawTo(address payable to, uint256 amount) external {
        _send(to, amount);
    }

    function _send(address payable to, uint256 amount) internal {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        to.transfer(amount);
        emit Withdrawn(msg.sender, to, amount);
    }
}
