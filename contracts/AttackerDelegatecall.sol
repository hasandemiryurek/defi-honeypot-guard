// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IHoneypot {
    function deposit() external payable;
}

contract AttackerDelegatecall {
    IHoneypot public honeypot;
    uint256 public slot0;
    uint256 public slot1;

    constructor(address _honeypot) {
        honeypot = IHoneypot(_honeypot);
    }

    function attack() external payable {
        address(this).delegatecall(abi.encodeWithSignature("_helper()"));
        address(this).delegatecall(abi.encodeWithSignature("_helper()"));
        address(this).delegatecall(abi.encodeWithSignature("_helper()"));
        address(this).delegatecall(abi.encodeWithSignature("_helper()"));
        (bool ok,) = address(honeypot).call{value: msg.value}("");
ok;
    }

    function _helper() external {
        slot0 += 1;
        slot1 = slot0 * 2;
    }
}