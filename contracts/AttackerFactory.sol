// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IHoneypot {
    function deposit() external payable;
}

contract AttackerFactory {
    IHoneypot public honeypot;
    address[] public children;

    constructor(address _honeypot) {
        honeypot = IHoneypot(_honeypot);
    }

    function attack() external payable {
        bytes memory code = type(MiniContract).creationCode;
        for (uint256 i = 0; i < 5; i++) {
            address child;
            assembly {
                child := create2(0, add(code, 0x20), mload(code), i)
            }
            if (child != address(0)) children.push(child);
        }
        (bool ok,) = address(honeypot).call{value: msg.value}("");
ok;
    }

    function childCount() external view returns (uint256) {
        return children.length;
    }
}

contract MiniContract {
    uint256 public x = 1;
}