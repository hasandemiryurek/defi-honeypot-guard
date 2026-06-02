// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IHoneypot {
    function claimBonus(uint256) external;
}

contract AttackerStorageManip {
    IHoneypot public honeypot;
    mapping(uint256 => uint256) private slots;
    uint256[10] private arr;

    constructor(address _honeypot) {
        honeypot = IHoneypot(_honeypot);
    }

    function attack() external payable {
        for (uint256 i = 0; i < 10; i++) {
            slots[i] = i * 0xdeadbeef;
            arr[i]   = block.number + i;
        }
        try honeypot.claimBonus(999) {} catch {}
    }
}