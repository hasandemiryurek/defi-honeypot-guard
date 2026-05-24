// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract HoneypotAdvanced {
    mapping(address => uint256) public balances;
    address public owner;
    bool    public isPaused;

    event SuspiciousActivity(
        string     attackType,
        address indexed actor,
        uint256         value,
        bytes           data
    );
    event WithdrawAttempt(address indexed user, uint256 amount);
    event Paused(address indexed by, string reason);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!isPaused, "Contract paused");
        _;
    }

    constructor() payable {
        owner = msg.sender;
    }

    function pause(string calldata reason) external onlyOwner {
        isPaused = true;
        emit Paused(msg.sender, reason);
    }

    function unpause() external onlyOwner {
        isPaused = false;
    }

    function deposit() external payable whenNotPaused {
        balances[msg.sender] += msg.value;
    }

        function withdraw() external whenNotPaused {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Yetersiz bakiye");

        emit WithdrawAttempt(msg.sender, bal);

        // CEI: balance sifirla, sonra transfer et
        balances[msg.sender] = 0;

        // 2300 gas ile reentrancy'yi fiziksel olarak engelle
        (bool sent, ) = msg.sender.call{value: bal, gas: 2300}("");
        if (!sent) {
            // Reentrancy tespit edildi — balance'i geri yukle, event at
            balances[msg.sender] = bal;
            emit SuspiciousActivity("REENTRANCY_WITHDRAW", msg.sender, bal, "");
        }
    }

    function claimBonus(uint256 amount) external whenNotPaused {
        emit SuspiciousActivity("OVERFLOW_ATTEMPT", msg.sender, amount, abi.encodePacked(amount));
    }

    function transferOwnership(address newOwner) external whenNotPaused {
        emit SuspiciousActivity("TX_ORIGIN_EXPLOIT", msg.sender, 0, abi.encodePacked(newOwner));
    }

    function luckyDraw() external payable whenNotPaused {
        emit SuspiciousActivity("FRONTRUN_TIMESTAMP_MANIP", msg.sender, msg.value, abi.encodePacked(block.timestamp));
    }

    receive() external payable whenNotPaused {
        emit SuspiciousActivity("DIRECT_ETH_TRANSFER", msg.sender, msg.value, "");
        balances[msg.sender] += msg.value;
    }

    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}