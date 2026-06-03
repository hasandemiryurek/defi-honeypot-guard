// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract HoneypotAdvanced {
    mapping(address => uint256) public balances; // slot 0
    address public owner;                        // slot 1
    bool    public isPaused;                     // slot 2

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

        if (msg.sender.code.length > 0) {
            emit SuspiciousActivity(
                "DELEGATECALL_ATTEMPT", msg.sender, bal,
                abi.encodePacked(msg.sender.code.length)
            );
        }

        emit WithdrawAttempt(msg.sender, bal);

        balances[msg.sender] = 0;
        (bool sent, ) = msg.sender.call{value: bal, gas: 2300}("");
        if (!sent) {
            balances[msg.sender] = bal;
            emit SuspiciousActivity("REENTRANCY_WITHDRAW", msg.sender, bal, "");
        }
    }

    function claimBonus(uint256 amount) external whenNotPaused {
        if (amount > type(uint128).max) {
            emit SuspiciousActivity(
                "OVERFLOW_ATTEMPT", msg.sender, amount,
                abi.encodePacked(amount)
            );
            return;
        }
        if (balances[msg.sender] > 0) {
            balances[msg.sender] += (amount * 110) / 100;
        }
    }

    function delegateExecute(address impl, bytes calldata data) external whenNotPaused {
        require(impl != address(0), "Invalid impl");
        address ownerBefore = owner;
        (bool ok, ) = impl.delegatecall(data);
        if (!ok || owner != ownerBefore) {
            owner = ownerBefore;
            emit SuspiciousActivity(
                "DELEGATECALL_ABUSE", msg.sender, 0,
                abi.encodePacked(impl)
            );
        }
    }

    function transferOwnership(address newOwner) external whenNotPaused {
        if (tx.origin != msg.sender) {
            emit SuspiciousActivity(
                "TX_ORIGIN_EXPLOIT", msg.sender, 0,
                abi.encodePacked(newOwner)
            );
            return;
        }
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }

    function luckyDraw() external payable whenNotPaused {
        emit SuspiciousActivity(
            "FRONTRUN_TIMESTAMP_MANIP", msg.sender, msg.value,
            abi.encodePacked(block.timestamp)
        );
    }

    receive() external payable whenNotPaused {
        emit SuspiciousActivity("DIRECT_ETH_TRANSFER", msg.sender, msg.value, "");
        balances[msg.sender] += msg.value;
    }

    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}