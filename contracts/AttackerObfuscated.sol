// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IHoneypot {
    function luckyDraw() external payable;
}

contract AttackerObfuscated {
    IHoneypot public honeypot;

    constructor(address _honeypot) {
        honeypot = IHoneypot(_honeypot);
    }

    function attack() external payable {
        uint256 x = block.timestamp ^ block.prevrandao;
        unchecked {
            if (x % 2 == 0)  { x = x * 3 + 1;   } else { x = x / 2 + 7; }
            if (x % 3 == 0)  { x = x ^ 0xff;     } else { x = x + block.number; }
            if (x % 5 == 0)  { x = ~x;            } else { x = x * 2 - 1; }
            if (x % 7 == 0)  { x = x >> 1;        } else { x = x << 1; }
            if (x % 11 == 0) { x = x + 0xbabe;    } else { x = x - 1; }
            if (x % 13 == 0) { x = x % 1000000000;} else { x = x + 42; }
            if (x % 17 == 0) { x = x ^ block.basefee; } else { x = x / 3; }
            if (x % 19 == 0) { x = x + gasleft(); } else { x = x * 5; }
        }
        try honeypot.luckyDraw{value: msg.value}() {} catch {}
    }
}