def extract_features(bytecode: str) -> list:
    code = bytecode.replace("0x", "").lower()
    if len(code) < 4:
        return [0.0] * 26
    bytes_list = [code[i:i+2] for i in range(0, len(code), 2)]
    total = len(bytes_list) or 1

    call_f1 = sum(1 for b in bytes_list if b == "f1")
    call_f2 = sum(1 for b in bytes_list if b == "f2")
    call_f4 = sum(1 for b in bytes_list if b == "f4")
    call_fa = sum(1 for b in bytes_list if b == "fa")
    call_ops     = call_f1 + call_f2 + call_f4 + call_fa
    selfdestruct = sum(1 for b in bytes_list if b == "ff")
    create_ops   = sum(1 for b in bytes_list if b in ("f0", "f5"))
    sstore       = sum(1 for b in bytes_list if b == "55")
    sload        = sum(1 for b in bytes_list if b == "54")
    jumpi_count  = sum(1 for b in bytes_list if b == "57")
    jump_count   = sum(1 for b in bytes_list if b == "56")
    jumpdest     = sum(1 for b in bytes_list if b == "5b")
    push_count   = sum(1 for b in bytes_list if "60" <= b <= "7f")
    dup_count    = sum(1 for b in bytes_list if "80" <= b <= "8f")
    swap_count   = sum(1 for b in bytes_list if "90" <= b <= "9f")
    lt_op  = sum(1 for b in bytes_list if b == "10")
    gt_op  = sum(1 for b in bytes_list if b == "11")
    eq_op  = sum(1 for b in bytes_list if b == "14")
    stop   = sum(1 for b in bytes_list if b == "00")
    revert = sum(1 for b in bytes_list if b == "fd")
    mload  = sum(1 for b in bytes_list if b == "51")
    mstore = sum(1 for b in bytes_list if b == "52")
    callvalue  = sum(1 for b in bytes_list if b == "34")
    unique_ops = len(set(bytes_list))
    
    create2 = sum(1 for b in bytes_list if b == "f5")
    jump_density = (jump_count + jumpi_count) / total
    f_density    = code.count("f") / len(code)
    ff_density   = selfdestruct / total

    return [
        len(code), f_density, call_ops, selfdestruct, create_ops,
        sstore, sload, jump_density,
        1.0 if call_ops > 0 and sstore > 0 else 0.0,
        call_f4 / call_ops if call_ops > 0 else 0.0,
        ff_density,
        1.0 if jumpi_count / total > 0.05 else 0.0,
        jumpdest / total,
        push_count / total,
        (dup_count + swap_count) / total,
        (lt_op + gt_op + eq_op) / total,
        (stop + revert) / total,
        (mload + mstore) / total,
        callvalue / total,
        unique_ops / 256.0,
        1.0 if create2 > 0 else 0.0,
        1.0 if call_f4 > 0 else 0.0,
        sstore / total,
        float(create2),
        float(call_f4),
        call_ops / total,
    ]