import sys
from instruction_set import instructions, cb_instructions

BASE_ADDR = 0xDA00

def read_byte(f):
    b = f.read(1)
    if not b:
        return None
    return b[0]

def read_word(f):
    lo = read_byte(f)
    hi = read_byte(f)
    if lo is None or hi is None:
        return None
    return lo | (hi << 8)

def main():
    if len(sys.argv) < 2:
        print("Usage: ./mgbdis.py <Filename>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        pc = 0
        while True:
            addr = BASE_ADDR + pc
            opcode = read_byte(f)
            if opcode is None:
                break

            if opcode == 0xCB:
                cbcode = read_byte(f)
                if cbcode is None:
                    break
                instr = cb_instructions.get(cbcode, f"db ${cbcode:02X}")
                print(f"{addr:04X}: {opcode:02X} {cbcode:02X}    {instr}")
                pc += 2
                continue

            instr = instructions.get(opcode, f"db ${opcode:02X}")

            if 'd16' in instr or 'a16' in instr:
                lo = read_byte(f)
                hi = read_byte(f)
                if lo is None or hi is None:
                    break
                word = lo | (hi << 8)
                print(f"{addr:04X}: {opcode:02X} {lo:02X} {hi:02X}    {instr.replace('d16', f'${word:04X}').replace('a16', f'${word:04X}')}")
                pc += 3
            elif 'd8' in instr or 'a8' in instr or 'r8' in instr:
                byte = read_byte(f)
                if byte is None:
                    break
                if 'r8' in instr:
                    val = byte if byte < 0x80 else byte - 0x100
                    print(f"{addr:04X}: {opcode:02X} {byte:02X}       {instr.replace('r8', f'{val:+d}')}")
                else:
                    print(f"{addr:04X}: {opcode:02X} {byte:02X}       {instr.replace('d8', f'${byte:02X}').replace('a8', f'${byte:02X}')}")
                pc += 2
            else:
                print(f"{addr:04X}: {opcode:02X}          {instr}")
                pc += 1

if __name__ == "__main__":
    main()
