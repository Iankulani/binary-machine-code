# -*- coding: utf-8 -*-
"""
Created on Thurs Jan  1 11:42:47 2025

@author: IAN CARTER KULANI
"""


from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("BINARY MACHINE CODE")
print(Fore.GREEN+font)


import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# Map of Assembly instructions to C/C++ code snippets
assembly_to_c_keywords = {
    "mov": "=",  # Assembly MOV to C/C++ assignment
    "add": "+=",
    "sub": "-=",
    "mul": "*=",
    "div": "/=",
    "jmp": "goto",
    "cmp": "if",
    "je": "if (condition) {",  # Simplified representation of conditional jump
    "jne": "if (condition) {",
    "jg": "if (condition) {",
    "jl": "if (condition) {",
    "call": "function_call",
    "ret": "return",
    "imul": "*",
    "nop": "// No operation"
}

# C/C++ keywords list (not exhaustive)
c_keywords = [
    "auto", "do", "double", "long", "short", "if", "else", "enum", "extern", "void", 
    "volatile", "struct", "static", "int", "float", "char", "sizeof", "typedef", "signed", 
    "unsigned", "for", "while", "register", "union", "goto", "_packed", "return"
]

def disassemble_machine_code(machine_code, architecture='x86_64'):
    """
    Disassemble the given machine code into human-readable assembly language.
    """
    if architecture == 'x86_64':
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        print("Unsupported architecture!")
        return []

    disassembled_code = []
    for insn in md.disasm(machine_code, 0x1000):  # Starting address is arbitrary
        disassembled_code.append(f"{insn.mnemonic} {insn.op_str}")

    return disassembled_code

def convert_to_c_language(assembly_code):
    """
    Convert the disassembled assembly code into C/C++ human-readable language.
    """
    c_code = []
    
    for line in assembly_code:
        parts = line.split()
        if len(parts) == 0:
            continue
        
        mnemonic = parts[0].lower()

        # Check if the mnemonic is in the assembly-to-C mapping
        if mnemonic in assembly_to_c_keywords:
            if mnemonic == "cmp" or mnemonic == "je" or mnemonic == "jne" or mnemonic == "jg" or mnemonic == "jl":
                # Handle conditional jumps (simplified)
                c_code.append(f"{assembly_to_c_keywords[mnemonic]} {parts[1]} }}")  # End of if statement
            elif mnemonic == "jmp":
                c_code.append(f"{assembly_to_c_keywords[mnemonic]} {parts[1]};")
            else:
                c_code.append(f"{parts[1]} {assembly_to_c_keywords[mnemonic]} {parts[2]};")
        else:
            c_code.append(f"// Unrecognized instruction: {line}")

    return c_code

def print_c_code(c_code):
    """
    Print the converted C/C++ code.
    """
    print("\nConverted C/C++ Code:")
    print("#include <stdio.h>\n")
    print("int main() {")
    
    for line in c_code:
        print(f"    {line}")
    
    print("    return 0;\n}")

def main():
    # Ask the user to enter the machine code (in hexadecimal format)
    machine_code_input = input("Enter machine code (in hexadecimal format):").strip()
    
    # Convert the input from hexadecimal to raw bytes
    try:
        machine_code = bytes.fromhex(machine_code_input)
    except ValueError:
        print("Invalid machine code format. Please enter valid hexadecimal values.")
        return
    
    # Disassemble the machine code
    print("\nDisassembling machine code...\n")
    disassembled_code = disassemble_machine_code(machine_code)
    
    if not disassembled_code:
        print("Error: Could not disassemble the machine code.")
        return
    
    # Convert the disassembled assembly code to C/C++ code
    c_code = convert_to_c_language(disassembled_code)
    
    # Print the converted C/C++ code
    print_c_code(c_code)

if __name__ == "__main__":
    main()
