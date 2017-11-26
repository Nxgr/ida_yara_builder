from capstone import *
from capstone.x86 import *

from keystone import *

from binascii import hexlify

import logging

logger = logging.getLogger(__name__)

class SigMake(object):
    """Return a yara string signature for bytecode, with register names wildcarded.

    The goal is to return a generic yara signature from a bytecode listing.
    For now it can only abstract registers names, to detect instructions such as :
        mov eax, 20h <-> mov ???, 20h

    The process is the following :
    - Takes in bytecode, disassembles it with Capstone.
    - Extract register name from the disassembly if possible
    - For each inst :
        . Generate all equivalent instruction by changing registers names
        . Get the compiled bytecode with Keystone
        . Diff the bytecode and set wildcard char '?' for the variable nibbles.
    - Return the generic signature

    Ex :
    - input  : 8D 14 3E 8B 7D FC 8A 0C 11 32 0C 38 40 8B 7D 10 88 0A 8B 4D 08 3B C3 72 E7 
    - output : 8D ?? ?? 8B ?? FC 8A ?? ?? 32 ?? ?? 4? 8B ?? 10 88 ?? 8B ?? 08 3? ?? 72 E7

    """

    def __init__(self, str_code, int_mode):
        """Init the class.

        Args:
            str_code (str): bytecode to work with.
            int_mode (int): cpu mode (32 or 64 bit)

        Raises:
            ValueError: Non implemented cpu mode

        """

        self.str_code = str_code

        if int_mode == 32:
            self._dword_regs = [u'eax',  u'ebx', u'ecx', u'edx', u'edi', u'esi', u'ebp', u'eip']
            self._word_regs  = [u'ax' ,  u'bx' , u'cx' , u'dx' , u'di' , u'si']
            self._hword_regs = [u'ah', u'al', u'bh', u'bl', u'ch', u'cl', u'dh', u'dl', u'sil', u'dil']

            self._md = Cs(CS_ARCH_X86, CS_MODE_32)

            self._ks = Ks(KS_ARCH_X86, KS_MODE_32)

        elif int_mode == 64:
            logger.error("64 bit mode not implemented yet")
            raise ValueError
        else:
            logger.error("unknown mode")
            raise ValueError

        self._md.detail = True
        self.list_regs = [self._dword_regs, self._word_regs, self._hword_regs]
        self.list_instructions = []

        self.get_instruction_list()

    def get_instruction_registers(self, instruction):
        """return a list of register names present in the instruction.

        Args:
            instruction (obj capstone instruction): instruction to extract the registers from

        Returns:
            A list of register names
        """
        list_registers = []
        if len(instruction.operands) > 0:
            for operand in instruction.operands:
                if operand.type == X86_OP_REG:
                    list_registers.append(instruction.reg_name(operand.value.reg))

                if operand.type == X86_OP_MEM:
                    if operand.value.mem.base != 0:
                        list_registers.append(instruction.reg_name(operand.value.mem.base))
                    if operand.value.mem.index != 0:
                        list_registers.append(instruction.reg_name(operand.value.mem.index))
        return set(list_registers)

    def get_instruction_list(self):
        """Get a list of tuples (capstone instruction, list_register).

        Setup the self instruction list for the current bytecode.
        self.list_instructions is actually a tuple of (obj capstone instruction, list_register) with
        list_register being the register names present in the instruction.

        """
        for instruction in self._md.disasm(self.str_code, 0x1000):
            set_registers = self.get_instruction_registers(instruction)
            self.list_instructions.append((instruction,set_registers))

    def format_instruction(self, instruction, pretty=False):
        """Format the obj capstone instruction into a string.

        Args:
            instruction (obj capstone instruction): instruction to format
            pretty (bool): defines if it return the raw version, or tabulated one with adress.

        Returns:
            String formated instruction.

            Ex with pretty :
            0x1001: mov eax, ebx

            Ex without pretty :
            mov eax, ebx

        """
        if pretty:
            return "0x%x:\t%s\t%s" %(instruction.address, instruction.mnemonic, instruction.op_str)
        else:
            return "{} {}".format(instruction.mnemonic, instruction.op_str)

    def hl_regs(self):
        for instruction in self.list_instructions:
            color_desc = self.format_instruction(instruction[0], pretty=True) 
            for reg in instruction[1]:
                color_desc = color_desc.replace(reg,"\033[31m"+reg+"\033[0m")
            print color_desc

    def get_similar_registers(self, reg):
        """Return a list containing equivalent registers

        Args:
            reg (str): a register name

        Returns:
            A list containing equivalent registers.
        """
        for list_reg in self.list_regs:
            if reg in list_reg:
                return list_reg

        return []

    def get_similar_instructions(self, instruction): 
        """Return a list of the same instruction with equivalent registers.

        Generate a list of instruction where the registers names have been
        swapped by equivalent registers names.
        Ex:
        mov eax, 10h -> ["mov ebx, 10h", "mov ecx, 10h", ...]

        Args:
            instruction (obj capstone instruction): instruction to format

        Returns:
            A list of the same instruction with different register names.

        """
        list_similar_instructions = []
        og_text_instruction = self.format_instruction(instruction[0])

        if not instruction[1]:
            return [og_text_instruction]

        for instruction_reg in instruction[1]:
            list_similar_registers = self.get_similar_registers(instruction_reg) 
            for reg in list_similar_registers:
                text_instruction = og_text_instruction.replace(instruction_reg,reg)
                list_similar_instructions.append(text_instruction)

        return list_similar_instructions

    def compile_inst(self, text_instruction):
        """Compiles asm code with Keystone.

        Tries to compile an asm instruction with keystone.
        
        Args:
            text_instruction (str): asm instruction.

        Returns:
            If success, returns an hexlified string corresponding to the inst
            bytecode.
            If failure, returns None

        """
        try:
            encoding, count = self._ks.asm(text_instruction)
        except KsError:
            return None
        
        #print("{} -> {}".format(text_instruction, hexlify("".join(chr(e) for e in encoding))))
        return hexlify("".join(chr(e) for e in encoding))

    def get_diff_bytes(self, list_bytes):
        """Diff a list of strings by setting '?' in place of changing chars.

        Args:
            list_bytes (list): list of strings.

        Returns:
            A string with changing chars wildcarded with '?'.

        """
        diff = ""
        for i,c in enumerate(list_bytes[0]):
            if len(set([l[i] for l in list_bytes])) > 1:
                diff += '?'
            else:
                diff += c

        return diff

    def get_wildcard_string(self):
        """Builds the the wildcarded signature.

        Uses the instruction list built from the bytecode gave
        to the class constructor, and generate a wildcarded byte signature
        to abstract the registers names.

        Returns:
            A string usable as a yara filter to match the input bytecode.

        """
        diff_bytes = ""

        # For each instruction in the bytecode disassembly
        for instruction in self.list_instructions:
            # Get all the similar instructions with different register names
            shuffled_instruction = self.get_similar_instructions(instruction)
            list_bytes = []
            
            # Avoids some artifacts due to compilation, such as jumps.
            if len(shuffled_instruction) == 1:
                list_bytes = [hexlify(instruction[0].bytes)]
            else:
                # Get the different compiled bytes for each register name
                print instruction[0].mnemonic
                print instruction[1]
                print shuffled_instruction
                for text_instruction in shuffled_instruction:
                    instruction_bytes = self.compile_inst(text_instruction)
                    if instruction_bytes:
                        list_bytes.append(instruction_bytes)

                if len(list_bytes) == 0:
                    print repr(instruction[0].bytes)
                    list_bytes = [hexlify(instruction[0].bytes)]
                    
            # Diff all the bytes listing 
            cur_diff_bytes = self.get_diff_bytes(list_bytes)
            diff_bytes += cur_diff_bytes

        return ''.join([diff_bytes[i] + diff_bytes[i+1] + ' ' for i in range(0,len(diff_bytes),2)])

def normalize_input(s):
    return s.translate(None, ' \n\t,')

if __name__ == "__main__":
    str_code = normalize_input("8D143E8B7DFC8A0C11320C38408B7D10880A8B4D083BC372E7").decode('hex')
    str_code = '@\xba\x04\x00\x00\x00\xf7\xe2UV\x0f\x90\xc1\xf7\xd9\x0b\xc8'
    sig = SigMake(str_code, 32)
    sig.hl_regs()
    print sig.get_wildcard_string()
    print "8D 14 3E 8B 7D FC 8A 0C 11 32 0C 38 40 8B 7D 10 88 0A 8B 4D 08 3B C3 72 E7"
