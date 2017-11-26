from miasm2.arch.x86.arch import mn_x86
from miasm2.analysis.binary import Container
from miasm2.analysis.machine import Machine
import copy

class SigMake(object):
    def __init__(self, str_code, int_mode):
        self.list_expr_regs32 = [mn_x86.regs.EAX,mn_x86.regs.EBX,mn_x86.regs.ECX,mn_x86.regs.EDX,mn_x86.regs.ESI,mn_x86.regs.EDI]
        self.list_expr_regs16 = [mn_x86.regs.AX,mn_x86.regs.BX,mn_x86.regs.CX,mn_x86.regs.DX,mn_x86.regs.SI,mn_x86.regs.DI]
        self.list_expr_regs08 = [mn_x86.regs.AL,mn_x86.regs.AH,mn_x86.regs.BL,mn_x86.regs.BH,mn_x86.regs.CL,mn_x86.regs.CH,mn_x86.regs.DL,mn_x86.regs.DH]

        self.list_list_regs = [ self.list_expr_regs08, self.list_expr_regs16, self.list_expr_regs32 ]

        self.list_all_regs = self.list_expr_regs32 + self.list_expr_regs16 + self.list_expr_regs08

        self.str_code = str_code

        if int_mode == 64:
            logger.error("64 bit mode not implemented yet")
            raise ValueError

        self.list_instructions = [] 

        self.build_disassembly()

    def build_disassembly(self):
        c = Container.from_string(self.str_code)
        machine = Machine('x86_32')
        mdis = machine.dis_engine(c.bin_stream)
        cfg = mdis.dis_multiblock(0)
        self.list_blocks = list(cfg.nodes())

    def get_wildcard_string(self, index_block):
        diff_bytes = ""

        for inst in self.list_blocks[index_block].lines:
            list_similar_insts = self.get_similar_instructions(inst)
            list_bytes = []

            for expr_similar_inst in list_similar_insts:
                list_inst_bytes = mn_x86.asm(expr_similar_inst)
                list_bytes.append(mn_x86.asm(expr_similar_inst)[0])

            print list_bytes
            list_filtered_bytes = filter(lambda x: len(x) == len(list_bytes[0]), list_bytes)
            if not list_filtered_bytes:
                print(inst)
                print(mn_x86.asm(inst))

            cur_diff_bytes = self.get_diff_bytes(list_filtered_bytes)
            diff_bytes += cur_diff_bytes
        print diff_bytes

    def get_similar_instructions(self, inst):
        list_similar_insts = []
        for index_arg,expr_arg in enumerate(inst.args):
            list_current_regs = self.get_expr_regs(expr_arg)

            for expr_reg in list_current_regs:
                list_similar_regs = self.get_similar_regs(expr_reg)
                list_current_similar_insts = self.replace_regs(inst, index_arg, expr_reg, list_similar_regs)
                list_similar_insts += list_current_similar_insts

        return list_similar_insts

    def get_similar_regs(self, expr_reg):
        for list_regs in self.list_list_regs:
            if expr_reg in list_regs:
                return list_regs
            
    def replace_regs(self, inst, index_arg, expr_reg, list_regs):
        expr_arg = inst.args[index_arg]
        list_inst = []
        for expr_new_reg in list_regs:
            new_inst = copy.deepcopy(inst)
            expr_new_arg = expr_arg.replace_expr({expr_reg:expr_new_reg})
            new_inst.args[index_arg] = expr_new_arg
            list_inst.append(new_inst)
        return list_inst

    def get_expr_regs(self, expr):
        list_regs = []
        for expr_reg in self.list_all_regs:
            if expr_reg in expr:
                list_regs.append(expr_reg)
        return list_regs

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


    def test(self):
        inst = mn_x86.fromstring("XOR EAX, BX", 32)
        inst = mn_x86.fromstring("MOV EAX, DWORD PTR [EBX+ECX]", 32)
        print("INST : {}".format(inst))

        print("INST ARGS : {}".format(inst.args))


        for i,arg in enumerate(inst.args):
            list_current_regs = get_expr_regs(arg)
            print("INST REGS : {}".format(list_current_regs))
            for expr_reg in list_current_regs:
                list_substitutes = get_similar_regs(expr_reg)
                replace_reg(inst, i, expr_reg, list_substitutes)

def normalize_input(s):
    return s.translate(None, ' \n\t,')

if __name__ == "__main__":
    str_code = normalize_input("8D143E8B7DFC8A0C11320C38408B7D10880A8B4D083BC372E7").decode('hex')
    #str_code = '@\xba\x04\x00\x00\x00\xf7\xe2UV\x0f\x90\xc1\xf7\xd9\x0b\xc8'
    sig = SigMake(str_code, 32)
    #sig.hl_regs()
    print sig.get_wildcard_string(0)
    print "8D 14 3E 8B 7D FC 8A 0C 11 32 0C 38 40 8B 7D 10 88 0A 8B 4D 08 3B C3 72 E7"
