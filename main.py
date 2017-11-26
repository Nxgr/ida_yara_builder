from idaapi import *
from idc import *

from sigmake import SigMake
from yaraRule import YaraRule

def get_selected_bytes():
    selected_range = read_selection()
    addr_selected_low = selected_range[1]
    addr_selected_high = selected_range[2]

    str_selected_bytes = ""

    size_last_instruction = ItemSize(addr_selected_high)

    size_selection = addr_selected_high - addr_selected_low + size_last_instruction
    str_selected_bytes = idc.GetManyBytes(addr_selected_low, size_selection)

    return str_selected_bytes


if __name__ == "__main__":
    str_selected_bytes = get_selected_bytes()
    print repr(str_selected_bytes)

    sig = SigMake(str_selected_bytes,32)
    str_signature = sig.get_wildcard_string()
    print str_signature
    
