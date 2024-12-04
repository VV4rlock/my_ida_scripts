import idautils

def find_mnem_above(ea, mnem, _max = 10):
    mnem = mnem.lower()
    ea -= 4
    cnt = 0
    while(not idc.print_insn_mnem(ea).lower().startswith(mnem)):
        ea -= 4
        cnt += 1
        if cnt >= _max:
            return idc.BADADDR
    return ea

def find_mnem_op0_above(ea, mnem, op0, _max = 10):
    mnem = mnem.lower()
    op0 = op0.lower()
    ea -= 4
    cnt = 0
    while(True):
        mov_ea = find_mnem_above(ea, mnem)
        if mov_ea == idc.BADADDR:
            return idc.BADADDR
        
        operand0 = idc.print_operand(mov_ea, 0).lower()
        #print(operand0)
        if operand0.startswith(op0):
            return mov_ea
        ea = mov_ea
        cnt += 1
        if cnt >= _max:
            return idc.BADADDR
    return ea
          
        
def print_args(ea):
    for xref in idautils.XrefsTo(ea):
        xref_adr = xref.frm
        arg1_addr = find_mnem_op0_above(xref_adr, 'mov', 'w1')
        func_start_ea = idaapi.get_func(xref_adr).start_ea
        if arg1_addr != idc.BADADDR:
            print("{}: {} {} {} {}".format(hex(xref_adr),idc.print_insn_mnem(arg1_addr), idc.print_operand(arg1_addr, 0), idaapi.get_name(func_start_ea) ,idc.print_operand(arg1_addr, 1) ))
        else:
            print("skip {}".format(hex(xref_adr)))

def is_mnem_op0(ea, mnem_name, op0_name):
    mnem_name = mnem_name.lower()
    op0_name = op0_name.lower()
    return idc.print_insn_mnem(ea).lower().startswith(mnem_name) and idc.print_operand(ea, 0).lower().startswith(op0_name)
    

def keybagd_aks_calls(aks_open_ea):
    for xref in idautils.XrefsTo(aks_open_ea):
        xref_adr = xref.frm
        func = idaapi.get_func(xref_adr)
        if func is None:
            print('[WARNING] skiping {}, func not found'.format(hex(xref_adr)))
            continue
        for ea in range(xref_adr, func.end_ea, 4):
            if is_mnem_op0(ea, "bl", '_IOConnectCallMethod'):
                arg1_addr = find_mnem_op0_above(ea, 'mov', 'w1')
                if arg1_addr != idc.BADADDR:
                    print("{}: {} {} {} {}".format(hex(func.start_ea), idc.print_insn_mnem(arg1_addr), idc.print_operand(arg1_addr, 0), idaapi.get_name(func.start_ea) ,idc.print_operand(arg1_addr, 1) ))
                    str_int = idc.print_operand(arg1_addr, 1).replace('#', '')
                    if not idaapi.get_name(func.start_ea).startswith("AppleKeyStore_call"):
                        idaapi.set_name(func.start_ea, "AppleKeyStore_call_{}".format(str_int), 0x801)
                else:
                    print("Skiping {}, arg1 not found",format(hex(func.start_ea)))
    
    
        
#ioconn_ea = idaapi.get_name_ea(idaapi.BADADDR,'_IOConnectCallMethod')   
#print_args(ioconn_ea)

aks_open_ea = idaapi.get_name_ea(idaapi.BADADDR,'openAppleKeyStore')  
keybagd_aks_calls(aks_open_ea)


def get_keys(der_table_ea):
    ea = der_table_ea
    tag_is_c = idaapi.get_bytes(ea, 1) == b'\x0c'
    out = {}
    while(tag_is_c):
        name = idaapi.get_name(ea)
        ea += 1
        length = idaapi.get_bytes(ea, 1)[0]
        ea += 1
        key = idaapi.get_bytes(ea, length)
        out[key] = name
        ea += length
        tag_is_c = idaapi.get_bytes(ea, 1) == b'\x0c'
    return out
        

der_table_start = 0x194C342C0
d = get_keys(der_table_start)
keys = [k for k in d]
for k in keys:
    #print(d[k], k)
    print("    {", " {}, 0,".format(", ".join([hex(i) for i in k])), "},")
#for k in keys:
#    print("    \"{}\",".format(d[k]))