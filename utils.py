
def clear_output():
    form = idaapi.find_widget("Output window")
    idaapi.activate_widget(form, True)
    idaapi.process_ui_action("msglist:Clear")

    print('===[Script Name]===')

def ida_set_name(self):
    idaapi.set_name(self.address, self.name, idaapi.SN_CHECK)
    
def get_ea_name(ea)
    return idaapi.get_name(ea)
        
def read_dword(ea):
    return int.from_bytes(idaapi.get_bytes(ea,4), byteorder='little')

def read_qword(ea):
    return int.from_bytes(idaapi.get_bytes(ea,8), byteorder='little')

def find_forward(ea, val, mask, search_size):
    while((read_dword(ea) & mask) != val):
        ea+=4
        search_size -=4
        if search_size == 0:
            return 0
    return ea
    
def find_func_4(base):
    ea = base
    next = True
    while next:
        ea = find_forward(ea, 0xB000000, 0xFFE0FC00, 524032)
        if ea == 0:
            print("find_func_4 ea not found")
            return 0
        print("    tmp: {}".format(hex(ea)))
        v18 = read_dword(ea + 4)
        ea += 4
        v15 = read_dword(ea + 8)
        next = ((v18 & 0xFFE0FC10) != 0xB8204810) or (v15 != 0xD65F03C0)
        
    print("found: {}".format(hex(ea)))

def patch_addreses_in_struct(ea, addr_offset, struc_size):
    adr = int.from_bytes(idaapi.get_bytes(ea+addr_offset, 4), 'little')
    while adr:
        if adr & 0xff000000 != 0x04000000:
            idaapi.patch_bytes(ea + addr_offset + 3, b'\x04')
        ea += struc_size
        adr = int.from_bytes(idaapi.get_bytes(ea+addr_offset, 4), 'little')
    