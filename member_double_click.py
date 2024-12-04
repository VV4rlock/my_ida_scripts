import idaapi
import idautils
from collections import defaultdict

try:
    EA64 = idaapi.get_inf_structure().is_64bit()
except:
    EA64 = not ida_ida.inf_is_32bit_exactly()
    
EA_SIZE = 8 if EA64 else 4

def convert_funcname_to_valid(name):
    dname = idaapi.demangle_name(name, idc.get_inf_attr(idc.INF_LONG_DN))
    if dname is None:
        return name
    name = dname
    args_idx_start = name.index('(') + 1
    args_idx_end = name.index(')')
    fname = name[:args_idx_start - 1]
    args = name[args_idx_start: args_idx_end].split(',')
    for i in range(len(args)):
        arg = args[i]
        arg = arg.strip(' ')
        arg = arg.replace(' ', '_')
        arg = arg.replace(' *', '_ptr')
        arg = arg.replace('*', '_ptr')
        args[i] = arg
    return "{}_I_{}_I".format(fname, "_I_".join(args))

class HexRaysCallbackManager(object):
    def __init__(self):
        self.__hexrays_event_handlers = defaultdict(list)

    def initialize(self):
        print("set hooks")
        idaapi.install_hexrays_callback(self.__handle)

    def finalize(self):
        print("remove hooks")
        idaapi.remove_hexrays_callback(self.__handle)

    def register(self, event, handler):
        self.__hexrays_event_handlers[event].append(handler)

    def __handle(self, event, *args):
        for handler in self.__hexrays_event_handlers[event]:
            handler.handle(event, *args)
        # IDA expects zero
        return 0

try:
    hx_callback_manager.finalize()
except: pass
hx_callback_manager = HexRaysCallbackManager()



class HexRaysEventHandler(object):
    def __init__(self):
        super(HexRaysEventHandler, self).__init__()

    def handle(self, event, *args):
        raise NotImplementedError("This is an abstract class")
        
        
class MemberDoubleClick(HexRaysEventHandler):
    def __init__(self):
        super(MemberDoubleClick, self).__init__()

    def handle(self, event, *args):
        hx_view = args[0] #vdui_t
        item = hx_view.item # ctree_item_t #cursor item .e - expression, x - first operand
        if item.citype == idaapi.VDI_EXPR and item.e.op in (idaapi.cot_memptr, idaapi.cot_memref):
            if item.e.x.op == idaapi.cot_memptr:
                vtable_tinfo = item.e.x.type
                if vtable_tinfo.is_ptr():
                    vtable_tinfo = vtable_tinfo.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.m

                name = str(vtable_tinfo)
                sid = idc.get_name_ea_simple(name)
                struc_id = idaapi.get_struc_id(name)
                struc_func_name = idc.get_member_name(struc_id, method_offset)
                
                if sid == idaapi.BADADDR:
                    print("[ERROR] struct {} not found".format(name))
                    return 1
                    
                xrefs = [x for x in idautils.XrefsTo(sid)]
                if len(xrefs) == 0:
                    print("[ERROR] xrefs to {} not found, please set type in ida view".format(name))
                    return 1
                #print(xrefs[0], hex(xrefs[0].frm), method_offset)
                
                func_ea = read_ptr(xrefs[0].frm + method_offset)
                #print(xrefs[0], hex(xrefs[0].frm), method_offset, xrefs[0].frm + method_offset, hex(func_ea))
                if func_ea:
                    idaapi.open_pseudocode(func_ea, 0)
                    real_func_name = idaapi.get_name(func_ea)
                    demangled_name = convert_funcname_to_valid(real_func_name)
                    if demangled_name and demangled_name != struc_func_name:
                        print("changing name in structure from '{}' to '{}'".format(struc_func_name, demangled_name))
                        idc.set_member_name(struc_id, method_offset, demangled_name)
                    return 0

            return 1

def get_member_name(tinfo, offset):
    udt_member = idaapi.udt_member_t()
    udt_member.offset = offset * 8
    tinfo.find_udt_member(udt_member, idaapi.STRMEM_OFFSET)
    return udt_member.name
    
    
def read_ptr(ea):
    if EA64:
        return idaapi.get_qword(ea)
    return idaapi.get_dword(ea)

hx_callback_manager.register(idaapi.hxe_double_click, MemberDoubleClick())
hx_callback_manager.initialize()
