import idaapi
import idautils
from collections import defaultdict

EA64 = idaapi.get_inf_structure().is_64bit()
EA_SIZE = 8 if EA64 else 4

#hx_callback_manager.finalize()
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
                print("2")
                vtable_tinfo = item.e.x.type
                if vtable_tinfo.is_ptr():
                    vtable_tinfo = vtable_tinfo.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.m

                #func_name = get_member_name(vtable_tinfo, method_offset)
                name = str(vtable_tinfo)
                #print(type(vtable_tinfo))
                sid = idc.get_name_ea_simple(name)
                #print(sid)
                
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
