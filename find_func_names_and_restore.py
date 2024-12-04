import idautils
import re
import idaapi


		
		
def func_signature_strings():
    func_pattern = re.compile(r"[\w\d_]+[ *]+([\w\d_]+)::([\w\d_]+)\(")
    for s in idautils.Strings():
        bin_string = ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype)
        string = bin_string.decode()
        match = func_pattern.match(string)
        if match:
            cls = match.group(1)
            fname = match.group(2)
            yield s.ea, string, cls, fname
    return None

def get_xrefs_func_addrs_by_ea(ea):
    funcs = set()
    for xref in idautils.XrefsTo(ea):
        xref_adr = xref.frm
        func = idaapi.get_func(xref_adr)
        if func is not None:
            funcs.add(func.start_ea)
        else:
            print("addr 0x{:X} hasn't xrefs from func")
    return funcs

def find_func_names():
    for ea, fullname, cls, fname in func_signature_strings():
        funcs = get_xrefs_func_addrs_by_ea(ea)
        funcname = "{}::{}".format(cls, fname)
        if len(funcs) > 1:
            print("function {} has more than 1 xrefs: {}".format(funcname, [hex(i) for i in funcs]))
        elif len(funcs) == 1:
            faddr = list(funcs)[0]
            curname = idaapi.get_name(faddr)
            if curname.startswith("sub_"):
                idaapi.set_name(faddr, funcname, idaapi.SN_FORCE)
                print("set name for 0x{:X}: {}".format(faddr, funcname))
            else:
                print("Function 0x{:X} already has name {} ( new '{}')".format(faddr, curname, funcname))
        else:
            print("String(0x{:X}) hasn't xrefs".format(ea))

find_func_names()   