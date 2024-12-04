import idautils
import re
import idaapi
import ctypes
import ida_nalt

VTAB_OFFSET = 0
EA64 = idaapi.get_inf_structure().is_64bit()
EA_SIZE = 8 if EA64 else 4
VOID_TINFO = idaapi.tinfo_t(idaapi.BT_VOID)
PVOID_TINFO = idaapi.tinfo_t()
PVOID_TINFO.create_ptr(VOID_TINFO)

DEFAULT_TYPE = idaapi.get_unk_type(EA_SIZE)
DEFAULT_NAME = "qword{:X}" if EA64 else "qword{:X}" 

class Aarch64Exception(Exception):
    pass

class Node:
    def __init__(self, name, size, addr, parrent, vtb):
        self.name = name
        self.size = size
        self.addr = addr
        self.vtb = vtb
        self.parrent = parrent
        self.child = []
    
    def __str__(self):
        addr = hex(self.addr) if self.addr is not None else "None"
        parrent = hex(self.parrent) if self.parrent is not None else "None"
        return "{}<{}, size=0x{:X}, parrent={}>".format(self.name, addr, self.size, parrent)
        
    def __repr__(self):
        return str(self)

def read_dword(ea):
    return int.from_bytes(idaapi.get_bytes(ea,4), byteorder='little')

def clear_output():
    form = idaapi.find_widget("Output window")
    idaapi.activate_widget(form, True)
    idaapi.process_ui_action("msglist:Clear")
    print('===[Extract_args]===')
    
clear_output()

def signExtend(val, is_64):
    is_64 = is_64 & 1
    shift = (32 * (is_64 + 1)) - 1
    while (val >> shift) == 0: shift -= 1
    shift += 1
    max_val = (1 << (32 * (is_64 + 1)))
    return (max_val - ((1 << shift))) | val
    

def is_adrp(insn: int):
    if (insn & 0x9f000000) != 0x90000000:
        return None
    rd = insn & 0x1f
    immlo = (insn >> 29) & 0x3
    immhi = (insn & 0x00FFFFE0) >> 3
    if (immhi >> 20) & 1:
        extended = signExtend((immhi | immlo) << 12, 1)
    else:
        extended = (immhi | immlo) << 12
    return (rd, ctypes.c_longlong(extended).value)
    
def is_add_immediate(insn: int):
    #shift[1] bit is reserve value or ADDG insn
    if (insn & 0x7f800000) != 0x11000000:
        return None
    is_64 = (insn >> 31) & 1
    rd = insn & 0x1F
    rn = (insn >> 5) & 0x1f
    shift = (insn >> 22) & 1
    imm12 = (insn & 0x003ffc00) >> 10
    return (rd, rn, imm12 << (12 * shift))
    
def is_adrl_at_ea(ea):
    adrp_tuple = is_adrp(read_dword(ea))
    if adrp_tuple is None: 
        return None
    
    add_tuple = is_add_immediate(read_dword(ea+4))
    if add_tuple is None: 
        return None
    
    if (adrp_tuple[0] != add_tuple[0]) or (adrp_tuple[0] != add_tuple[1]):
        return None
    
    page_offset = adrp_tuple[1]
    offset = add_tuple[2]
    curr_page = ea & ((1 << 64) - 0x1000)
    return (adrp_tuple[0], curr_page + page_offset + offset)
    
    
def find_adrl_rd(ea, rd, step=4, max=0x50):
    rd_variants = [rd]
    while max > 0:
        adrl = is_adrl_at_ea(ea)
        if adrl is not None and adrl[0] in rd_variants:
            return adrl[1]
        
        mov = is_mov_register_at_ea(ea)
        if mov is not None and mov[0] == rd:
            rd_variants.append(mov[1])
        
        ea += step
        max -= abs(step)
    return None
    
def is_movz(insn):
    if (insn & 0x7f800000) != 0x52800000:
        return None
    rd = insn & 0x1f
    imm16 = (insn & 0x1fffe0) >> 5
    hw = (insn >> 21) & 3
    is_64 = (insn >> 31) & 1
    if is_64 == 0 and hw > 1:
        raise Aarch64Exception("unknown movz params: sf={} hw={}".format(is_64, hw))
    shift = 16 * hw
    return (rd, imm16 << shift)

def is_movz_at_ea(ea):
    return is_movz(read_dword(ea))
    
#https://gist.github.com/xerub/c6936d219db8e6635d25
def HighestSetBit(N, imm):
	i = N - 1
	while i >= 0:
		if imm & (1 << i):
			return i
		i -= 1
	return -1

def ZeroExtendOnes(M, N):				# zero extend M ones to N width
	return (1 << M) - 1

def RORZeroExtendOnes(M, N, R):
	val = ZeroExtendOnes(M, N)
	return ((val >> R) & ((1 << (N - R)) - 1)) | ((val & ((1 << R) - 1)) << (N - R))

def Replicate(val, bits):
	ret = val
	shift = bits
	while shift < 64:				# XXX actually, it is either 32 or 64
		ret |= (val << shift)
		shift += bits
	return ret

def DecodeBitMasks(immN, imms, immr, immediate):
	len = HighestSetBit(7, (immN << 6) | (~imms & 0x3F))
	if len < 1:
		return None
	levels = ZeroExtendOnes(len, 6)
	if immediate and (imms & levels) == levels:
		return None
	S = imms & levels
	R = immr & levels
	esize = 1 << len
	return Replicate(RORZeroExtendOnes(S + 1, esize, R), esize)
    
def is_orr_immediate(insn):
    if (insn & 0x7f800000 ) != 0x32000000:
        return None
    is_64 = (insn >> 31) & 1
    N = (insn >> 22) & 1
    immr = (insn >> 16) & 0x3f
    imms = (insn >> 10) & 0x3f
    rd = insn & 0x1f
    rn = (insn >> 5) & 0x1f
    if is_64 == 0 and N != 0:
        raise Aarch64Exception("unknown orr_immediate params: sf={} N={}".format(is_64, N))
    decoded = DecodeBitMasks(N, imms, immr, True)
    decoded &= ((1 << (32 * (is_64 + 1))) - 1)
    return (rd, rn, decoded)
    
def is_orr_immediate_at_ea(ea):
    return is_orr_immediate(read_dword(ea))
    
def find_movz(ea, rd, step=4, max=0x50):
    while max > 0:
        movz = is_movz_at_ea(ea)
        if movz is not None and movz[0] == rd:
            return movz[1]
        orr_imm = is_orr_immediate_at_ea(ea)
        # (rd, xzr, val)
        if orr_imm is not None and orr_imm[1] == 31 and orr_imm[0] == rd:
            return orr_imm[2]
        ea += step
        max -= abs(step)
    return None
    
def is_mov_register(insn):
    #orr rd, xzr, rm, lsl0
    if (insn & 0x7f200000) != 0x2a000000:
        return None
    is_64 = (insn >> 31) & 1
    shift = (insn >> 22) & 3
    rm = (insn >> 16) & 0x1F
    rn = (insn >> 5) & 0x1F
    rd = (insn >> 0) & 0x1F
    imm6 = (insn >> 10) & 0x3F
    if rn != 31 or imm6 != 0 or shift != 0:
        return None
    return (rd, rm)

def is_mov_register_at_ea(ea):
    return is_mov_register(read_dword(ea))
    

def find_objects_by_create_func(ea):
    #find argument 1
    objs = []
    for xref in idautils.XrefsTo(ea):
        xref_adr = xref.frm
        func = idaapi.get_func(xref_adr)
        if func is not None:
            max = xref_adr - func.start_ea
        else:
            max = 0x50
        x0_adrl = find_adrl_rd(xref_adr, 0, step=-4, max=max)
        x1_adrl = find_adrl_rd(xref_adr, 1, step=-4, max=max)
        x2_adrl = find_adrl_rd(xref_adr, 2, step=-4, max=max)
        
        x8_adrl = find_adrl_rd(xref_adr, 8, step=4, max=max)
        
        movz_val = find_movz(xref_adr, 3, step=-4)
        if None not in [x1_adrl, movz_val]:
            str_size = ida_bytes.get_max_strlit_length(x1_adrl, ida_nalt.STRTYPE_C)
            obj_name = ida_bytes.get_strlit_contents(x1_adrl, str_size, ida_nalt.STRTYPE_C).decode()
            objs.append((obj_name, movz_val, x0_adrl, x2_adrl, x8_adrl))
            
            idaapi.set_name(func.start_ea, "{}_create".format(obj_name), 0x800)
            #print("object {} has size=0x{:X}".format(obj_name, movz_val))
        else:
            print("[W] Arguments for xref 0x{:X} not found: {}".format(xref_adr, [x0_adrl, x1_adrl, x2_adrl, movz_val]))
    return objs
            

def common_suffix(s1, s2):
    i,j = len(s1) - 1, len(s2) - 1
    while(s1[i] == s2[j]):
        i-=1
        j-=1
    return s2[j + 1:]      
   
def filter_duplicates(obj_list):
    f = {}
    for o in obj_list:
        if o.name not in f:
            f[o.name] = o
        else:
            if o.addr is not None:
                f[o.name] = o
    return list(f.values())
    
def filter_roots(roots):
    roots = filter_duplicates(roots)
    for r in roots:
        r.child = filter_roots(r.child)
    return roots
    
def create_objs_tree(objs):
    addresses = {}
    unknown = []
    roots = []
    for o in objs:
        obj = Node(*o)
        if obj.addr is not None:
            if obj.addr not in addresses:
                addresses[obj.addr] = obj
            else:
                print("duplicated obj: orig={} dup={}".format(addresses[obj.addr], str(obj)))
                if  addresses[obj.addr].size < obj.size:
                    addresses[obj.addr] = obj
        else:
            #print("Unknown object: {}".format(str(obj)))
            unknown.append(obj)
    
    unknown_parrents = {}
    for addr, obj in addresses.items(): 
        if obj.parrent is not None:
            if obj.parrent in addresses:
                addresses[obj.parrent].child.append(obj)
            else:
                print("Unknown parrent 0x{:x} for object {}".format(obj.parrent, obj, []))
                parrent = unknown_parrents.get(obj.parrent, None)
                if parrent is None:
                    parrent = Node( "parent_" + obj.name, obj.size, obj.parrent, None, None)
                    parrent.child.append(obj)
                else:
                    parrent.name = common_suffix(obj.name, parrent.name)
                    parrent.size = min(obj.size, unknown_parrents[obj.parrent].size)
                    parrent.child.append(obj)
        
        else:
            roots.append(obj)
    
    for obj in unknown:
        if obj.parrent is not None:
            if obj.parrent in addresses:
                addresses[obj.parrent].child.append(obj)
            else:
                print("Unknown parrent 0x{:x} for unknown object {}".format(obj.parrent, str(obj)))
                parrent = unknown_parrents.get(obj.parrent, None)
                if parrent is None:
                    parrent = Node( "parent_" + obj.name, obj.size, obj.parrent, None, None)
                    parrent.child.append(obj)
                else:
                    parrent.name = common_suffix(obj.name, parrent.name)
                    parrent.size = min(obj.size, unknown_parrents[obj.parrent].size)
                    parrent.child.append(obj)
        
        else:
            roots.append(obj)
    
    for addr, obj in unknown_parrents.items():
        roots.append(obj)
        addresses[addr] = obj
    
    roots = filter_roots(roots)
    return roots           
    
def get_udt_member(name, offset, tinfo, size):
    udt_member = idaapi.udt_member_t()
    udt_member.type = tinfo
    udt_member.offset = offset
    udt_member.name = name
    udt_member.size = size
    
    return udt_member
    
    
def create_and_import_structure(tinfo, name):
    print("Creating {}".format(name))
    cdecl_typedef = idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI, tinfo, name, None)
    previous_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, name)
    if previous_ordinal:
        print("    duplicate")
        idaapi.del_numbered_type(idaapi.cvar.idati, previous_ordinal)
        ordinal = idaapi.idc_set_local_type(previous_ordinal, cdecl_typedef, idaapi.PT_TYP)
    else:
        ordinal = idaapi.idc_set_local_type(-1, cdecl_typedef, idaapi.PT_TYP)
    if not ordinal:
        idaapi.ask_text(0x10000, cdecl_typedef, "The following new type not be created")
        return None
    idaapi.import_type(idaapi.cvar.idati, -1, name)
    return True
           
def create_class_body(obj, parent):
    #class body without vtab
    udt_data = idaapi.udt_type_data_t()
    
    start_offset = 0
    if parent is not None:
        pbody_tinfo = idaapi.create_typedef("{}_body".format(parent.name))
        udt_data.push_back(get_udt_member("_p", EA_SIZE, pbody_tinfo, parent.size - EA_SIZE))
        start_offset = parent.size - EA_SIZE
        
    for offset in range(start_offset, obj.size - EA_SIZE, EA_SIZE):
        udt_data.push_back(get_udt_member(DEFAULT_NAME.format(offset), offset, DEFAULT_TYPE, EA_SIZE))
    
    final_tinfo = idaapi.tinfo_t()
    if final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT):
        name = "{}_body".format(obj.name)
        if create_and_import_structure(final_tinfo, name):
            return name
        
    print("[ERROR] Body for {} not created".format(str(obj)))
    return None  
   
        
    
def create_class(obj, parent):
    '''
    each class has follow structure:
    struc cls_name{
        void* vtab;
        struc cls_name_body _ {
            fields[];
        };
    }
    or
    struc cls_name : parrent_name {
        void* vtab;
        struc cls_name_body{
            parrent_name_body _p;
            fields[];
        }
        
    }
    
    '''
    SET_ADDR_AND_OBJ_NAMES = True
    if SET_ADDR_AND_OBJ_NAMES:
        if obj.addr is not None:
            idaapi.set_name(obj.addr, "{}_metaobj".format(obj.name), idaapi.SN_FORCE)
        if obj.vtb is not None:
            idaapi.set_name(obj.vtb + VTAB_OFFSET, "{}_basevtab".format(obj.name), idaapi.SN_FORCE)


    print("creating object {}".format(str(obj)))
    udt_data = idaapi.udt_type_data_t()
    udt_data.push_back(get_udt_member("vtab", 0, PVOID_TINFO, EA_SIZE))
    
    body_name = create_class_body(obj, parent)
    if body_name is None:
        return None
    body_tinfo = idaapi.create_typedef(body_name)
    udt_data.push_back(get_udt_member("_", EA_SIZE, body_tinfo, obj.size-8))
    final_tinfo = idaapi.tinfo_t()
    if final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT):
        #obj.body_tinfo = final_tinfo
        if create_and_import_structure(final_tinfo, obj.name):
           return True
    
def create_child_req(obj):
    for c in obj.child:
        if create_class(c, obj) is None:
            return None
        create_child_req(c)

def create_all_objects(roots):
    for r in roots:
        if create_class(r, None) is None:
            return None
        create_child_req(r)
        
        
def kernelcache_create_classes(addr):
    """main function"""
    clear_output()
    objs = find_objects_by_create_func(addr)
    roots = create_objs_tree(objs)
    create_all_objects(roots)
