import idaapi
import ida_ida
import re
import idc
import collections

NULL_POSSIBLE_IN_VTABLE = False
DEMUNGLE_NAME = False
BAD_C_NAME_PATTERN = re.compile('[^a-zA-Z_0-9:]')
try:
    EA64 = idaapi.get_inf_structure().is_64bit()
except:
    EA64 = None

if EA64 is not None:
    EA_SIZE = 8 if EA64 else 4
else:
    EA_SIZE = 4 if ida_ida.inf_is_32bit_exactly() else 8

def demangled_name_to_c_str(name):
    """
    Removes or replaces characters from demangled symbol so that it was possible to create legal C structure from it
    """
        
    if not BAD_C_NAME_PATTERN.findall(name):
        return name

    # FIXME: This is very ugly way to find and replace illegal characters
    idx = name.find("::operator")
    if idx >= 0:
        idx += len("::operator")
        if idx == len(name) or name[idx].isalpha():
            # `operator` is part of name of some name and not a keyword
            pass
        elif name[idx:idx + 2] == "==":
            name = name.replace("operator==", "operator_EQ_")
        elif name[idx:idx + 2] == "!=":
            name = name.replace("operator!=", "operator_NEQ_")
        elif name[idx] == "=":
            name = name.replace("operator=", "operator_ASSIGN_")
        elif name[idx:idx + 2] == "+=":
            name = name.replace("operator+=", "operator_PLUS_ASSIGN_")
        elif name[idx:idx + 2] == "-=":
            name = name.replace("operator-=", "operator_MINUS_ASSIGN_")
        elif name[idx:idx + 2] == "*=":
            name = name.replace("operator*=", "operator_MUL_ASSIGN_")
        elif name[idx:idx + 2] == "/=":
            name = name.replace("operator/=", "operator_DIV_ASSIGN_")
        elif name[idx:idx + 2] == "%=":
            name = name.replace("operator%=", "operator_MODULO_DIV_ASSIGN_")
        elif name[idx:idx + 2] == "|=":
            name = name.replace("operator|=", "operator_OR_ASSIGN_")
        elif name[idx:idx + 2] == "&=":
            name = name.replace("operator&=", "operator_AND_ASSIGN_")
        elif name[idx:idx + 2] == "^=":
            name = name.replace("operator^=", "operator_XOR_ASSIGN_")
        elif name[idx:idx + 3] == "<<=":
            name = name.replace("operator<<=", "operator_LEFT_SHIFT_ASSIGN_")
        elif name[idx:idx + 3] == ">>=":
            name = name.replace("operator>>=", "operator_RIGHT_SHIFT_ASSIGN_")
        elif name[idx:idx + 2] == "++":
            name = name.replace("operator++", "operator_INC_")
        elif name[idx:idx + 2] == "--":
            name = name.replace("operator--", "operator_PTR_")
        elif name[idx:idx + 2] == "->":
            name = name.replace("operator->", "operator_REF_")
        elif name[idx:idx + 2] == "[]":
            name = name.replace("operator[]", "operator_IDX_")
        elif name[idx] == "*":
            name = name.replace("operator*", "operator_STAR_")
        elif name[idx:idx + 2] == "&&":
            name = name.replace("operator&&", "operator_LAND_")
        elif name[idx:idx + 2] == "||":
            name = name.replace("operator||", "operator_LOR_")
        elif name[idx] == "!":
            name = name.replace("operator!", "operator_LNOT_")
        elif name[idx] == "&":
            name = name.replace("operator&", "operator_AND_")
        elif name[idx] == "|":
            name = name.replace("operator|", "operator_OR_")
        elif name[idx] == "^":
            name = name.replace("operator^", "operator_XOR_")
        elif name[idx:idx + 2] == "<<":
            name = name.replace("operator<<", "operator_LEFT_SHIFT_")
        elif name[idx:idx + 2] == ">>":
            name = name.replace("operator>", "operator_GREATER_")
        elif name[idx:idx + 2] == "<=":
            name = name.replace("operator<=", "operator_LESS_EQUAL_")
        elif name[idx:idx + 2] == ">=":
            name = name.replace("operator>>", "operator_RIGHT_SHIFT_")
        elif name[idx] == "<":
            name = name.replace("operator<", "operator_LESS_")
        elif name[idx] == ">":
            name = name.replace("operator>=", "operator_GREATER_EQUAL_")
        elif name[idx] == "+":
            name = name.replace("operator+", "operator_ADD_")
        elif name[idx] == "-":
            name = name.replace("operator-", "operator_SUB_")
        elif name[idx] == "/":
            name = name.replace("operator/", "operator_DIV_")
        elif name[idx] == "%":
            name = name.replace("operator%", "operator_MODULO_DIV_")
        elif name[idx:idx + 2] == "()":
            name = name.replace("operator()", "operator_CALL_")
        elif name[idx: idx + 6] == " new[]":
            name = name.replace("operator new[]", "operator_NEW_ARRAY_")
        elif name[idx: idx + 9] == " delete[]":
            name = name.replace("operator delete[]", "operator_DELETE_ARRAY_")
        elif name[idx: idx + 4] == " new":
            name = name.replace("operator new", "operator_NEW_")
        elif name[idx: idx + 7] == " delete":
            name = name.replace("operator delete", "operator_DELETE_")
        elif name[idx:idx + 2] == "\"\" ":
            name = name.replace("operator\"\" ", "operator_LITERAL_")
        elif name[idx] == "~":
            name = name.replace("operator~", "operator_NOT_")
        elif name[idx] == ' ':
            pass
        else:
            raise AssertionError("Replacement of demangled string by c-string for keyword `operatorXXX` is not yet"
                                 "implemented ({}). You can do it by yourself or create an issue".format(name))

    name = name.replace("public:", "")
    name = name.replace("protected:", "")
    name = name.replace("private:", "")
    name = name.replace("~", "DESTRUCTOR_")
    name = name.replace("*", "_PTR")
    name = name.replace("<", "_LESSt_")
    name = name.replace(">", "_MOREt_")
    name = name.replace("::", "__")
    name = "_".join(filter(len, BAD_C_NAME_PATTERN.split(name)))
    return name

class ActionManager(object):
    def __init__(self):
        self.__actions = []

    def register(self, action):
        self.__actions.append(action)
        idaapi.register_action(
                idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
            )

    def initialize(self):
        pass

    def finalize(self):
        for action in self.__actions:
            idaapi.unregister_action(action.name)


action_manager = ActionManager()


class Action(idaapi.action_handler_t):
    """
    Convenience wrapper with name property allowing to be registered in IDA using ActionManager
    """
    description = None
    hotkey = None

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "HexRaysPyTools:" + type(self).__name__

    def activate(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

    def update(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError
        
SCORE_TABLE = dict((v, k) for k, v in enumerate(
    ['unsigned __int8 *', 'unsigned __int8', '__int8 *', '__int8', '_BYTE', '_BYTE *', '_BYTE **', 'const char **',
     'signed __int16', 'unsigned __int16', '__int16', 'signed __int16 *', 'unsigned __int16 *', '__int16 *',
     '_WORD *', '_WORD **', '_QWORD', '_QWORD *',
     'signed int*', 'signed int', 'unsigned int *', 'unsigned int', 'int **', 'char **', 'int *', 'void **',
     'int', '_DWORD *', 'char', '_DWORD', '_WORD', 'void *', 'char *']
))


def parse_vtable_name(address):
    name = idaapi.get_name(address)
    if idaapi.is_valid_typename(name):
        if name[0:3] == 'off':
            # off_XXXXXXXX case
            return "Vtable" + name[3:], False
        elif "table" in name or 'vtab' in name:
            return name, True
        print("[Warning] Weird virtual table name -", name)
        return "Vtable_" + name, False
    name = idc.demangle_name(idaapi.get_name(address), idc.get_inf_attr(idc.INF_SHORT_DN))
    assert name, "Virtual table must have either legal c-type name or mangled name"
    return demangled_name_to_c_str(name).replace("const_", "").replace("::_vftable", "_vtbl"), True

def to_hex(ea):
    """ Formats address so it could be double clicked at console """
    if EA64:
        return "0x{:016X}".format(ea)
    return "0x{:08X}".format(ea) 

def search_duplicate_fields(virt_funcs):
    # Returns list of lists with duplicate fields

    default_dict = collections.defaultdict(list)
    for idx, func in enumerate(virt_funcs):
        default_dict[func.name].append(idx)
    return [indices for indices in list(default_dict.values()) if len(indices) > 1]

def is_imported_ea(ea):
    if idc.get_segm_name(ea) == ".plt":
        return True
    return False

def get_procname():
    try:
        return idaapi.cvar.inf.procname
    except:
        pass
    return ida_ida.inf_get_procname()

def is_code_ea(ea):
    if get_procname() == "ARM":
        # In case of ARM code in THUMB mode we sometimes get pointers with thumb bit set
        flags = idaapi.get_full_flags(ea & -2)  # flags_t
    else:
        flags = idaapi.get_full_flags(ea)
    return idaapi.is_code(flags)


def get_ptr(ea):
    """ Reads ptr at specified address. """
    if EA64:
        return idaapi.get_64bit(ea)
    ptr = idaapi.get_32bit(ea)
    if get_procname() == "ARM":
        ptr &= -2    # Clear thumb bit
    return ptr
    
    
class AbstractMember:
    def __init__(self, offset, scanned_variable, origin):
        """
        Offset is the very very base of the structure
        Origin is from which offset of the base structure the variable have been scanned
        scanned_variable - information about context in which this variable was scanned. This is necessary for final
        applying type after packing or finalizing structure.

        :param offset: int
        :param scanned_variable: ScannedVariable
        :param origin: int
        """
        self.offset = offset
        self.origin = origin
        self.enabled = True
        self.is_array = False
        self.scanned_variables = {scanned_variable} if scanned_variable else set()
        self.tinfo = None

    def type_equals_to(self, tinfo):
        return self.tinfo.equals_to(tinfo)

    def switch_array_flag(self):
        self.is_array ^= True

    def activate(self, temp_struct):
        pass

    def set_enabled(self, enable):
        self.enabled = enable
        self.is_array = False

    def has_collision(self, other):
        if self.offset <= other.offset:
            return self.offset + self.size > other.offset
        return other.offset + other.size >= self.offset

    @property
    def score(self):
        """ More score of the member - it better suits as candidate for this offset """
        try:
            return SCORE_TABLE[self.type_name]
        except KeyError:
            if self.tinfo and self.tinfo.is_funcptr():
                return 0x1000 + len(self.tinfo.dstr())
            return 0xFFFF

    @property
    def type_name(self):
        return self.tinfo.dstr()

    @property
    def size(self):
        size = self.tinfo.get_size()
        return size if size != idaapi.BADSIZE else 1

    @property
    def font(self):
        return None

    def __repr__(self):
        return hex(self.offset) + ' ' + self.type_name

    def __eq__(self, other):
        """ I'm aware that it's dirty but have no time to refactor whole file to nice one """

        if self.offset == other.offset and self.type_name == other.type_name:
            self.scanned_variables |= other.scanned_variables
            return True
        return False

    __ne__ = lambda self, other: self.offset != other.offset or self.type_name != other.type_name
    __lt__ = lambda self, other: self.offset < other.offset or \
                                 (self.offset == other.offset and self.type_name < other.type_name)
    __le__ = lambda self, other: self.offset <= other.offset
    __gt__ = lambda self, other: self.offset > other.offset or \
                                 (self.offset == other.offset and self.type_name < other.type_name)
    __ge__ = lambda self, other: self.offset >= other.offset
 
END_NUMBER_PATTERN = re.compile(r"_[0-9]+[^a-zA-Z]*")
class VirtualFunction:
    def __init__(self, address, offset, class_name=""):
        self.address = address
        self.offset = offset
        self.class_name = class_name
        self.visited = False
        self.name = None
        self.get_name()
        print("Created virtual function {}".format(self.name))

    def get_ptr_tinfo(self):
        # print self.tinfo.dstr()
        ptr_tinfo = idaapi.tinfo_t()
        ptr_tinfo.create_ptr(self.tinfo)
        return ptr_tinfo

    def get_udt_member(self):
        udt_member = idaapi.udt_member_t()
        udt_member.type = self.get_ptr_tinfo()
        udt_member.offset = self.offset
        udt_member.name = self.name
        udt_member.size = EA_SIZE
        
        return udt_member

    def get_information(self):
        return [to_hex(self.address), self.name, self.tinfo.dstr()]

    def get_name(self):
        if self.name:
            return self.name
        name = idaapi.get_name(self.address)
        #if idaapi.is_valid_typename(name):
        #    return name
        
        if any([i in name for i in ["RefCounter"]]):
            name = None        
        
        if name is None:
            name = "gap_0x{}".format(self.offset)
            
        if "__" in name:
            name = name[name.index("__")+2:]
            
        if self.class_name:
            name = self.class_name + "_0x{:X}".format(self.offset) + "__" + name
        
        if DEMUNGLE_NAME:
            prefix=name[:name.index('_Z')] if name[:2]=='j_' and ('_Z' in name) else ""
            name = END_NUMBER_PATTERN.sub("", name)
            
            dname = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
            if dname:         
                name = demangled_name_to_c_str(dname)
            print("Name: {} Dname: {}".format(name, dname))
        
        
            self.name = prefix + name
        else:
            self.name = name
        self.name = self.name.replace(":", "_")
        return self.name
        
    def set_name(self, name):
        self.name = name
        
    def ida_set_name(self):
        if idaapi.get_name(self.address).startswith("sub"):
            idaapi.set_name(self.address, self.name, idaapi.SN_CHECK)
            print("Set func name at {} to {}".format(hex(self.offset), self.name))
    

    @property
    def tinfo(self):
        try:
            decompiled_function = idaapi.decompile(self.address)
            if decompiled_function and decompiled_function.type:
                return idaapi.tinfo_t(decompiled_function.type)
            return DUMMY_FUNC
        except idaapi.DecompilationFailure:
            pass
        print("[ERROR] Failed to decompile function at 0x{0:08X}".format(self.address))
        return DUMMY_FUNC

    def show_location(self):
        idaapi.open_pseudocode(self.address, 1)


class ImportedVirtualFunction(VirtualFunction):
    def __init__(self, address, offset, class_name=""):
        VirtualFunction.__init__(self, address, offset, class_name=class_name)

    @property
    def tinfo(self):
        print("[INFO] Ignoring import function at 0x{0:08X}".format(self.address))
        tinfo = idaapi.tinfo_t()
        if idaapi.guess_tinfo(tinfo, self.address):
            return tinfo
        return DUMMY_FUNC

    def show_location(self):
        idaapi.jumpto(self.address)

PVOID_TINFO = idaapi.tinfo_t()
VOID_TINFO = idaapi.tinfo_t(idaapi.BT_VOID)
PVOID_TINFO.create_ptr(VOID_TINFO)
func_data = idaapi.func_type_data_t()
func_data.rettype = PVOID_TINFO
func_data.cc = idaapi.CM_CC_UNKNOWN
DUMMY_FUNC = idaapi.tinfo_t()
DUMMY_FUNC.create_func(func_data, idaapi.BT_FUNC)

class VirtualTable(AbstractMember):

    def __init__(self, offset, address, scanned_variable=None, origin=0):
        AbstractMember.__init__(self, offset + origin, scanned_variable, origin)
        self.address = address
        self.virtual_functions = []
        self.name = "__vftable" + ("_{0:X}".format(self.offset) if self.offset else "")
        self.vtable_name, self.have_nice_name = parse_vtable_name(address)
        if "vtab" in self.vtable_name:
            self.class_name = self.vtable_name[:self.vtable_name.index("_vtab")]
        else:
            self.class_name = ""
        print("Vtable name: {} class name: {} address: 0x{:X}".format(self.name, self.class_name, self.address))
        self.populate()

    def populate(self):
        address = self.address
        first = True
        while True:
            #check if next vtab after current
            
                
            ptr = get_ptr(address)
            if is_code_ea(ptr):
                self.virtual_functions.append(VirtualFunction(ptr, address - self.address, class_name=self.class_name))
            elif is_imported_ea(ptr):
                self.virtual_functions.append(ImportedVirtualFunction(ptr, address - self.address))
            elif ptr == 0:
                break
                
            print("populate: 0x{0:08X}".format(ptr))
            address += EA_SIZE
            
            # for first xref
            if 0 and idaapi.get_first_dref_to(address) != idaapi.BADADDR:
                break
        print("Vtable end at 0x{0:08X} ".format(address))       

    def create_tinfo(self):
        # print "(Virtual table) at address: 0x{0:08X} name: {1}".format(self.address, self.name)

        for duplicates in search_duplicate_fields(self.virtual_functions):
            first_entry_idx = duplicates.pop(0)
            print("[Warning] Found duplicate virtual functions", self.virtual_functions[first_entry_idx].name)
            for num, dup in enumerate(duplicates):
                self.virtual_functions[dup].set_name("{0}_{1}".format(self.virtual_functions[first_entry_idx].name, num + 1))
                print("set duplicate name {}".format(self.virtual_functions[dup].name))
        
        
        self.set_ida_names()
        
        udt_data = idaapi.udt_type_data_t()
        for idx, function in enumerate(self.virtual_functions):
            #if not function.name.startswith("sub"):
            #    idaapi.set_name(function.address, function.name, idaapi.SN_CHECK)
            #else:
            
            udt_data.push_back(function.get_udt_member())

        final_tinfo = idaapi.tinfo_t()
        if final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT):
            # print "\n\t(Final structure)\n" + idaapi.print_tinfo('\t', 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE
            #                                                      | idaapi.PRTYPE_SEMI, final_tinfo, self.name, None)
            return final_tinfo
        print("[ERROR] Virtual table creation failed")
        
    def set_ida_names(self):    
        for idx, function in enumerate(self.virtual_functions):
            function.ida_set_name()

    def import_to_structures(self, ask=False):
        """
        Imports virtual tables and returns tid_t of new structure

        :return: idaapi.tid_t
        """
        name = self.vtable_name + "_struct"
        cdecl_typedef = idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                                           self.create_tinfo(), name, None)
        if ask:
            cdecl_typedef = idaapi.ask_text(0x10000, cdecl_typedef, "The following new type will be created")
            if not cdecl_typedef:
                return
        previous_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, name)
        if previous_ordinal:
            print("[Info] Virtual table alredy add: previous_ordinal="+str( previous_ordinal))
            idaapi.del_numbered_type(idaapi.cvar.idati, previous_ordinal)
            ordinal = idaapi.idc_set_local_type(previous_ordinal, cdecl_typedef, idaapi.PT_TYP)
        else:
            ordinal = idaapi.idc_set_local_type(-1, cdecl_typedef, idaapi.PT_TYP)

        if ordinal:
            print("[Info] Virtual table " + name + " added to Local Types; ordinal="+str(ordinal))
            try:
                return idaapi.import_type(idaapi.cvar.idati, -1, name)
            except:
                pass
            return idc.import_type(idaapi.cvar.idati, name)
        else:
            print("[Error] Failed to create virtual table " + name)
            print("*" * 100)
            print(cdecl_typedef)
            print("*" * 100)

    def get_udt_member(self, offset=0):
        udt_member = idaapi.udt_member_t()
        tid = self.import_to_structures()
        if tid != idaapi.BADADDR:
            udt_member.name = self.name
            tmp_tinfo = idaapi.create_typedef(self.vtable_name)
            tmp_tinfo.create_ptr(tmp_tinfo)
            udt_member.type = tmp_tinfo
            udt_member.offset = self.offset - offset
            udt_member.size = EA_SIZE
        return udt_member

    def type_equals_to(self, tinfo):
        udt_data = idaapi.udt_type_data_t()
        if tinfo.is_ptr() and tinfo.get_pointed_object().get_udt_details(udt_data):
            if udt_data[0].type.is_funcptr():
                return True
        return False

    def switch_array_flag(self):
        pass

    
    @staticmethod
    def check_address(address):
        # Checks if given address contains virtual table. Returns True if more than 2 function pointers found
        # Also if table's addresses point to code in executable section, than tries to make functions at that addresses
        if is_code_ea(address):
            return False

        if not idaapi.get_name(address):
            return False

        functions_count = 0
        while True:
            func_address = get_ptr(address)
            # print "[INFO] Address 0x{0:08X}".format(func_address)
            if is_code_ea(func_address) or is_imported_ea(func_address):
                functions_count += 1
                address += EA_SIZE
            else:
                segment = idaapi.getseg(func_address)
                if segment and segment.perm & idaapi.SEGPERM_EXEC:
                    idc.del_items(func_address, 1, idaapi.DELIT_SIMPLE)
                    if idc.add_func(func_address):
                        functions_count += 1
                        address += EA_SIZE
                        continue
                #break
            if func_address == 0:
                print("End vtab at 0x{0:08X}".format(address))
                break
            idaapi.auto_wait()
        print("Function count = {}".format(functions_count))
        return functions_count

    @property
    def score(self):
        return 0x2000

    @property
    def type_name(self):
        return self.vtable_name + " *"

    @property
    def size(self):
        return EA_SIZE


class Member(AbstractMember):
    def __init__(self, offset, tinfo, scanned_variable, origin=0):
        AbstractMember.__init__(self, offset + origin, scanned_variable, origin)
        self.tinfo = tinfo
        self.name = "field_{0:X}".format(self.offset)

    def get_udt_member(self, array_size=0, offset=0):
        udt_member = idaapi.udt_member_t()
        udt_member.name = "field_{0:X}".format(self.offset - offset) if self.name[:6] == "field_" else self.name
        udt_member.type = self.tinfo
        if array_size:
            tmp = idaapi.tinfo_t(self.tinfo)
            tmp.create_array(self.tinfo, array_size)
            udt_member.type = tmp
        udt_member.offset = self.offset - offset
        udt_member.size = self.size
        return udt_member

    def activate(self, temp_struct):
        new_type_declaration = idaapi.ask_str(self.type_name, 0x100, "Enter type:")
        if new_type_declaration is None:
            return

        result = idc.parse_decl(new_type_declaration, 0)
        if result is None:
            return
        _, tp, fld = result
        tinfo = idaapi.tinfo_t()
        tinfo.deserialize(idaapi.cvar.idati, tp, fld, None)
        self.tinfo = tinfo
        self.is_array = False
 
class CreateVtable(Action):
    description = "Create Virtual Table"
    hotkey = "V"

    def __init__(self):
        super(CreateVtable, self).__init__()

    @staticmethod
    def check(ea):
        return ea != idaapi.BADADDR #and VirtualTable.check_address(ea)

    def activate(self, ctx):
        ea = ctx.cur_ea
        if self.check(ea):
            vtable = VirtualTable(0, ea)
            vtable.import_to_structures(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE


class RenameFuncs(Action):
    description = "Rename functions"
    hotkey = "W"

    def __init__(self):
        super(RenameFuncs, self).__init__()

    @staticmethod
    def check(ea):
        return ea != idaapi.BADADDR #and VirtualTable.check_address(ea)

    def activate(self, ctx):
        ea = ctx.cur_ea
        if self.check(ea):
            vtable = VirtualTable(0, ea)
            vtable.set_ida_names()

    def update(self, ctx):
        return idaapi.AST_ENABLE

action_manager.register(CreateVtable())
action_manager.register(RenameFuncs())
