import struct

# Headers' length
DOS_HEADER_LENGTH = 64
DOS_STUB_LENGTH = None
FILE_HEADER_LENGTH = 20
OPTIONAL_HEADER_LENGTH = 96
DATA_DIRECTORY_LENGTH = None


# type_size
BYTE = 1
WORD = 2
DWORD = 4
QWORD = 8


def from_little_endian(string, length):
    if length == 1:
        str_len = 'B'
    elif length == 2:
        str_len = 'H'
    elif length == 4:
        str_len = 'I'
    elif length == 8:
        str_len = 'Q'
    else:
        raise Exception('invalid byte-string length')
    return struct.unpack('<' + str_len, string)[0]


def fill_fields(cls, content, fields):
    offset = 0
    for item in fields:
        if item[2] == 1:
            exec(f'cls.{item[0]} = content[offset:offset+{item[1]}]')
        else:
            exec(f'cls.{item[0]} = list()')
            for elem in range(item[2]):
                exec(f'cls.{item[0]}.append(content[offset+elem*{item[1]}:offset+(elem+1)*{item[1]}])')
                exec(f'cls.{item[0]}[-1] = from_little_endian(cls.{item[0]}[elem], {item[1]})')
        if len(item) != 4 and item[2] == 1:
            exec(f'cls.{item[0]} = from_little_endian(cls.{item[0]}, {item[1]})')
        offset += item[1] * item[2]


class DOS_header:
    def __init__(self, content):
        fields = (['e_magic', WORD, 1, True], ['e_cblp', WORD, 1], ['e_cp', WORD, 1], ['e_crlc', WORD, 1],
                  ['e_cparhdr', WORD, 1], ['e_minalloc', WORD, 1], ['e_maxalloc', WORD, 1], ['e_ss', WORD, 1],
                  ['e_sp', WORD, 1], ['e_csum', WORD, 1], ['e_ip', WORD, 1], ['e_cs', WORD, 1],
                  ['e_lfarlc', WORD, 1], ['e_ovno', WORD, 1], ['e_res', WORD, 4], ['e_oemid', WORD, 1],
                  ['e_oeminfo', WORD, 1], ['e_res2', WORD, 10], ['e_lfanew', DWORD, 1])
        fill_fields(self, content, fields)
        global DOS_STUB_LENGTH
        DOS_STUB_LENGTH = self.e_lfanew - DOS_HEADER_LENGTH


# Unknown purposes of fields
class DOS_stub:
    def __init__(self, content):
        self.content = content


class PE_sign:
    def __init__(self, content):
        self.signature = content[0:DWORD]


class File_header:
    def __init__(self, content):
        fields = (['machine', WORD, 1], ['number_of_sections', WORD, 1], ['timedate_stamp', DWORD, 1],
                  ['pointer_to_symbol_table', DWORD, 1], ['number_of_symbols', DWORD, 1],
                  ['size_of_optional_header', WORD, 1], ['characteristics', WORD, 1])
        fill_fields(self, content, fields)
        global DATA_DIRECTORY_LENGTH
        DATA_DIRECTORY_LENGTH = self.size_of_optional_header - OPTIONAL_HEADER_LENGTH


class Optional_header:
    def __init__(self, content):
        fields = (['magic', WORD, 1], ['major_linker_version', BYTE, 1], ['minor_linker_version', BYTE, 1],
                  ['size_of_code', DWORD, 1], ['size_of_initialized_data', DWORD, 1],
                  ['size_of_uninitialized_data', DWORD, 1], ['address_of_entry_point', DWORD, 1],
                  ['base_of_code', DWORD, 1], ['base_of_data', DWORD, 1], ['image_base', DWORD, 1],
                  ['section_alignment', DWORD, 1], ['file_alignment', DWORD, 1],
                  ['major_operations_system_version', WORD, 1], ['minor_operations_system_version', WORD, 1],
                  ['major_image_version', WORD, 1], ['minor_image_version', WORD, 1],
                  ['major_subsystem_version', WORD, 1], ['minor_subsystem_version', WORD, 1],
                  ['win32_version_value', DWORD, 1], ['size_of_image', DWORD, 1], ['size_of_headers', DWORD, 1],
                  ['check_sum', DWORD, 1], ['subsystem', WORD, 1], ['dll_characteristics', WORD, 1],
                  ['size_of_stack_reserve', DWORD, 1], ['size_of_stack_commit', DWORD, 1],
                  ['size_of_heap_reserve', DWORD, 1], ['size_of_heap_commit', DWORD, 1], ['loader_flags', DWORD, 1],
                  ['number_of_rva_and_sizes', DWORD, 1])
        fill_fields(self, content, fields)
