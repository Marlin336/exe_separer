import struct

# Headers' length
DOS_HEADER_LENGTH = 64
DOS_STUB_LENGTH = None
FILE_HEADER_LENGTH = 20
OPTIONAL_HEADER_LENGTH = None
DATA_DIRECTORY_LENGTH = None
SECTION_DATA_LENGTH = 40


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
        if len(item) == 2:
            exec(f'cls.{item[0]} = content[offset:offset+{item[1]}]')
            exec(f'cls.{item[0]} = from_little_endian(cls.{item[0]}, {item[1]})')
            offset += item[1]
        else:
            exec(f'cls.{item[0]} = list()')
            for elem in range(item[2]):
                exec(f'cls.{item[0]}.append(content[offset+elem*{item[1]}:offset+(elem+1)*{item[1]}])')
                exec(f'cls.{item[0]}[-1] = from_little_endian(cls.{item[0]}[elem], {item[1]})')
            offset += item[1] * item[2]


class DOS_header:
    def __init__(self, content):
        fields = (['e_magic', BYTE, 2], ['e_cblp', WORD], ['e_cp', WORD], ['e_crlc', WORD],
                  ['e_cparhdr', WORD], ['e_minalloc', WORD], ['e_maxalloc', WORD], ['e_ss', WORD],
                  ['e_sp', WORD], ['e_csum', WORD], ['e_ip', WORD], ['e_cs', WORD],
                  ['e_lfarlc', WORD], ['e_ovno', WORD], ['e_res', WORD, 4], ['e_oemid', WORD],
                  ['e_oeminfo', WORD], ['e_res2', WORD, 10], ['e_lfanew', DWORD])
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
        fields = (['machine', WORD], ['number_of_sections', WORD], ['timedate_stamp', DWORD],
                  ['pointer_to_symbol_table', DWORD], ['number_of_symbols', DWORD],
                  ['size_of_optional_header', WORD], ['characteristics', WORD])
        fill_fields(self, content, fields)
        global OPTIONAL_HEADER_LENGTH
        OPTIONAL_HEADER_LENGTH = self.size_of_optional_header


class Optional_header:
    def __init__(self, content):
        fields = (['magic', WORD], ['major_linker_version', BYTE], ['minor_linker_version', BYTE],
                  ['size_of_code', DWORD], ['size_of_initialized_data', DWORD],
                  ['size_of_uninitialized_data', DWORD], ['address_of_entry_point', DWORD],
                  ['base_of_code', DWORD], ['base_of_data', DWORD], ['image_base', DWORD],
                  ['section_alignment', DWORD], ['file_alignment', DWORD], ['major_operations_system_version', WORD],
                  ['minor_operations_system_version', WORD], ['major_image_version', WORD],
                  ['minor_image_version', WORD], ['major_subsystem_version', WORD], ['minor_subsystem_version', WORD],
                  ['win32_version_value', DWORD], ['size_of_image', DWORD], ['size_of_headers', DWORD],
                  ['check_sum', DWORD], ['subsystem', WORD], ['dll_characteristics', WORD],
                  ['size_of_stack_reserve', DWORD], ['size_of_stack_commit', DWORD], ['size_of_heap_reserve', DWORD],
                  ['size_of_heap_commit', DWORD], ['loader_flags', DWORD], ['number_of_rva_and_sizes', DWORD])
        fill_fields(self, content, fields)
        self.data_directory = list()
        global DATA_DIRECTORY_LENGTH
        DATA_DIRECTORY_LENGTH = OPTIONAL_HEADER_LENGTH - 96
        data_directory_count = DATA_DIRECTORY_LENGTH // self.number_of_rva_and_sizes
        data_directory_content = content[96:]
        for c in range(data_directory_count):
            address = data_directory_content[c * DWORD * 2:c * DWORD * 2 + DWORD]
            size = data_directory_content[c * DWORD * 2 + DWORD:c * DWORD * 2 + DWORD + DWORD]
            self.data_directory.append(Image_data_directory(from_little_endian(address, DWORD),
                                                            from_little_endian(size, DWORD)))


class Image_data_directory:
    def __init__(self, address, size):
        self.address = address
        self.size = size


class Section_data:
    def __init__(self, content):
        fields = (['name', BYTE, 8], ['physical_address', DWORD], ['virtual_address', DWORD],
                  ['size_of_raw_data', DWORD], ['pointer_to_raw_data', DWORD], ['pointer_to_relocations', DWORD],
                  ['pointer_to_linenumbers', DWORD], ['number_of_relocations', WORD], ['number_of_linenumbers', WORD],
                  ['characteristics', DWORD])
        fill_fields(self, content, fields)
