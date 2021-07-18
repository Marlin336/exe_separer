from func import from_little_endian, BYTE, WORD, DWORD

# Headers' length
DOS_HEADER_LENGTH = 64
DOS_STUB_LENGTH = None
FILE_HEADER_LENGTH = 20
OPTIONAL_HEADER_LENGTH = None
DATA_DIRECTORY_LENGTH = None
SECTION_DATA_LENGTH = 40


def fill_fields(cls, content, fields):
    """
    Fill fields of the _cls_ header, using _content_ data and creating _fields_ fields
    :param cls: the instance of the class that represents the header
    :param content: byte-string from an executable file that contains necessary data
    :param fields: list of names of fields that will be added in _cls_
    :return: None
    """
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
    """
    WORD    e_magic;         // Magic number
    WORD    e_cblp;          // Bytes on last page of file
    WORD    e_cp;            // Pages in file
    WORD    e_crlc;          // Relocations
    WORD    e_cparhdr;       // Size of header in paragraphs
    WORD    e_minalloc;      // Minimum extra paragraphs needed
    WORD    e_maxalloc;      // Maximum extra paragraphs needed
    WORD    e_ss;            // Initial (relative) SS value
    WORD    e_sp;            // Initial SP value
    WORD    e_csum;          // Checksum
    WORD    e_ip;            // Initial IP value
    WORD    e_cs;            // Initial (relative) CS value
    WORD    e_lfarlc;        // File address of relocation table
    WORD    e_ovno;          // Overlay number
    WORD    e_res[4];        // Reserved words
    WORD    e_oemid;         // OEM identifier (for e_oeminfo)
    WORD    e_oeminfo;       // OEM information; e_oemid specific
    WORD    e_res2[10];      // Reserved words
    DWORD   e_lfanew;        // File address of new exe header
    """
    def __init__(self, content):
        fields = (['e_magic', BYTE, 2], ['e_cblp', WORD], ['e_cp', WORD], ['e_crlc', WORD],
                  ['e_cparhdr', WORD], ['e_minalloc', WORD], ['e_maxalloc', WORD], ['e_ss', WORD],
                  ['e_sp', WORD], ['e_csum', WORD], ['e_ip', WORD], ['e_cs', WORD],
                  ['e_lfarlc', WORD], ['e_ovno', WORD], ['e_res', WORD, 4], ['e_oemid', WORD],
                  ['e_oeminfo', WORD], ['e_res2', WORD, 10], ['e_lfanew', DWORD])
        fill_fields(self, content, fields)
        global DOS_STUB_LENGTH
        DOS_STUB_LENGTH = self.e_lfanew - DOS_HEADER_LENGTH


class DOS_stub:
    """
    DOS-stub executes when the application is running on DOS-system
    """
    def __init__(self, content):
        self.content = content


class PE_sign:
    def __init__(self, content):
        self.value = content[:DWORD]


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
        data_directory_content = content[96:]
        dir_names = ['EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION', 'SECURITY', 'BASERELOC', 'DEBUG',
                     'ARCHITECTURE', 'GLOBALPTR', 'TLS', 'LOAD_CONFIG', 'BOUND_IMPORT' 'IAT',
                     'DELAY_IMPORT', 'COM_DESCRIPTOR'] + ['UNKNOWN'] * 2
        for c in range(self.number_of_rva_and_sizes):
            address = data_directory_content[c * DWORD * 2:c * DWORD * 2 + DWORD]
            size = data_directory_content[c * DWORD * 2 + DWORD:c * DWORD * 2 + DWORD + DWORD]
            self.data_directory.append({'name': dir_names[c],
                                        'address': from_little_endian(address, DWORD),
                                        'size': from_little_endian(size, DWORD)})


class Section_data:
    def __init__(self, content):
        fields = (['name', BYTE, 8], ['physical_address', DWORD], ['virtual_address', DWORD],
                  ['size_of_raw_data', DWORD], ['pointer_to_raw_data', DWORD], ['pointer_to_relocations', DWORD],
                  ['pointer_to_linenumbers', DWORD], ['number_of_relocations', WORD], ['number_of_linenumbers', WORD],
                  ['characteristics', DWORD])
        fill_fields(self, content, fields)
