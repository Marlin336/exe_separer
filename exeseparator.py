import struct
import os

# type_size
BYTE = 1
WORD = 2
DWORD = 4
QWORD = 8


def from_little_endian(string):
    length = len(string)
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


def to_little_endian(data, length):
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
    return struct.pack('<' + str_len, data)


def get_name_from_rsrc_id(_id):
    if _id == 1:
        return 'CURSOR'
    elif _id == 2:
        return 'BITMAP'
    elif _id == 3:
        return 'ICON'
    elif _id == 4:
        return 'MENU'
    elif _id == 5:
        return 'DIALOG'
    elif _id == 6:
        return 'STRING_TABLE'
    elif _id == 7:
        return 'FONTDIR'
    elif _id == 8:
        return 'FONT'
    elif _id == 9:
        return 'ACCELERATOR'
    elif _id == 10:
        return 'RCDATA'
    elif _id == 11:
        return 'MESSAGE_TABLE'
    elif _id == 12:
        return 'GROUP_CURSOR'
    elif _id == 14:
        return 'GROUP_ICON'
    elif _id == 16:
        return 'VERSION_INFO'
    elif _id == 17:
        return 'DLGINCLUDE'
    elif _id == 19:
        return 'PLUGPLAY'
    elif _id == 20:
        return 'VXD'
    elif _id == 21:
        return 'ANICURSOR'
    elif _id == 22:
        return 'ANIICON'
    elif _id == 24:
        return 'MANIFEST'
    else:
        return _id


def get_name(name_field, content, is_type=False):
    if name_field & int('80000000', 16):
        name_offset = name_field & int('7FFFFFFF', 16)
        name_size = from_little_endian(content[name_offset:name_offset + WORD])
        name_offset += WORD
        name = list()
        for char in range(name_size):
            name.append(from_little_endian(content[name_offset:name_offset + WORD]))
            name_offset += WORD
        return bytes(name).decode('UTF-8')
    else:
        if is_type:
            return get_name_from_rsrc_id(name_field)
        else:
            return name_field


def get_dir(content, offset, curr_node: list, is_type=False):
    header = dict()
    header['char'] = from_little_endian(content[offset:offset + DWORD])
    offset += DWORD
    header['td_stamp'] = from_little_endian(content[offset:offset + DWORD])
    offset += DWORD
    header['maj_ver'] = from_little_endian(content[offset:offset + WORD])
    offset += WORD
    header['min_ver'] = from_little_endian(content[offset:offset + WORD])
    offset += WORD
    header['num_of_named_ent'] = from_little_endian(content[offset:offset + WORD])
    offset += WORD
    header['num_of_id_ent'] = from_little_endian(content[offset:offset + WORD])
    offset += WORD
    for child_num in range(header['num_of_id_ent'] + header['num_of_named_ent']):
        dir_name = get_name(from_little_endian(content[offset:offset + DWORD]), content, is_type)
        offset += DWORD
        dir_offset = from_little_endian(content[offset:offset + DWORD])
        offset += DWORD
        curr_node.append([dir_name, dir_offset, []])


def get_data(content, offset, curr_node: list, virtual_address):
    header = dict()
    header['offset'] = (from_little_endian(content[offset:offset + DWORD]) - virtual_address)
    offset += DWORD
    header['size'] = from_little_endian(content[offset:offset + DWORD])
    offset += DWORD
    header['code_page'] = from_little_endian(content[offset:offset + DWORD])
    offset += DWORD
    # reserved
    offset += DWORD
    curr_node[2] = content[header['offset']:header['offset'] + header['size']]


# Headers' length
DOS_HEADER_LENGTH = 64
DOS_STUB_LENGTH = int()
FILE_HEADER_LENGTH = 20
OPTIONAL_HEADER_LENGTH = int()
DATA_DIRECTORY_LENGTH = int()
SECTION_DATA_LENGTH = 40


def fill_fields(class_, content, fields):
    """
    Fill fields of the class_ header, using content data and creating fields
    :param class_: the instance of the class that represents the header
    :param content: byte-string from an executable file that contains necessary data
    :param fields: list of names of fields that will be added in class_
    :return: None
    """
    offset = 0
    for item in fields:
        if len(item) == 2:
            exec(f'class_.{item[0]} = content[offset:offset+{item[1]}]')
            exec(f'class_.{item[0]} = from_little_endian(class_.{item[0]})')
            offset += item[1]
        else:
            exec(f'class_.{item[0]} = list()')
            for elem in range(item[2]):
                exec(f'class_.{item[0]}.append(content[offset+elem*{item[1]}:offset+(elem+1)*{item[1]}])')
                exec(f'class_.{item[0]}[-1] = from_little_endian(class_.{item[0]}[elem])')
            offset += item[1] * item[2]


class DOSHeader:
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


class DOSStub:
    """
    DOS-stub executes when the application is running on DOS-system
    """

    def __init__(self, content):
        self.content = content


class PESign:
    def __init__(self, content):
        self.value = content[:DWORD]


class FileHeader:
    def __init__(self, content):
        fields = (['machine', WORD], ['number_of_sections', WORD], ['timedate_stamp', DWORD],
                  ['pointer_to_symbol_table', DWORD], ['number_of_symbols', DWORD],
                  ['size_of_optional_header', WORD], ['characteristics', WORD])
        fill_fields(self, content, fields)
        global OPTIONAL_HEADER_LENGTH
        OPTIONAL_HEADER_LENGTH = self.size_of_optional_header


class OptionalHeader:
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
                                        'address': from_little_endian(address),
                                        'size': from_little_endian(size)})


class SectionData:
    def __init__(self, content):
        fields = (['name', BYTE, 8], ['physical_address', DWORD], ['virtual_address', DWORD],
                  ['size_of_raw_data', DWORD], ['pointer_to_raw_data', DWORD], ['pointer_to_relocations', DWORD],
                  ['pointer_to_linenumbers', DWORD], ['number_of_relocations', WORD], ['number_of_linenumbers', WORD],
                  ['characteristics', DWORD])
        fill_fields(self, content, fields)


class ExeSeparator:
    def __init__(self, file_name: str):
        self.file_name = file_name
        exe = open(file_name, 'rb')
        offset = 0
        self.DOS_header = DOSHeader(exe.read(DOS_HEADER_LENGTH))
        offset += DOS_HEADER_LENGTH
        if bytes(self.DOS_header.e_magic) != b'MZ':
            raise Exception('The file isn\'t an executable.')
        self.DOS_stub = DOSStub(exe.read(DOS_STUB_LENGTH))
        offset += DOS_STUB_LENGTH
        self.PE_sign = PESign(exe.read(DWORD))
        offset += DWORD
        if bytes(self.PE_sign.value) != b'PE\x00\x00':
            raise Exception('The file isn\'t a portable executable.')
        self.File_header = FileHeader(exe.read(FILE_HEADER_LENGTH))
        offset += FILE_HEADER_LENGTH
        self.Optional_header = OptionalHeader(exe.read(OPTIONAL_HEADER_LENGTH))
        offset += OPTIONAL_HEADER_LENGTH
        self.Section_table = list()
        for sect_num in range(self.File_header.number_of_sections):
            self.Section_table.append(SectionData(exe.read(SECTION_DATA_LENGTH)))
            offset += SECTION_DATA_LENGTH
        self.Section_content = list()
        for sect_num in range(self.File_header.number_of_sections):
            start = self.Section_table[sect_num].pointer_to_raw_data
            sect_len = self.Section_table[sect_num].size_of_raw_data
            exe.seek(start)
            self.Section_content.append(exe.read(sect_len))
        # analyzing rsrc section
        if b'.rsrc\x00\x00\x00' in [bytes(item.name) for item in self.Section_table]:
            sect_num = [bytes(item.name) for item in self.Section_table].index(b'.rsrc\x00\x00\x00')
            self.rsrc_section = RsrcSection(self, sect_num)

    def get_sections(self):
        os.mkdir(f'{self.file_name}.sections')
        os.chdir(f'{self.file_name}.sections')
        for sect_num in range(len(self.Section_table)):
            name = bytes([x for x in self.Section_table[sect_num].name if x != 0]).decode('utf-8')
            open(name, 'wb').write(self.Section_content[sect_num])

    def get_resources(self):
        self.rsrc_section.get_directories()

    def get_icons(self):
        self.rsrc_section.get_icon()

    def get_cursors(self):
        self.rsrc_section.get_cursor()


class RsrcSection:
    def __init__(self, parent: ExeSeparator, sect_num):
        self.parent = parent
        content = parent.Section_content[sect_num]
        self.dir_tree = list()
        get_dir(content, 0, self.dir_tree, True)
        for d_type in self.dir_tree:
            d_type[1] = d_type[1] & int('7FFFFFFF', 16)
            get_dir(content, d_type[1], d_type[2])
        for d_type in self.dir_tree:
            for d_name in d_type[2]:
                d_name[1] = d_name[1] & int('7FFFFFFF', 16)
                get_dir(content, d_name[1], d_name[2])
        for d_type in self.dir_tree:
            for d_name in d_type[2]:
                for d_lang in d_name[2]:
                    get_data(content, d_lang[1], d_lang, parent.Section_table[sect_num].virtual_address)
        pass

    def get_directories(self):
        sdir_name = dir_name = f'{self.parent.file_name}.rsrc'
        num = 0
        while os.path.exists(dir_name):
            dir_name = f'{sdir_name}_{num}'
            num += 1
        os.mkdir(dir_name)
        os.chdir(dir_name)
        for d_type in self.dir_tree:
            os.mkdir(str(d_type[0]))
        for d_type in self.dir_tree:
            os.chdir(str(d_type[0]))
            for d_name in d_type[2]:
                os.mkdir(str(d_name[0]))
            os.chdir('..')
        for d_type in self.dir_tree:
            os.chdir(d_type[0])
            for d_name in d_type[2]:
                os.chdir(str(d_name[0]))
                for d_lang in d_name[2]:
                    f_in = open(str(d_lang[0]), 'wb')
                    f_in.write(d_lang[2])
                    f_in.close()
                os.chdir('..')
            os.chdir('..')

    def get_icon(self):
        if 'GROUP_ICON' not in [item[0] for item in self.dir_tree] or 'ICON' not in [item[0] for item in self.dir_tree]:
            raise AttributeError('There are no icons in the executable file')
        sdir_name = dir_name = f'{self.parent.file_name}.icons'
        num = 0
        while os.path.exists(dir_name):
            dir_name = f'{sdir_name}_{num}'
            num += 1
        ico_hdr = [item for item in self.dir_tree if item[0] == 'GROUP_ICON'][0][2]
        icons = [item for item in self.dir_tree if item[0] == 'ICON'][0][2]
        os.mkdir(dir_name)
        os.chdir(dir_name)
        icon_name = [item[0] for item in ico_hdr]
        icon_lang = [item[2] for item in ico_hdr]
        ico_hdr = list()
        for item in icon_lang:
            ico_hdr.append([i[2] for i in item])
        icons = [item[2][0][2] for item in icons]
        for i_name in range(len(icon_name)):
            os.mkdir(str(icon_name[i_name]))
            os.chdir(str(icon_name[i_name]))
            for icon_hdr_num in range(len(ico_hdr[i_name])):
                offset = 0
                # reserved
                offset += WORD
                data_type = from_little_endian(ico_hdr[i_name][icon_hdr_num][offset:offset + WORD])
                offset += WORD
                img_count = from_little_endian(ico_hdr[i_name][icon_hdr_num][offset:offset + WORD])
                offset += WORD
                res = bytes()
                res += to_little_endian(0, WORD)
                res += to_little_endian(data_type, WORD)
                res += to_little_endian(img_count, WORD)
                last_ico_size = 0
                img_index = list()
                for elem in range(img_count):
                    # 0 == 256
                    # width
                    res += ico_hdr[i_name][icon_hdr_num][offset:offset + BYTE]
                    offset += BYTE
                    # 0 == 256
                    # height
                    res += ico_hdr[i_name][icon_hdr_num][offset:offset + BYTE]
                    offset += BYTE
                    # color count
                    res += ico_hdr[i_name][icon_hdr_num][offset:offset + BYTE]
                    offset += BYTE
                    # reserved
                    res += to_little_endian(0, BYTE)
                    offset += BYTE
                    # planes
                    res += ico_hdr[i_name][icon_hdr_num][offset:offset + WORD]
                    offset += WORD
                    # bits per pixel
                    res += ico_hdr[i_name][icon_hdr_num][offset:offset + WORD]
                    offset += WORD
                    # size in bytes
                    size_mem = from_little_endian(ico_hdr[i_name][icon_hdr_num][offset:offset + DWORD])
                    res += ico_hdr[i_name][icon_hdr_num][offset:offset + DWORD]
                    offset += DWORD
                    # image index in ICON directory
                    img_index.append(from_little_endian(ico_hdr[i_name][icon_hdr_num][offset:offset + WORD]) - 1)
                    offset += WORD
                    # data_offset
                    file_offset = WORD * 3
                    file_offset += (BYTE * 4 + WORD * 2 + DWORD * 2) * img_count + last_ico_size
                    res += to_little_endian(file_offset, DWORD)
                    last_ico_size += size_mem
                for ico in range(img_count):
                    res += icons[img_index[ico]]
                with open(f'{icon_lang[i_name][icon_hdr_num][0]}.ico', 'wb') as out_file:
                    out_file.write(res)
            os.chdir('..')

    def get_cursor(self):
        if 'GROUP_CURSOR' not in [item[0] for item in self.dir_tree] or \
                'CURSOR' not in [item[0] for item in self.dir_tree]:
            raise AttributeError('There are no icons in the executable file')
        sdir_name = dir_name = f'{self.parent.file_name}.cursors'
        num = 0
        while os.path.exists(dir_name):
            dir_name = f'{sdir_name}_{num}'
            num += 1
        cur_hdr = [item for item in self.dir_tree if item[0] == 'GROUP_CURSOR'][0][2]
        cursors = [item for item in self.dir_tree if item[0] == 'CURSOR'][0][2]
        os.mkdir(dir_name)
        os.chdir(dir_name)
        cur_name = [item[0] for item in cur_hdr]
        cur_lang = [item[2] for item in cur_hdr]
        cur_hdr = list()
        for item in cur_lang:
            cur_hdr.append([i[2] for i in item])
        cursors = [item[2][0][2] for item in cursors]
        for c_name in range(len(cur_name)):
            os.mkdir(str(cur_name[c_name]))
            os.chdir(str(cur_name[c_name]))
            for icon_hdr_num in range(len(cur_hdr[c_name])):
                offset = 0
                # reserved
                offset += WORD
                data_type = from_little_endian(cur_hdr[c_name][icon_hdr_num][offset:offset + WORD])
                offset += WORD
                img_count = from_little_endian(cur_hdr[c_name][icon_hdr_num][offset:offset + WORD])
                offset += WORD
                res = bytes()
                res += to_little_endian(0, WORD)
                res += to_little_endian(data_type, WORD)
                res += to_little_endian(img_count, WORD)
                last_cur_size = 0
                img_index = list()
                for elem in range(img_count):
                    # width
                    w = from_little_endian(cur_hdr[c_name][icon_hdr_num][offset:offset + WORD])
                    offset += WORD
                    # height
                    h = from_little_endian(cur_hdr[c_name][icon_hdr_num][offset:offset + WORD])
                    offset += WORD
                    unknown = from_little_endian(cur_hdr[c_name][icon_hdr_num][offset:offset + DWORD])
                    offset += DWORD
                    if unknown != int('40', 16):
                        h = h // 2
                    # size in bytes
                    size_mem = from_little_endian(cur_hdr[c_name][icon_hdr_num][offset:offset + DWORD]) - 4
                    offset += DWORD
                    # image index in CURSOR directory
                    img_index.append(from_little_endian(cur_hdr[c_name][icon_hdr_num][offset:offset + WORD]) - 1)
                    offset += WORD
                    # data_offset
                    file_offset = WORD * 3
                    file_offset += (BYTE * 4 + WORD * 2 + DWORD * 2) * img_count + last_cur_size
                    h_coordinate = from_little_endian(cursors[img_index[-1]][:2])
                    v_coordinate = from_little_endian(cursors[img_index[-1]][2:4])

                    # cursor assembling
                    res += to_little_endian(w, BYTE)
                    res += to_little_endian(h, BYTE)
                    res += to_little_endian(0, BYTE)
                    res += to_little_endian(0, BYTE)
                    res += to_little_endian(h_coordinate, WORD)
                    res += to_little_endian(v_coordinate, WORD)
                    res += to_little_endian(size_mem, DWORD)
                    res += to_little_endian(file_offset, DWORD)
                    last_cur_size += size_mem
                for ico in range(img_count):
                    res += cursors[img_index[ico]][4:]
                with open(f'{cur_lang[c_name][icon_hdr_num][0]}.cur', 'wb') as out_file:
                    out_file.write(res)
            os.chdir('..')
