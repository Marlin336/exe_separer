import os
import headers
from headers import *


def get_name_from_rsrc_index(index):
    if index == 1:
        return 'CURSOR'
    elif index == 2:
        return 'BITMAP'
    elif index == 3:
        return 'ICON'
    elif index == 4:
        return 'MENU'
    elif index == 5:
        return 'DIALOG'
    elif index == 6:
        return 'STRING'
    elif index == 7:
        return 'FONTDIR'
    elif index == 8:
        return 'FONT'
    elif index == 9:
        return 'ACCELERATOR'
    elif index == 10:
        return 'RCDATA'
    elif index == 11:
        return 'MESSAGETABLE'
    elif index == 12:
        return 'GROUP_CURSOR'
    elif index == 13:
        return 'GROUP_ICON'
    elif index == 16:
        return 'VERSION'
    elif index == 17:
        return 'DLGINCLUDE'
    elif index == 19:
        return 'PLUGPLAY'
    elif index == 20:
        return 'VXD'
    elif index == 21:
        return 'ANICURSOR'
    elif index == 22:
        return 'ANIICON'
    else:
        return index


class Separer:
    def __init__(self, path: str):
        self.path = path
        exe = open(path, 'rb')
        offset = 0
        self.DOS_header = DOS_header(exe.read(DOS_HEADER_LENGTH))
        offset += DOS_HEADER_LENGTH
        if bytes(self.DOS_header.e_magic) != b'MZ':
            raise Exception('The file isn\'t an executable.')
        self.DOS_stub = DOS_stub(exe.read(headers.DOS_STUB_LENGTH))
        offset += headers.DOS_STUB_LENGTH
        self.PE_sign = PE_sign(exe.read(DWORD))
        offset += DWORD
        if bytes(self.PE_sign.signature) != b'PE\x00\x00':
            raise Exception('The file isn\'t a portable executable.')
        self.File_header = File_header(exe.read(FILE_HEADER_LENGTH))
        offset += FILE_HEADER_LENGTH
        self.Optional_header = Optional_header(exe.read(headers.OPTIONAL_HEADER_LENGTH))
        offset += headers.OPTIONAL_HEADER_LENGTH
        self.Section_table = list()
        for sect_num in range(self.File_header.number_of_sections):
            self.Section_table.append(Section_data(exe.read(SECTION_DATA_LENGTH)))
            offset += SECTION_DATA_LENGTH
        self.Section_content = list()
        for sect_num in range(self.File_header.number_of_sections):
            start = self.Section_table[sect_num].pointer_to_raw_data
            sect_len = self.Section_table[sect_num].size_of_raw_data
            exe.seek(start)
            self.Section_content.append(exe.read(sect_len))

    def extract_sections(self):
        os.mkdir(f'{self.path}.sections')
        os.chdir(f'{self.path}.sections')
        for sect_num in range(len(self.Section_table)):
            name = bytes([x for x in self.Section_table[sect_num].name if x != 0]).decode('utf-8')
            open(name, 'wb').write(self.Section_content[sect_num])

    def extract_icon(self):
        if b'.rsrc\x00\x00\x00' not in [bytes(item.name) for item in self.Section_table]:
            raise Exception('This PE has no .rsrc section.')
        else:
            sect_num = [bytes(item.name) for item in self.Section_table].index(b'.rsrc\x00\x00\x00')
        rsrc = self.Section_content[sect_num]
        offset = 0
        number_of_id_entries_ptr = int('0e', 16)
        number_of_id_entries = from_little_endian(rsrc[number_of_id_entries_ptr:number_of_id_entries_ptr + WORD], WORD)
        offset += number_of_id_entries_ptr + WORD
        dir_list = list()
        for dir_num in range(number_of_id_entries):
            name = get_name_from_rsrc_index(from_little_endian(rsrc[offset:offset + DWORD], DWORD))
            offset += DWORD
            data_offset = from_little_endian(rsrc[offset:offset + DWORD], DWORD)
            offset += DWORD
            dir_list.append({'name': name, 'offset': data_offset})
        pass
