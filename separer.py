import os
from headers import *
import headers
from rsrc_section import *


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
        if bytes(self.PE_sign.value) != b'PE\x00\x00':
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
        # analyzing rsrc section
        if b'.rsrc\x00\x00\x00' in [bytes(item.name) for item in self.Section_table]:
            sect_num = [bytes(item.name) for item in self.Section_table].index(b'.rsrc\x00\x00\x00')
            self.rsrc_section = rsrc_section(self.Section_content[sect_num],
                                             self.Section_table[sect_num].pointer_to_raw_data,
                                             self.Section_table[sect_num].virtual_address)
            pass

    def extract_sections(self):
        os.mkdir(f'{self.path}.sections')
        os.chdir(f'{self.path}.sections')
        for sect_num in range(len(self.Section_table)):
            name = bytes([x for x in self.Section_table[sect_num].name if x != 0]).decode('utf-8')
            open(name, 'wb').write(self.Section_content[sect_num])
