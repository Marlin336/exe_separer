import os
import headers
from headers import *


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
        for section_num in range(self.File_header.number_of_sections):
            self.Section_table.append(Section_data(exe.read(SECTION_DATA_LENGTH)))
            offset += SECTION_DATA_LENGTH
        self.Section_content = list()
        for section_num in range(self.File_header.number_of_sections):
            self.Section_content.append(exe.read(self.Section_table[section_num].size_of_raw_data))

    def extract_sections(self):
        os.mkdir(f'{self.path}.sections')
        os.chdir(f'{self.path}.sections')
        for sec_num in range(len(self.Section_table)):
            name = bytes([x for x in self.Section_table[sec_num].name if x != 0]).decode('utf-8')
            open(name, 'wb').write(self.Section_content[sec_num])
