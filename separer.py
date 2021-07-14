import headers
from headers import *


class Separer:
    def __init__(self, path: str):
        exe = open(path, 'rb')
        offset = 0
        self.DOS_header = DOS_header(exe.read(DOS_HEADER_LENGTH))
        offset += DOS_HEADER_LENGTH
        if bytes(self.DOS_header.e_magic) != b'MZ':
            raise Exception('The file isn\'t a executable.')
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
