import headers
from headers import *


class Separer:
    def __init__(self, path: str):
        exe = open(path, 'rb')
        offset = 0
        self.DOS_header = DOS_header(exe.read(DOS_HEADER_LENGTH))
        offset += DOS_HEADER_LENGTH
        if self.DOS_header.e_magic != b'MZ':
            raise Exception('The file isn\'t a executable.')
        self.DOS_stub = DOS_stub(exe.read(headers.DOS_STUB_LENGTH))
        offset += headers.DOS_STUB_LENGTH
        self.PE_sign = PE_sign(exe.read(DWORD))
        offset += DWORD
        self.File_header = File_header(exe.read(FILE_HEADER_LENGTH))
        offset += FILE_HEADER_LENGTH
        self.Optional_header = Optional_header(exe.read(OPTIONAL_HEADER_LENGTH))
        print(headers.DATA_DIRECTORY_LENGTH)
