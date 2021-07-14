import struct

# Headers' length
DOS_HEADER_LENGTH = 64
DOS_STUB_LENGTH = None

# type_size
BYTE = 1
SHORT = 2
INT = 4
LONG = 8


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


class DOS_header:
    def __init__(self, content):
        offset = 0
        fields = (['e_magic', SHORT, 1, True], ['e_cblp', SHORT, 1], ['e_cp', SHORT, 1], ['e_crlc', SHORT, 1],
                  ['e_cparhdr', SHORT, 1], ['e_minalloc', SHORT, 1], ['e_maxalloc', SHORT, 1], ['e_ss', SHORT, 1],
                  ['e_sp', SHORT, 1], ['e_csum', SHORT, 1], ['e_ip', SHORT, 1], ['e_cs', SHORT, 1],
                  ['e_lfarlc', SHORT, 1], ['e_ovno', SHORT, 1], ['e_res', SHORT, 4], ['e_oemid', SHORT, 1],
                  ['e_oeminfo', SHORT, 1], ['e_res2', SHORT, 10], ['e_lfanew', LONG, 1])
        for item in fields:
            if item[2] == 1:
                exec(f'self.{item[0]} = content[offset:offset+{item[1]}]')
            else:
                exec(f'self.{item[0]} = list()')
                for elem in range(item[2]):
                    exec(f'self.{item[0]}.append(content[offset+elem*{item[1]}:offset+(elem+1)*{item[1]}])')
                    exec(f'self.{item[0]}[-1] = from_little_endian(self.{item[0]}[elem], {item[1]})')
            if len(item) != 4 and item[2] == 1:
                exec(f'self.{item[0]} = from_little_endian(self.{item[0]}, {item[1]})')
            offset += item[1]


class Separer:
    def __init__(self, path: str):
        exe = open(path, 'rb')
        offset = 0
        s = exe.read(DOS_HEADER_LENGTH)
        self.DOS_header = DOS_header(s)
        offset += DOS_HEADER_LENGTH
        if self.DOS_header.e_magic != b'MZ':
            raise Exception('The file isn\'t a executable.')
        DOS_STUB_LENGTH = DOS_HEADER_LENGTH - self.DOS_header.e_lfanew
        print(DOS_STUB_LENGTH)
        pass