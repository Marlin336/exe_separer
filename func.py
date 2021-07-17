import struct

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
