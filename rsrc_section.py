from func import from_little_endian, get_name_from_rsrc_id, BYTE, WORD, DWORD


def get_name(name_field, content, is_type):
    if name_field & int('80000000', 16):
        name_offset = name_field & int('7FFFFFFF', 16)
        name_size = from_little_endian(content[name_offset:name_offset + WORD], WORD)
        name_offset += WORD
        name = list()
        for char in range(name_size):
            name.append(from_little_endian(content[name_offset:name_offset + WORD], WORD))
            name_offset += WORD
        return bytes(name).decode('UTF-8')
    else:
        if is_type:
            return get_name_from_rsrc_id(name_field)
        else:
            return name_field


class rsrc_section:
    def __init__(self, content, virtual_address):
        offset = 0
        dir_desc = list()
        dir_desc.append([rsrc_section.get_descriptor_data(content[offset:offset + 16])])
        offset += 16
        dir_count = dir_desc[0][0]['num_of_named_entries'] + dir_desc[0][0]['num_of_id_entries']
        offset += dir_count * (DWORD + DWORD)
        sec_level = list()
        for d in dir_count:
            pass

    @staticmethod
    def get_descriptor_data(content):
        offset = 0
        char = from_little_endian(content[offset:offset + DWORD], DWORD)
        offset += DWORD
        timedate_stamp = from_little_endian(content[offset:offset+DWORD], DWORD)
        offset += DWORD
        major_version = from_little_endian(content[offset:offset + WORD], WORD)
        offset += WORD
        minor_version = from_little_endian(content[offset:offset + WORD], WORD)
        offset += WORD
        num_of_named_entries = from_little_endian(content[offset:offset + WORD], WORD)
        offset += WORD
        num_of_id_entries = from_little_endian(content[offset:offset + WORD], WORD)
        return {'characteristics': char, 'timedate_stamp': timedate_stamp, 'major_version': major_version,
                'minor_version': minor_version, 'num_of_named_entries': num_of_named_entries,
                'num_of_id_entries': num_of_id_entries}


class node:
    def __init__(self, name, offset):
        self.name = name
        self.offset = offset
        self.characteristics = None
        self.timedate_stamp = None
        self.major_version = None
        self.minor_version = None
        self.number_of_named_entries = None
        self.number_of_id_entries = None
        self.children = list()

    def add_child(self, child):
        self.children.append(child)

    def del_child(self, child):
        self.children.remove(child)

    def is_leaf(self):
        return not(self.offset & int('80000000', 16))
