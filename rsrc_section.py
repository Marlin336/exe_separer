from func import from_little_endian, get_name_from_rsrc_id, BYTE, WORD, DWORD


def is_leaf(dir_: dict):
    return not(dir_['offset'] & int('80000000', 16))


class rsrc_section:
    def __init__(self, content):
        offset = 0
        rsrc_header = content[:16]
        self.characteristics = from_little_endian(rsrc_header[offset:offset + DWORD], DWORD)
        offset += DWORD
        self.timedate_stamp = from_little_endian(rsrc_header[offset:offset + DWORD], DWORD)
        offset += DWORD
        self.major_version = from_little_endian(rsrc_header[offset:offset + WORD], WORD)
        offset += WORD
        self.minor_version = from_little_endian(rsrc_header[offset:offset + WORD], WORD)
        offset += WORD
        self.number_of_named_entries = from_little_endian(rsrc_header[offset:offset + WORD], WORD)
        offset += WORD
        self.number_of_id_entries = from_little_endian(rsrc_header[offset:offset + WORD], WORD)
        offset += WORD
        self.dir_list = list()
        for dir_num in range(self.number_of_named_entries + self.number_of_id_entries):
            name_or_id = from_little_endian(content[offset:offset + DWORD], DWORD)
            if not (name_or_id & int('80000000', 16)):
                name = get_name_from_rsrc_id(from_little_endian(content[offset:offset + DWORD], DWORD))
            else:
                name_offset = name_or_id & int('7FFFFFFF', 16)
                name_size = from_little_endian(content[name_offset:name_offset + WORD], WORD)
                name_offset += WORD
                name = list()
                for char in range(name_size):
                    name.append(from_little_endian(content[name_offset:name_offset + WORD], WORD))
                    name_offset += WORD
                name = bytes(name).decode('UTF-8')
            offset += DWORD
            rsrc_offset = from_little_endian(content[offset:offset + DWORD], DWORD)
            offset += DWORD
            self.dir_list.append({'name': name, 'offset': rsrc_offset})
        for dir_ in self.dir_list:
            inner_list = list()
            while not is_leaf(dir_):
                offset = dir_['offset'] & int('7FFFFFFF', 16)
                next_node = content[16 + offset:16 + offset + DWORD + DWORD]
                next_node_name = from_little_endian(next_node[:DWORD], DWORD)
                offset += DWORD
                next_node_offset = from_little_endian(next_node[:DWORD], DWORD)
                offset += DWORD
                if next_node_name & int('80000000', 16):
                    name_offset = next_node_offset & int('7FFFFFFF', 16)
                    name_size = from_little_endian(content[name_offset:name_offset + WORD], WORD)
                    name_offset += WORD
                    name = list()
                    for char in range(name_size):
                        name.append(from_little_endian(content[name_offset:name_offset + WORD], WORD))
                        name_offset += WORD
                    name = bytes(name).decode('UTF-8')
                pass


