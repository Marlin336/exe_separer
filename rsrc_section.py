from func import from_little_endian, get_name_from_rsrc_id, BYTE, WORD, DWORD


def is_leaf(dir_: dict):
    return not(dir_['offset'] & int('80000000', 16))


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
        self.dir_tree = list()
        self.dir_tree.append(node('__ROOT__'))
        curr_node = self.dir_tree
        while curr_node:
            for child in curr_node:
                child.characteristics = from_little_endian(content[offset:offset + DWORD], DWORD)
                offset += DWORD
                child.timedate_stamp = from_little_endian(content[offset:offset + DWORD], DWORD)
                offset += DWORD
                child.major_version = from_little_endian(content[offset:offset + WORD], WORD)
                offset += WORD
                child.minor_version = from_little_endian(content[offset:offset + WORD], WORD)
                offset += WORD
                child.number_of_named_entries = from_little_endian(content[offset:offset + WORD], WORD)
                offset += WORD
                child.number_of_id_entries = from_little_endian(content[offset:offset + WORD], WORD)
                offset += WORD
                for dir_num in range(child.number_of_named_entries + child.number_of_id_entries):
                    name_field = from_little_endian(content[offset:offset + DWORD], DWORD)
                    name = get_name(name_field, content, child.name == '__ROOT__')
                    offset += DWORD
                    rsrc_offset = from_little_endian(content[offset:offset + DWORD], DWORD)
                    offset += DWORD
                    child.add_child(node(name, rsrc_offset))
                curr_node = child.children


class node:
    def __init__(self, name, offset=0):
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

    def get_children(self):
        return self.children
