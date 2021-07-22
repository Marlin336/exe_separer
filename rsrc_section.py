from func import from_little_endian, get_name_from_rsrc_id, BYTE, WORD, DWORD
import os


def is_leaf(curr_node):
    return not(curr_node[1] & int('80000000', 16))


def get_name(name_field, content, is_type=False):
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


def get_dir(content, offset, curr_node: list, is_type=False):
    header = dict()
    header['char'] = from_little_endian(content[offset:offset + DWORD], DWORD)
    offset += DWORD
    header['td_stamp'] = from_little_endian(content[offset:offset + DWORD], DWORD)
    offset += DWORD
    header['maj_ver'] = from_little_endian(content[offset:offset + WORD], WORD)
    offset += WORD
    header['min_ver'] = from_little_endian(content[offset:offset + WORD], WORD)
    offset += WORD
    header['num_of_named_ent'] = from_little_endian(content[offset:offset + WORD], WORD)
    offset += WORD
    header['num_of_id_ent'] = from_little_endian(content[offset:offset + WORD], WORD)
    offset += WORD
    for child_num in range(header['num_of_id_ent'] + header['num_of_named_ent']):
        dir_name = get_name(from_little_endian(content[offset:offset + DWORD], DWORD), content, is_type)
        offset += DWORD
        dir_offset = from_little_endian(content[offset:offset + DWORD], DWORD)
        offset += DWORD
        curr_node.append([dir_name, dir_offset, []])


def get_data(content, offset, curr_node: list, virtual_address):
    header = dict()
    header['offset'] = (from_little_endian(content[offset:offset + DWORD], DWORD) - virtual_address)
    offset += DWORD
    header['size'] = from_little_endian(content[offset:offset + DWORD], DWORD)
    offset += DWORD
    header['code_page'] = from_little_endian(content[offset:offset + DWORD], DWORD)
    offset += DWORD
    # reserved
    offset += DWORD
    curr_node[2] = content[header['offset']:header['offset'] + header['size']]


class rsrc_section:
    def __init__(self, parent, sect_num):
        self.parent = parent
        content = parent.Section_content[sect_num]
        self.dir_tree = list()
        get_dir(content, 0, self.dir_tree, True)
        for d_type in self.dir_tree:
            d_type[1] = d_type[1] & int('7FFFFFFF', 16)
            get_dir(content, d_type[1], d_type[2])
        for d_type in self.dir_tree:
            for d_name in d_type[2]:
                d_name[1] = d_name[1] & int('7FFFFFFF', 16)
                get_dir(content, d_name[1], d_name[2])
        for d_type in self.dir_tree:
            for d_name in d_type[2]:
                for d_lang in d_name[2]:
                    get_data(content, d_lang[1], d_lang, parent.Section_table[sect_num].virtual_address)
        pass

    def extract_directories(self):
        if not os.path.exists(f'{self.parent.file_name}.rsrc'):
            os.mkdir(f'{self.parent.file_name}.rsrc')
            os.chdir(f'{self.parent.file_name}.rsrc')
            for d_type in self.dir_tree:
                os.mkdir(str(d_type[0]))
            for d_type in self.dir_tree:
                os.chdir(str(d_type[0]))
                for d_name in d_type[2]:
                    os.mkdir(str(d_name[0]))
                os.chdir('..')
            for d_type in self.dir_tree:
                os.chdir(d_type[0])
                for d_name in d_type[2]:
                    os.chdir(str(d_name[0]))
                    for d_lang in d_name[2]:
                        f_in = open(str(d_lang[0]), 'wb')
                        f_in.write(d_lang[2])
                        f_in.close()
                    os.chdir('..')
                os.chdir('..')
            pass
