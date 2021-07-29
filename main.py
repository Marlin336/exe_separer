import sys
import exe_separator


if __name__ == '__main__':
    arg_list = ['RH.exe'] # sys.argv[1:]
    sep = exe_separator.EXE_separator(arg_list[0])
    sep.get_cursors()


