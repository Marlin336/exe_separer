import sys
import exeseparator


if __name__ == '__main__':
    arg_list = ['RH.exe'] # sys.argv[1:]
    sep = exeseparator.ExeSeparator(arg_list[0])
    sep.get_icons()


