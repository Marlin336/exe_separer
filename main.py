import sys
from separer import *

if __name__ == '__main__':
    arg_list = ['LSB.exe'] # sys.argv[1:]
    sep = Separer(arg_list[0])
    sep.extract_sections()
