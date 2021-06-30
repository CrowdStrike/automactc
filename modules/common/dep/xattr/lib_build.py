import sys
import os

if sys.version_info[0] == 3:
    if sys.version_info[1] == 7:
        from ..cffi37 import FFI
    elif sys.version_info[1] == 8:
        from ..cffi38 import FFI
    elif sys.version_info[1] == 9:
        from ..cffi39 import FFI 


PATH = os.path.dirname(__file__)

with open(os.path.join(PATH, 'lib_build.h')) as hf:
    c_header = hf.read()
with open(os.path.join(PATH, 'lib_build.c')) as cf:
    c_source = cf.read()

ffi = FFI()
ffi.cdef(c_header)
ffi.set_source('_lib', c_source)

if __name__ == '__main__':
    ffi.compile()
