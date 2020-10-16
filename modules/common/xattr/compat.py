"""Python 3 compatibility shims
"""
import os
import sys
import codecs

if sys.version_info[0] < 3:
    integer_types = (int, long)
    text_type = unicode
    binary_type = str
else:
    integer_types = (int,)
    text_type = str
    binary_type = bytes

fs_encoding = sys.getfilesystemencoding()
fs_errors = 'strict'
if fs_encoding != 'mbcs':
    try:
        codecs.lookup('surrogateescape')
        fs_errors = 'surrogateescape'
    except LookupError:
        pass
try:
    fs_encode = os.fsencode
except AttributeError:
    def fs_encode(val):
        if not isinstance(val, bytes):
            return val.encode(fs_encoding, fs_errors)
        else:
            return val
