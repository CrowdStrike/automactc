#
# A block cipher is instantiated as a combination of:
# 1. A base cipher (such as AES)
# 2. A mode of operation (such as CBC)
#
# Both items are implemented as C modules.
#
# The API of #1 is (replace "AES" with the name of the actual cipher):
# - AES_start_operaion(key) --> base_cipher_state
# - AES_encrypt(base_cipher_state, in, out, length)
# - AES_decrypt(base_cipher_state, in, out, length)
# - AES_stop_operation(base_cipher_state)
#
# Where base_cipher_state is AES_State, a struct with BlockBase (set of
# pointers to encrypt/decrypt/stop) followed by cipher-specific data.
#
# The API of #2 is (replace "CBC" with the name of the actual mode):
# - CBC_start_operation(base_cipher_state) --> mode_state
# - CBC_encrypt(mode_state, in, out, length)
# - CBC_decrypt(mode_state, in, out, length)
# - CBC_stop_operation(mode_state)
#
# where mode_state is a a pointer to base_cipher_state plus mode-specific data.

import os

from _mode_cbc import _create_cbc_cipher

_modes = { 2:_create_cbc_cipher,
           }

_extra_modes = {
                }

def _create_cipher(factory, key, mode, *args, **kwargs):

    kwargs["key"] = key

    modes = dict(_modes)
    if kwargs.pop("add_aes_modes", False):
        modes.update(_extra_modes)
    if not mode in modes:
        raise ValueError("Mode not supported")

    if args:
        if mode in (8, 9, 10, 11, 12):
            if len(args) > 1:
                raise TypeError("Too many arguments for this mode")
            kwargs["nonce"] = args[0]
        elif mode in (2, 3, 5, 7):
            if len(args) > 1:
                raise TypeError("Too many arguments for this mode")
            kwargs["IV"] = args[0]
        elif mode == 6:
            if len(args) > 0:
                raise TypeError("Too many arguments for this mode")
        elif mode == 1:
            raise TypeError("IV is not meaningful for the ECB mode")

    return modes[mode](factory, **kwargs)
