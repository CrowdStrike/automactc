#!/usr/bin/env python

import ctypes
import ctypes.util
import sys

if sys.version_info[0] < 3:
    import Foundation
    import objc

try:
    xrange
except NameError:
    xrange = range
try:
    unicode
except NameError:
    unicode = str

class CodeSignChecker(object):

    """Call `CodeSignChecker.get_signature_chain` to get the signing chain for a binary.

    This class is derived from KnockKock
     - https://github.com/synack/knockknock
    KnockKnock is licensed under a Creative Commons Attribution-NonCommercial 4.0 International License
     - https://github.com/synack/knockknock/blob/master/LICENSE
    """

    # Class level pointers to dynamic link libraries
    SEC_DLL = None
    OBJC_DLL = None
    FOUNDATION_DLL = None

    # OS X constants
    errSecSuccess = 0x0
    kSecCSDefaultFlags = 0x0
    kSecCSDoNotValidateResources = 0x4
    kSecCSSigningInformation = 0x2
    kSecCodeInfoCertificates = 'certificates'

    class CodeSignCheckerError(Exception):
        pass

    class MissingDLLError(CodeSignCheckerError):

        """Raised when a DLL can't be loaded."""
        pass

    class CheckSignatureError(CodeSignCheckerError):

        """Raised when a signature can't be checked."""
        pass

    class SystemCallError(CodeSignCheckerError):

        """Raised when a system call fails."""

        def __init__(self, method, status):
            self.status = status
            self.method = method

        def __str__(self):
            return '{0} failed with status[{1}]'.format(self.method, self.status)

    class CFTypeWrapper(object):

        """A helper class which ensures CFRelease is called.

        Attributes:
            val: The actual value stored in this wrapper.
        """

        def __init__(self, val):
            self.val = val

        def __del__(self):
            CFRelease = CodeSignChecker.FOUNDATION_DLL.CFRelease
            CFRelease.argtypes = [ctypes.c_void_p]
            CFRelease(self.val)

    @classmethod
    def _load_library(cls, dll_path):
        """Load a DLL.

        Args:
            dll_path: Fully qualified path to the DLL
        Returns:
            handle to the library
        Raises:
            MissingDLLError
        """
        dll = ctypes.cdll.LoadLibrary(dll_path)
        if not dll:
            raise cls.MissingDLLError(message='could not load {0}'.format(dll_path))
        return dll

    @classmethod
    def _load_framework(cls):
        """Loads all DLLs required by the CodeSignChecker."""

        if not cls.SEC_DLL:
            cls.SEC_DLL = cls._load_library('/System/Library/Frameworks/Security.framework/Versions/Current/Security')

        if not cls.OBJC_DLL:
            cls.OBJC_DLL = cls._load_library(ctypes.util.find_library('objc'))

            cls.OBJC_DLL.objc_getClass.restype = ctypes.c_void_p
            cls.OBJC_DLL.sel_registerName.restype = ctypes.c_void_p

        if not cls.FOUNDATION_DLL:
            cls.FOUNDATION_DLL = cls._load_library(ctypes.util.find_library('Foundation'))

    @classmethod
    def SecStaticCodeCreateWithPath(cls, file_path):
        """Call Security Framework's SecStaticCodeCreateWithPath method.

        Args:
            file_path: fully qualified file path
        Returns:
            A SecStaticCodeRef wrapped with a CFTypeWrapper
        """

        if isinstance(file_path, unicode):
            file_path = file_path.encode(encoding='utf-8', errors='ignore')

        # file_path as NSString
        file_path = Foundation.NSString.stringWithUTF8String_(file_path)

        # file_path with spaces escaped
        file_path = file_path.stringByAddingPercentEscapesUsingEncoding_(Foundation.NSUTF8StringEncoding).encode('utf-8')

        # init file_path as url
        path = Foundation.NSURL.URLWithString_(Foundation.NSString.stringWithUTF8String_(file_path))

        # pointer for static code
        static_code = ctypes.c_void_p(0)

        # create static code from path and check
        result = cls.SEC_DLL.SecStaticCodeCreateWithPath(ctypes.c_void_p(objc.pyobjc_id(path)),
                                                         cls.kSecCSDefaultFlags, ctypes.byref(static_code))
        if cls.errSecSuccess != result:
            raise cls.SystemCallError('SecStaticCodeCreateWithPath', result)

        return cls.CFTypeWrapper(static_code)

    @classmethod
    def SecStaticCodeCheckValidityWithErrors(cls, static_code):
        """Call Security Framework's SecStaticCodeCheckValidityWithErrors method.

        Args:
            static_code: A SecStaticCodeRef
        Raises:
            SystemCallError when the code is not secure
        """

        result = cls.SEC_DLL.SecStaticCodeCheckValidityWithErrors(static_code, cls.kSecCSDoNotValidateResources, None, None)
        if cls.errSecSuccess != result:
            raise cls.SystemCallError('SecStaticCodeCheckValidityWithErrors', result)

    @classmethod
    def SecCodeCopySigningInformation(cls, static_code):
        """Call Security Framework's SecCodeCopySigningInformation method.

        Args:
            static_code: A SecStaticCodeRef
        Returns:
            A CFDictionaryRef wrapped with a CFTypeWrapper
        Raises:
            SystemCallError
        """

        signing_information = ctypes.c_void_p(0)

        result = cls.SEC_DLL.SecCodeCopySigningInformation(static_code, cls.kSecCSSigningInformation, ctypes.byref(signing_information))
        if cls.errSecSuccess != result:
            raise cls.SystemCallError('SecCodeCopySigningInformation', result)

        return cls.CFTypeWrapper(signing_information)

    @classmethod
    def SecCertificateCopyCommonName(cls, certificate):
        """Call Security Framework's SecCertificateCopyCommonName method.

        Args:
            static_code: A SecCertificateRef
        Returns:
            An NSString
        Raises:
            SystemCallError
        """

        certificate_name = ctypes.c_char_p(0)

        result = cls.SEC_DLL.SecCertificateCopyCommonName(ctypes.c_void_p(certificate), ctypes.byref(certificate_name))
        if cls.errSecSuccess != result:
            raise cls.SystemCallError('SecCertificateCopyCommonName', result)

        return certificate_name

    @classmethod
    def NSString_from_str(cls, str_val):
        """Creates an instance of NSString.

        Args:
            str_val: A Python string
        Returns:
            An NSString
        """
        NSString = cls.OBJC_DLL.objc_getClass('NSString')
        cls.OBJC_DLL.objc_msgSend.restype = ctypes.c_void_p
        cls.OBJC_DLL.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        return cls.OBJC_DLL.objc_msgSend(NSString, cls.OBJC_DLL.sel_registerName('stringWithUTF8String:'), str_val)

    @classmethod
    def str_from_NSString(cls, nsstring_val):
        """Creates a Python string from an NSString.

        Args:
            nsstring_val: An NSString
        Returns:
            A string
        """
        cls.OBJC_DLL.objc_msgSend.restype = ctypes.c_char_p
        cls.OBJC_DLL.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        return cls.OBJC_DLL.objc_msgSend(nsstring_val, cls.OBJC_DLL.sel_registerName('UTF8String'))

    @classmethod
    def CFDictionary_objectForKey(cls, instance, key):
        """Calls CFDictionary:objectForKey

        Args:
            instance - A CFDictionaryRef
            key - A string
        Returns:
            value retrieved from the CFDictionary
        """
        nsstring_key = cls.NSString_from_str(key)

        cls.OBJC_DLL.objc_msgSend.restype = ctypes.c_void_p
        cls.OBJC_DLL.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        return cls.OBJC_DLL.objc_msgSend(instance, cls.OBJC_DLL.sel_registerName('objectForKey:'), nsstring_key)

    @classmethod
    def CFArray_count(cls, instance):
        """Calls CFArray:count

        Args:
            instance - A CFArrayRef
        Returns:
            int
        """
        cls.OBJC_DLL.objc_msgSend.restype = ctypes.c_uint
        cls.OBJC_DLL.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        return cls.OBJC_DLL.objc_msgSend(instance, cls.OBJC_DLL.sel_registerName('count'))

    @classmethod
    def CFArray_objectAtIndex(cls, instance, index):
        """Calls CFArray:objectAtIndex

        Args:
            instance - A CFArrayRef
            index - int
        Returns:
            value retrieved from the CFArray
        """
        cls.OBJC_DLL.objc_msgSend.restype = ctypes.c_void_p
        cls.OBJC_DLL.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]

        return cls.OBJC_DLL.objc_msgSend(instance, cls.OBJC_DLL.sel_registerName('objectAtIndex:'), index)

    @classmethod
    def get_signature_chain(cls, file_path):
        """Retrieves the singing authorities for a binary.

        Args:
            file_path: A string of the fully qualified file path

        Returns:
            An array of signing authorities or an empty array
        """
        signing_authorities = []

        cls._load_framework()

        static_code = cls.SecStaticCodeCreateWithPath(file_path)

        try:
            cls.SecStaticCodeCheckValidityWithErrors(static_code.val)
        except cls.SystemCallError:
            # The binary is not signed
            return signing_authorities

        cfdict_information = cls.SecCodeCopySigningInformation(static_code.val)
        cfarray_cert_chain = cls.CFDictionary_objectForKey(cfdict_information.val, cls.kSecCodeInfoCertificates)

        for index in xrange(cls.CFArray_count(cfarray_cert_chain)):
            certificate = cls.CFArray_objectAtIndex(cfarray_cert_chain, index)

            try:
                nsstring_common_name = cls.SecCertificateCopyCommonName(certificate)
                common_name = cls.str_from_NSString(nsstring_common_name)
                signing_authorities.append(common_name)
            except cls.SystemCallError:
                # If this certificate's name can't be retrieved just continue
                pass

        return signing_authorities
