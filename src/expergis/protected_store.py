"""Current-user Windows DPAPI; no credentials or plaintext fallback."""
import ctypes
import os
from ctypes import wintypes


class DPAPIProtector:
    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("Durable private storage requires Windows DPAPI or an injected protector")

    def _crypt(self, value, decrypt=False):
        class Blob(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]
        buffer = ctypes.create_string_buffer(value)
        source = Blob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
        target = Blob()
        dll = ctypes.WinDLL("crypt32", use_last_error=True)
        fn = dll.CryptUnprotectData if decrypt else dll.CryptProtectData
        fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        fn.restype = wintypes.BOOL
        if not fn(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
            raise OSError("Private storage protection failed")
        try:
            return ctypes.string_at(target.data, target.size)
        finally:
            free = ctypes.WinDLL("kernel32").LocalFree
            free.argtypes = [ctypes.c_void_p]
            free.restype = ctypes.c_void_p
            free(target.data)

    def seal(self, value):
        return self._crypt(value)

    def open(self, value):
        return self._crypt(value, decrypt=True)
