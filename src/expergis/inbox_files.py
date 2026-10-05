"""Read one immutable flat-inbox event with handle-level link/containment checks."""
import ctypes
from ctypes import wintypes as W
import os
from pathlib import Path
import stat

from expergis.job_event_contract import MAX_BYTES, uuid_text
from expergis.watch_scope import checked_local_path


def read_event_file(inbox, name):
    if not isinstance(name, str) or len(name) != 41 or not name.endswith('.json'):
        raise ValueError('Invalid event filename')
    uuid_text(name[:-5])
    root = checked_local_path(str(inbox))
    if not root.is_dir():
        raise PermissionError('Inbox must be a directory')
    if os.name == 'nt':
        result = _windows_read(root/name)
    else:
        result = _posix_read(root, name)
    checked_local_path(str(root))
    return result


def _windows_read(path):
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateFileW.argtypes = [W.LPCWSTR,W.DWORD,W.DWORD,W.LPVOID,W.DWORD,W.DWORD,W.HANDLE]
    api.CreateFileW.restype = W.HANDLE
    api.CloseHandle.argtypes = [W.HANDLE]
    class Info(ctypes.Structure):
        _fields_ = [('attributes',W.DWORD),('created',W.FILETIME),('accessed',W.FILETIME),
            ('written',W.FILETIME),('volume',W.DWORD),('size_high',W.DWORD),('size_low',W.DWORD),
            ('links',W.DWORD),('index_high',W.DWORD),('index_low',W.DWORD)]
    api.GetFileInformationByHandle.argtypes = [W.HANDLE,ctypes.POINTER(Info)]
    api.GetFinalPathNameByHandleW.argtypes = [W.HANDLE,W.LPWSTR,W.DWORD,W.DWORD]
    api.ReadFile.argtypes = [W.HANDLE,W.LPVOID,W.DWORD,ctypes.POINTER(W.DWORD),W.LPVOID]
    # OPEN_REPARSE_POINT prevents following a leaf link; READ-only sharing excludes writers/renames.
    handle = api.CreateFileW(str(path),0x80000000,1,None,3,0x00200000|0x08000000,None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError('Event unavailable')
    try:
        info = Info()
        if not api.GetFileInformationByHandle(handle,ctypes.byref(info)):
            raise OSError('Event metadata unavailable')
        if info.attributes & (0x400|0x10) or info.links != 1 or info.size_high or not 1 <= info.size_low <= MAX_BYTES:
            raise ValueError('Event file rejected')
        final = ctypes.create_unicode_buffer(32768)
        length = api.GetFinalPathNameByHandleW(handle,final,len(final),0)
        if not 0 < length < len(final) or os.path.normcase(final.value.removeprefix('\\\\?\\')) != os.path.normcase(str(path)):
            raise PermissionError('Event handle escaped inbox')
        buffer, count = ctypes.create_string_buffer(MAX_BYTES+1), W.DWORD()
        if not api.ReadFile(handle,buffer,MAX_BYTES+1,ctypes.byref(count),None) or count.value != info.size_low:
            raise OSError('Event read incomplete')
        return buffer.raw[:count.value]
    finally:
        api.CloseHandle(handle)


def _posix_read(root, name):
    # Open every directory component relative to a pinned parent, refusing symlinks.
    directory = os.open('/', os.O_RDONLY|os.O_DIRECTORY)
    handle = None
    try:
        for part in root.parts[1:]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            os.close(directory)
            directory=child
        handle=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        before=os.fstat(handle)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= MAX_BYTES:
            raise ValueError('Event file rejected')
        body=os.read(handle,MAX_BYTES+1)
        after=os.fstat(handle)
        if (len(body)!=before.st_size or (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns)):
            raise OSError('Event changed during read')
        return body
    finally:
        if handle is not None: os.close(handle)
        os.close(directory)
