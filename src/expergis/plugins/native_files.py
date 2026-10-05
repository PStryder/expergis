"""Native Windows change signals for explicitly selected directories only.

Signals trigger the existing bounded directory snapshot semantics. They do not
capture transient files created and removed between snapshots, or file contents.
"""
import asyncio
import ctypes
import os
from ctypes import wintypes


class DirectorySignals:
    def __init__(self, paths):
        if os.name != "nt":
            raise OSError("Native directory signals require Windows")
        roots = list(dict.fromkeys(str(path if path.is_dir() else path.parent) for path in paths))
        if not 1 <= len(roots) <= 32:
            raise ValueError("Native watcher requires 1 to 32 directories")
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.FindFirstChangeNotificationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
        self.api.FindFirstChangeNotificationW.restype = wintypes.HANDLE
        self.api.FindNextChangeNotification.argtypes = [wintypes.HANDLE]
        self.api.FindNextChangeNotification.restype = wintypes.BOOL
        self.api.FindCloseChangeNotification.argtypes = [wintypes.HANDLE]
        self.api.FindCloseChangeNotification.restype = wintypes.BOOL
        self.api.WaitForMultipleObjects.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
                                                   wintypes.BOOL, wintypes.DWORD]
        self.api.WaitForMultipleObjects.restype = wintypes.DWORD
        self.handles = []
        self.closed = False
        self._wait_task = None
        try:
            for root in roots:
                handle = self.api.FindFirstChangeNotificationW(root, False, 0x1 | 0x8 | 0x10)
                if handle == ctypes.c_void_p(-1).value:
                    raise OSError("Cannot watch selected directory")
                self.handles.append(handle)
        except BaseException:
            self._close_handles()
            raise

    def _wait(self):
        handles = (wintypes.HANDLE * len(self.handles))(*self.handles)
        result = self.api.WaitForMultipleObjects(len(handles), handles, False, 250)
        if result == 258:  # WAIT_TIMEOUT
            return False
        if result >= len(handles) or not self.api.FindNextChangeNotification(self.handles[result]):
            raise OSError("Native directory notification failed")
        return True

    async def wait(self, timeout):
        deadline = asyncio.get_running_loop().time() + timeout
        while not self.closed and asyncio.get_running_loop().time() < deadline:
            self._wait_task = asyncio.create_task(asyncio.to_thread(self._wait))
            try:
                if await asyncio.shield(self._wait_task):
                    return True
            finally:
                # Never close handles while the OS wait still uses them.
                await self._wait_task
                self._wait_task = None
        return False

    def _close_handles(self):
        for handle in self.handles:
            self.api.FindCloseChangeNotification(handle)
        self.handles.clear()

    async def close(self):
        self.closed = True
        if self._wait_task:
            await asyncio.shield(self._wait_task)
        self._close_handles()
