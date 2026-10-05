"""Windows child cleanup and session-scoped tunnel exclusivity."""
import ctypes
from ctypes import wintypes

class KillJob:
    """Windows closes the tunnel child if the user's launcher is closed abruptly."""
    def __init__(self):
        class Limits(ctypes.Structure):
            _fields_ = [("user", ctypes.c_longlong), ("job_user", ctypes.c_longlong),
                        ("flags", wintypes.DWORD), ("minimum", ctypes.c_size_t),
                        ("maximum", ctypes.c_size_t), ("active", wintypes.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                        ("scheduling", wintypes.DWORD)]
        class Extended(ctypes.Structure):
            _fields_ = [("basic", Limits), ("io", ctypes.c_ulonglong * 6),
                        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                        ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.api.CreateJobObjectW(None, None)
        info = Extended()
        info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.handle or not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            self.close()
            raise OSError("Cannot establish temporary child cleanup")

    def attach(self, process):
        if not self.api.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(process._handle))):
            raise OSError("Cannot attach temporary child cleanup")

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


class TunnelMutex:
    """Prevent supervisors in this Windows session from sharing a tunnel ID."""
    def __init__(self, tunnel_id):
        import hashlib
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        self.api.CreateMutexW.restype = wintypes.HANDLE
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        name = "Local\\ExpergisTunnel-" + hashlib.sha256(tunnel_id.encode()).hexdigest()
        self.handle = self.api.CreateMutexW(None, False, name)
        if not self.handle or ctypes.get_last_error() == 183:
            self.close()
            raise RuntimeError("A supervisor already owns this tunnel in this session")

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None
