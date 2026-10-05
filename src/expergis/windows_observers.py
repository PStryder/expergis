"""Read-only, selected Windows process and service metadata. No enumeration API."""
import ctypes
from ctypes import wintypes as W
import csv
import os
from pathlib import Path
import subprocess


def libraries():
    if os.name != 'nt':
        raise OSError('Selected process/service monitoring requires Windows')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.GetProcessTimes.argtypes = [W.HANDLE] + [ctypes.POINTER(W.FILETIME)] * 4
    kernel.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD)]
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    kernel.WaitForSingleObject.restype = W.DWORD
    advapi.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE)]
    advapi.GetTokenInformation.argtypes = [W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)]
    advapi.EqualSid.argtypes = [W.LPVOID, W.LPVOID]
    return kernel, advapi


def _user_token(kernel, advapi, process):
    token = W.HANDLE()
    if not advapi.OpenProcessToken(process, 0x0008, ctypes.byref(token)):  # TOKEN_QUERY only
        raise PermissionError('Selected process owner unavailable')
    try:
        size = W.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 0 < size.value <= 65536:
            raise PermissionError('Invalid owner metadata')
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise PermissionError('Selected process owner unavailable')
        return buffer
    finally:
        kernel.CloseHandle(token)


def process_identity(pid):
    """Return own-user PID/start identity/basename; None means gone, not denied."""
    kernel, advapi = libraries()
    handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)  # LIMITED_QUERY | SYNCHRONIZE
    if not handle:
        if ctypes.get_last_error() == 87:
            return None
        raise PermissionError('Selected process unavailable')
    try:
        ours = _user_token(kernel, advapi, kernel.GetCurrentProcess())
        theirs = _user_token(kernel, advapi, handle)
        if not advapi.EqualSid(ctypes.cast(ours, ctypes.POINTER(W.LPVOID))[0],
                               ctypes.cast(theirs, ctypes.POINTER(W.LPVOID))[0]):
            raise PermissionError('Other-user processes excluded')
        wait = kernel.WaitForSingleObject(handle, 0)
        if wait == 0:
            return None
        if wait != 258:
            raise OSError('Process state unavailable')
        times = [W.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            raise OSError('Creation time unavailable')
        name, size = ctypes.create_unicode_buffer(32768), W.DWORD(32768)
        if not kernel.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(size)):
            raise OSError('Executable name unavailable')
        return {'pid': pid, 'creation_time': str(times[0].dwHighDateTime << 32 | times[0].dwLowDateTime),
                'process_name': Path(name.value).name.lower()}
    finally:
        kernel.CloseHandle(handle)


def selected_processes(names, identities):
    from expergis.monitoring_scope import image_name
    candidates = {i['pid']: i['creation_time'] for i in identities}
    wanted = {image_name(n) for n in names}
    for name in sorted(wanted):
        output = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq ' + name,
            '/FO', 'CSV', '/NH'], text=True, timeout=10, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        rows = list(csv.reader(output.splitlines()))
        if len(rows) > 128:
            raise ValueError('Too many matches for selected executable')
        for row in rows:
            if len(row) >= 2 and row[0].lower() == name and row[1].isdigit():
                candidates.setdefault(int(row[1]), None)
    if len(candidates) > 128:
        raise ValueError('Too many selected processes')
    result = {}
    for pid, start in candidates.items():
        try:
            item = process_identity(pid)
        except PermissionError:
            # Never turn denied metadata into a stopped event. Fail the observation.
            raise
        if item and (item['creation_time'] == start if start is not None else item['process_name'] in wanted):
            result[(pid, item['creation_time'])] = item
    return result


class ServiceStatus(ctypes.Structure):
    _fields_ = [(n, W.DWORD) for n in ('service_type', 'state', 'controls', 'exit_code',
        'service_exit_code', 'checkpoint', 'wait_hint', 'pid', 'flags')]


def service_status(name):
    """SCM CONNECT and SERVICE_QUERY_STATUS only; never start/stop/configure."""
    if name != 'SemSearch':
        raise PermissionError('Service outside scope')
    _, api = libraries()
    api.OpenSCManagerW.argtypes = [W.LPCWSTR, W.LPCWSTR, W.DWORD]
    api.OpenSCManagerW.restype = W.HANDLE
    api.OpenServiceW.argtypes = [W.HANDLE, W.LPCWSTR, W.DWORD]
    api.OpenServiceW.restype = W.HANDLE
    api.CloseServiceHandle.argtypes = [W.HANDLE]
    api.QueryServiceStatusEx.argtypes = [W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)]
    manager = api.OpenSCManagerW(None, None, 1)  # SC_MANAGER_CONNECT
    if not manager:
        raise PermissionError('SCM status unavailable')
    service = None
    try:
        service = api.OpenServiceW(manager, name, 4)  # SERVICE_QUERY_STATUS
        if not service:
            raise PermissionError('Selected service unavailable')
        status, size = ServiceStatus(), W.DWORD()
        if not api.QueryServiceStatusEx(service, 0, ctypes.byref(status), ctypes.sizeof(status), ctypes.byref(size)):
            raise OSError('Service status unavailable')
        states = {1: 'stopped', 2: 'start_pending', 3: 'stop_pending', 4: 'running',
                  5: 'continue_pending', 6: 'pause_pending', 7: 'paused'}
        return {'service_name': name, 'state': states.get(status.state, 'unknown'),
                'exit_code': status.exit_code if status.state == 1 else None,
                'service_exit_code': status.service_exit_code if status.state == 1 and status.exit_code == 1066 else None}
    finally:
        if service:
            api.CloseServiceHandle(service)
        api.CloseServiceHandle(manager)
