"""Is a directory owned by the account running the auditor?

Cleanup deletes only workspaces whose ownership is verified: a directory planted by another
account (e.g. in a shared ``%TEMP%`` that other principals can write to) is never deleted or
reused. Fail-closed: if the owner cannot be determined, the answer is ``False``.

- POSIX: ``lstat().st_uid`` equals the effective uid.
- Windows: the owner SID, read from a handle opened *without following* reparse points, equals
  the token's user SID or its default owner SID (an elevated administrator's new objects are
  owned by the Administrators group).
"""

import os
import sys


def owned_by_current_user(path: str) -> bool:
    if sys.platform == "win32":
        return _windows_owned(path)
    try:
        return os.lstat(path).st_uid == os.geteuid()
    except OSError:
        return False


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _READ_CONTROL = 0x00020000
    _FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # needed to open a directory
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000  # the link itself, never its target
    _INVALID_HANDLE = ctypes.c_void_p(-1).value
    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x1
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _TOKEN_OWNER = 4

    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.LocalFree.restype = wintypes.HLOCAL
    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.GetCurrentProcess.argtypes = []
    _advapi32.GetSecurityInfo.restype = wintypes.DWORD
    _advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.EqualSid.restype = wintypes.BOOL
    _advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    def _token_sids() -> list[ctypes.Array]:
        """Buffers whose first field is a SID pointer (TOKEN_USER, TOKEN_OWNER)."""
        token = wintypes.HANDLE()
        if not _advapi32.OpenProcessToken(
            _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
        ):
            return []
        buffers = []
        try:
            for info_class in (_TOKEN_USER, _TOKEN_OWNER):
                size = wintypes.DWORD()
                _advapi32.GetTokenInformation(token, info_class, None, 0, ctypes.byref(size))
                buffer = ctypes.create_string_buffer(size.value)
                if size.value and _advapi32.GetTokenInformation(
                    token, info_class, buffer, size, ctypes.byref(size)
                ):
                    buffers.append(buffer)
        finally:
            _kernel32.CloseHandle(token)
        return buffers

    def _windows_owned(path: str) -> bool:
        handle = _kernel32.CreateFileW(
            path,
            _READ_CONTROL,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle in (None, _INVALID_HANDLE):
            return False
        try:
            owner = ctypes.c_void_p()
            descriptor = ctypes.c_void_p()
            status = _advapi32.GetSecurityInfo(
                handle,
                _SE_FILE_OBJECT,
                _OWNER_SECURITY_INFORMATION,
                ctypes.byref(owner),
                None,
                None,
                None,
                ctypes.byref(descriptor),
            )
            if status != 0 or not owner.value:
                return False
            try:
                buffers = _token_sids()
                return any(
                    _advapi32.EqualSid(owner, ctypes.c_void_p.from_buffer(b).value) for b in buffers
                )
            finally:
                _kernel32.LocalFree(descriptor)
        finally:
            _kernel32.CloseHandle(handle)

else:  # pragma: no cover - POSIX uses st_uid

    def _windows_owned(path: str) -> bool:
        return False
