from __future__ import annotations

import ctypes
from typing import Any

_HANDLE = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_LONG = ctypes.c_int32
_SIZE_T = ctypes.c_size_t
_ULONGLONG = ctypes.c_uint64
_LARGE_INTEGER = ctypes.c_int64
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_THREAD_SUSPEND_RESUME = 0x0002
_TH32CS_SNAPTHREAD = 0x00000004
_ERROR_NO_MORE_FILES = 18


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", _LARGE_INTEGER),
        ("PerJobUserTimeLimit", _LARGE_INTEGER),
        ("LimitFlags", _DWORD),
        ("MinimumWorkingSetSize", _SIZE_T),
        ("MaximumWorkingSetSize", _SIZE_T),
        ("ActiveProcessLimit", _DWORD),
        ("Affinity", _SIZE_T),
        ("PriorityClass", _DWORD),
        ("SchedulingClass", _DWORD),
    ]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", _ULONGLONG),
        ("WriteOperationCount", _ULONGLONG),
        ("OtherOperationCount", _ULONGLONG),
        ("ReadTransferCount", _ULONGLONG),
        ("WriteTransferCount", _ULONGLONG),
        ("OtherTransferCount", _ULONGLONG),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", _SIZE_T),
        ("JobMemoryLimit", _SIZE_T),
        ("PeakProcessMemoryUsed", _SIZE_T),
        ("PeakJobMemoryUsed", _SIZE_T),
    ]


class _THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", _DWORD),
        ("cntUsage", _DWORD),
        ("th32ThreadID", _DWORD),
        ("th32OwnerProcessID", _DWORD),
        ("tpBasePri", _LONG),
        ("tpDeltaPri", _LONG),
        ("dwFlags", _DWORD),
    ]


class _Kernel32:
    def __init__(self) -> None:
        library = ctypes.WinDLL("kernel32", use_last_error=True)
        self._bind(library, "CreateJobObjectW", [_HANDLE, ctypes.c_wchar_p], _HANDLE)
        self._bind(
            library,
            "SetInformationJobObject",
            [_HANDLE, ctypes.c_int, ctypes.c_void_p, _DWORD],
            ctypes.c_int32,
        )
        self._bind(library, "AssignProcessToJobObject", [_HANDLE, _HANDLE], ctypes.c_int32)
        self._bind(library, "TerminateJobObject", [_HANDLE, ctypes.c_uint], ctypes.c_int32)
        self._bind(library, "CreateToolhelp32Snapshot", [_DWORD, _DWORD], _HANDLE)
        self._bind(
            library,
            "Thread32First",
            [_HANDLE, ctypes.POINTER(_THREADENTRY32)],
            ctypes.c_int32,
        )
        self._bind(
            library,
            "Thread32Next",
            [_HANDLE, ctypes.POINTER(_THREADENTRY32)],
            ctypes.c_int32,
        )
        self._bind(library, "OpenThread", [_DWORD, ctypes.c_int32, _DWORD], _HANDLE)
        self._bind(library, "ResumeThread", [_HANDLE], _DWORD)
        self._bind(library, "CloseHandle", [_HANDLE], ctypes.c_int32)
        self._bind(library, "GetLastError", [], _DWORD)
        self._bind(library, "SetLastError", [_DWORD], None)

    @staticmethod
    def _bind(library: Any, name: str, arguments: list[Any], result: Any) -> None:
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = result


class WindowsJob:
    def __init__(
        self,
        process_handle: int,
        process_id: int,
        *,
        api: Any | None = None,
    ) -> None:
        self._api = _Kernel32() if api is None else api
        self._handle: int | None = self._api.CreateJobObjectW(None, None)
        if not self._handle:
            _raise_last_error(self._api.GetLastError())
        try:
            information = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            information.BasicLimitInformation.LimitFlags = (
                _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            self._require(
                self._api.SetInformationJobObject(
                    self._handle,
                    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    ctypes.byref(information),
                    ctypes.sizeof(information),
                )
            )
            self._require(
                self._api.AssignProcessToJobObject(self._handle, process_handle)
            )
            self._resume_primary_thread(process_id)
        except BaseException:
            try:
                self.close()
            except OSError:
                pass
            raise

    def terminate(self) -> bool:
        if self._handle is None:
            return False
        self._require(self._api.TerminateJobObject(self._handle, 1))
        return True

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            self._require(self._api.CloseHandle(handle))

    def _resume_primary_thread(self, process_id: int) -> None:
        snapshot = self._api.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot == _INVALID_HANDLE_VALUE or not snapshot:
            _raise_last_error(self._api.GetLastError())
        try:
            entry = _THREADENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            if not self._api.Thread32First(snapshot, ctypes.byref(entry)):
                _raise_last_error(self._api.GetLastError())
            while True:
                if entry.th32OwnerProcessID == process_id:
                    self._resume_thread(entry.th32ThreadID)
                    return
                self._api.SetLastError(0)
                if not self._api.Thread32Next(snapshot, ctypes.byref(entry)):
                    if self._api.GetLastError() == _ERROR_NO_MORE_FILES:
                        break
                    _raise_last_error(self._api.GetLastError())
            raise OSError("The new process primary thread could not be found.")
        finally:
            self._require(self._api.CloseHandle(snapshot))

    def _resume_thread(self, thread_id: int) -> None:
        thread = self._api.OpenThread(_THREAD_SUSPEND_RESUME, False, thread_id)
        if not thread:
            _raise_last_error(self._api.GetLastError())
        try:
            result = self._api.ResumeThread(thread)
            if result == 0xFFFFFFFF:
                _raise_last_error(self._api.GetLastError())
            if result != 1:
                raise OSError("The new process thread did not resume exactly once.")
        finally:
            self._require(self._api.CloseHandle(thread))

    def _require(self, result: int) -> None:
        if not result:
            _raise_last_error(self._api.GetLastError())


def _raise_last_error(error: int) -> None:
    raise OSError(error, "A Windows process operation failed.")
