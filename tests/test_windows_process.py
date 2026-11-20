from __future__ import annotations

import ctypes
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from release_proof_mcp.windows_process import (
    WindowsJob,
    _JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    _Kernel32,
    _THREADENTRY32,
)


def fake_kernel32(resume_result: int = 1) -> tuple[SimpleNamespace, list[tuple]]:
    calls: list[tuple] = []

    def first_thread(snapshot: int, pointer: object) -> int:
        entry = pointer._obj
        entry.th32OwnerProcessID = 4321
        entry.th32ThreadID = 8765
        calls.append(("first_thread", snapshot))
        return 1

    def resume_thread(handle: int) -> int:
        calls.append(("resume", handle))
        if resume_result == 0xFFFFFFFF:
            api.last_error = 5
        return resume_result

    api = SimpleNamespace(
        last_error=0,
        CreateJobObjectW=Mock(
            side_effect=lambda *args: calls.append(("create_job",)) or 20
        ),
        SetInformationJobObject=Mock(
            side_effect=lambda *args: calls.append(("set_limits", *args)) or 1
        ),
        AssignProcessToJobObject=Mock(
            side_effect=lambda *args: calls.append(("assign", *args)) or 1
        ),
        CreateToolhelp32Snapshot=Mock(
            side_effect=lambda *args: calls.append(("snapshot", *args)) or 21
        ),
        Thread32First=Mock(side_effect=first_thread),
        Thread32Next=Mock(return_value=0),
        OpenThread=Mock(side_effect=lambda *args: calls.append(("open_thread", *args)) or 22),
        ResumeThread=Mock(side_effect=resume_thread),
        TerminateJobObject=Mock(
            side_effect=lambda *args: calls.append(("terminate", *args)) or 1
        ),
        CloseHandle=Mock(side_effect=lambda handle: calls.append(("close", handle)) or 1),
        GetHandleInformation=Mock(return_value=1),
        SetHandleInformation=Mock(return_value=1),
    )
    api.GetLastError = Mock(side_effect=lambda: api.last_error)
    api.SetLastError = Mock(
        side_effect=lambda error: setattr(api, "last_error", error)
    )
    return api, calls


def test_windows_job_assigns_suspended_process_before_resuming() -> None:
    api, calls = fake_kernel32()

    job = WindowsJob(19, 4321, api=api)
    job.close()
    job.close()

    assert calls.index(("assign", 20, 19)) < calls.index(("resume", 22))
    assert ("open_thread", 0x0002, False, 8765) in calls
    assert ("snapshot", 0x00000004, 0) in calls
    assert calls.count(("close", 20)) == 1
    information = api.SetInformationJobObject.call_args.args[2]
    limits = ctypes.cast(
        information, ctypes.POINTER(_JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
    ).contents
    assert limits.BasicLimitInformation.LimitFlags == 0x2000
    assert ctypes.sizeof(_THREADENTRY32) == 28


def test_windows_job_resume_failure_closes_job_and_kills_suspended_process() -> None:
    api, calls = fake_kernel32(resume_result=0xFFFFFFFF)

    with pytest.raises(OSError):
        WindowsJob(19, 4321, api=api)

    assert calls[-1] == ("close", 20)
    assert ("resume", 22) in calls


def test_windows_job_termination_covers_all_members() -> None:
    api, calls = fake_kernel32()
    job = WindowsJob(19, 4321, api=api)

    assert job.terminate() is True
    job.close()

    assert ("terminate", 20, 1) in calls
    assert job.terminate() is False


def test_kernel32_binding_is_exposed_on_the_api_object() -> None:
    api = object.__new__(_Kernel32)
    function = Mock()
    library = SimpleNamespace(CreateJobObjectW=function)

    api._bind(library, "CreateJobObjectW", [], None)

    assert api.CreateJobObjectW is function


def test_windows_thread_snapshot_retries_bad_length() -> None:
    api, calls = fake_kernel32()
    api.CreateToolhelp32Snapshot = Mock(side_effect=[0, 21])
    api.last_error = 24

    job = WindowsJob(19, 4321, api=api)
    job.close()

    assert api.CreateToolhelp32Snapshot.call_count == 2
    assert ("resume", 22) in calls


def test_windows_job_clears_accidental_handle_inheritance() -> None:
    api, calls = fake_kernel32()

    def inherited_handle(handle: int, pointer: object) -> int:
        pointer._obj.value = 1
        return 1

    api.GetHandleInformation = Mock(side_effect=inherited_handle)

    job = WindowsJob(19, 4321, api=api)
    job.close()

    api.SetHandleInformation.assert_called_once_with(20, 1, 0)
