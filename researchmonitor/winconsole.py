"""Read what a job printed to its terminal, without the job writing a log file.

Windows: a short-lived helper process attaches to the job's console (AttachConsole) and copies the text
of its screen buffer. The helper — not the agent — attaches, so the agent can never be affected by
console events (e.g. the user closing that terminal at the same moment). The job's console outlives the
job while its terminal window stays open, so the final traceback can be read by attaching through the
parent shell's PID after the job has exited.

Linux: if the job runs inside tmux, `tmux capture-pane` returns the pane's recent output. A plain
terminal (pty) cannot be read from outside; redirect to a file or use tmux.
"""
from __future__ import annotations

import os
import subprocess
import sys

IS_WIN = sys.platform == "win32"
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008

# Runs inside the helper (python -I -S -c ...). Kept dependency-free and tiny.
_HELPER = r'''
import ctypes, sys
from ctypes import wintypes as W
k = ctypes.WinDLL("kernel32", use_last_error=True)
class COORD(ctypes.Structure): _fields_ = [("X", W.SHORT), ("Y", W.SHORT)]
class SMALL_RECT(ctypes.Structure): _fields_ = [("L", W.SHORT), ("T", W.SHORT), ("R", W.SHORT), ("B", W.SHORT)]
class CSBI(ctypes.Structure):
    _fields_ = [("dwSize", COORD), ("dwCursorPosition", COORD), ("wAttributes", W.WORD),
                ("srWindow", SMALL_RECT), ("dwMaximumWindowSize", COORD)]
k.AttachConsole.argtypes = [W.DWORD]
k.CreateFileW.restype = W.HANDLE
k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
k.GetConsoleScreenBufferInfo.argtypes = [W.HANDLE, ctypes.POINTER(CSBI)]
k.ReadConsoleOutputCharacterW.argtypes = [W.HANDLE, W.LPWSTR, W.DWORD, COORD, ctypes.POINTER(W.DWORD)]
k.SetConsoleCtrlHandler.argtypes = [W.LPVOID, W.BOOL]
pids = [int(x) for x in sys.argv[1].split(",") if x]
maxl = int(sys.argv[2])
k.SetConsoleCtrlHandler(None, True)
k.FreeConsole()
ok = False
for pid in pids:
    if k.AttachConsole(pid):
        ok = True
        break
if not ok:
    sys.exit(3)
k.SetConsoleCtrlHandler(None, True)
h = k.CreateFileW("CONOUT$", 0xC0000000, 3, None, 3, 0, None)
if not h or h == W.HANDLE(-1).value:
    sys.exit(4)
info = CSBI()
if not k.GetConsoleScreenBufferInfo(h, ctypes.byref(info)):
    sys.exit(5)
import unicodedata
w = info.dwSize.X
last = info.dwCursorPosition.Y
first = max(0, last - maxl + 1)
buf = ctypes.create_unicode_buffer(w + 1)
lines, pending = [], ""
for y in range(first, last + 1):
    got = W.DWORD(0)
    if not k.ReadConsoleOutputCharacterW(h, buf, w, COORD(0, y), ctypes.byref(got)):
        continue
    raw = buf[:got.value]
    cells = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in raw.rstrip())
    pending += raw.rstrip() if cells < w else raw
    if cells < w:              # the row did not fill the screen width: the logical line ends here
        lines.append(pending)
        pending = ""
if pending:
    lines.append(pending)
while lines and not lines[-1].strip():
    lines.pop()
k.FreeConsole()
sys.stdout.buffer.write(("\n".join(lines)).encode("utf-8", "replace"))
'''


def _helper_python() -> str | None:
    # a venv's python.exe is a redirector that starts the base interpreter as a *new* console process
    exe = getattr(sys, "_base_executable", None) or sys.executable
    d = os.path.dirname(exe)
    for name in ("python.exe", "pythonw.exe"):  # console-subsystem python + DETACHED_PROCESS = no console, real pipes
        cand = os.path.join(d, name)
        if os.path.exists(cand):
            return cand
    return exe or None


def read_windows_console(pids, max_lines: int = 300, timeout: float = 5.0) -> list[str] | None:
    """Text of the console shared by the first PID in `pids` that has one (job, then its parent shell)."""
    if not IS_WIN:
        return None
    py = _helper_python()
    if not py:
        return None
    try:
        r = subprocess.run([py, "-I", "-S", "-c", _HELPER, ",".join(str(p) for p in pids if p), str(max_lines)],
                           capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
                           creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return r.stdout.decode("utf-8", "replace").split("\n")


def tmux_target(proc) -> tuple | None:
    """(socket, pane) when the process runs inside tmux."""
    try:
        env = proc.environ()
    except Exception:
        return None
    pane, tmux = env.get("TMUX_PANE"), env.get("TMUX")
    if not pane or not tmux:
        return None
    return tmux.split(",")[0], pane


def read_tmux(target, max_lines: int = 300, timeout: float = 5.0) -> list[str] | None:
    if not target:
        return None
    sock, pane = target
    try:
        r = subprocess.run(["tmux", "-S", sock, "capture-pane", "-p", "-J", "-t", pane, "-S", f"-{max_lines}"],
                           capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    rows = r.stdout.decode("utf-8", "replace").split("\n")
    while rows and not rows[-1].strip():
        rows.pop()
    return rows


_PROGRESS_ROW = None


def _stable(row: str) -> bool:
    """Rows that do not change in place (progress bars and spinners are redrawn constantly)."""
    global _PROGRESS_ROW
    if _PROGRESS_ROW is None:
        import re
        _PROGRESS_ROW = re.compile(r"\d+%\||\d+/\d+\s*\[|it/s\]|s/it\]|[█▉▊▋▌▍▎▏#=>-]{6,}|^\s*[|/\\-]\s*$")
    return bool(row.strip()) and not _PROGRESS_ROW.search(row)


def new_lines(prev: list[str], cur: list[str]) -> list[str]:
    """Lines in `cur` that were not in the previous snapshot of the same scrolling screen.

    Anchors on the last *stable* rows of the previous snapshot (never on a progress bar, which redraws in
    place). If no anchor is found the screen was cleared or scrolled too far: return nothing rather than
    re-reading old lines (which would duplicate metrics and completion messages)."""
    if not prev:
        return cur
    prev_st = [x for x in prev if _stable(x)]
    cur_idx = [i for i, x in enumerate(cur) if _stable(x)]
    for k in (4, 2, 1):
        if len(prev_st) < k or len(cur_idx) < k:
            continue
        anchor = prev_st[-k:]
        for j in range(len(cur_idx) - k, -1, -1):
            if [cur[cur_idx[j + t]] for t in range(k)] == anchor:
                return cur[cur_idx[j + k - 1] + 1:]
    return []
