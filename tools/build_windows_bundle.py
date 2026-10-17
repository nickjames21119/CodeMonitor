"""Build the Windows portable package: unzip and double-click, no Python installation needed.

    python tools/build_windows_bundle.py --python <dir of a Windows CPython 3.12 (python-build-standalone)>

Layout of the result (ResearchMonitor-<version>-windows-x64.zip):
    ResearchMonitor/
        Start ResearchMonitor.vbs     double-click: start background monitoring + open the setup page
        Stop ResearchMonitor.vbs      stop the background agent (your jobs keep running)
        Self-test.cmd                 end-to-end check on this computer (no e-mail sent)
        Command line.cmd              a console where `rmon ...` works
        README.txt                    Chinese quick start
        python/                       private Python 3.12 + psutil, nvidia-ml-py, keyring, researchmonitor
"""
from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STRIP_DIRS = ["tcl", "include", "libs", "Scripts", "Lib/tkinter", "Lib/idlelib", "Lib/turtledemo", "Lib/test",
              "Lib/ensurepip", "Lib/lib2to3", "Lib/pydoc_data", "Lib/venv/scripts/posix"]
STRIP_GLOBS = ["DLLs/_tkinter.pyd", "DLLs/tcl*.dll", "DLLs/tk*.dll", "DLLs/_test*.pyd", "DLLs/_ctypes_test.pyd",
               "DLLs/_msi.pyd", "Lib/site-packages/pip*", "Lib/turtle.py", "**/__pycache__"]

VBS_START = r'''' ResearchMonitor: start background monitoring and open the dashboard (no console window)
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
Set sh = CreateObject("WScript.Shell")
sh.CurrentDirectory = dir
sh.Run """" & dir & "\python\pythonw.exe"" -m researchmonitor start", 0, False
'''
VBS_STOP = r'''' ResearchMonitor: stop the background agent (programs being monitored keep running)
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
Set sh = CreateObject("WScript.Shell")
sh.Run """" & dir & "\python\pythonw.exe"" -m researchmonitor stop-agent", 0, True
MsgBox "ResearchMonitor stopped. / ResearchMonitor 已退出（正在运行的程序不受影响）。", 64, "ResearchMonitor"
'''
CMD_SELFTEST = "@echo off\r\nchcp 65001 >nul\r\ncd /d \"%~dp0\"\r\necho ResearchMonitor self-test ...\r\n" \
               "\"%~dp0python\\python.exe\" -m researchmonitor selftest\r\necho.\r\npause\r\n"
CMD_CONSOLE = ("@echo off\r\nchcp 65001 >nul\r\ncd /d \"%~dp0\"\r\n"
               "doskey rmon=\"%~dp0python\\python.exe\" -m researchmonitor $*\r\n"
               "echo ResearchMonitor command line. Try:  rmon jobs   rmon ls   rmon doctor   rmon --help\r\n"
               "cmd /k\r\n")
README = """ResearchMonitor 便携版（Windows）
================================

不需要安装 Python，也不需要改你运行实验的方式。

第一次使用
1. 如果是从网上下载的 zip：先右键 zip → 属性 → 勾选「解除锁定」→ 确定，再解压。
2. 解压到一个固定位置（例如 D:\\Tools\\ResearchMonitor）。开启开机自启后不要再移动这个文件夹。
3. 双击「Start ResearchMonitor.vbs」。浏览器会打开设置页：
   - 收件邮箱填你的邮箱；
   - 发信方式推荐 Resend：用收件邮箱在 resend.com 注册，创建 API Key 粘贴进来；
     或者用 QQ / 163 邮箱的「授权码」；
   - 点「保存并发送测试邮件」，确认收到（第一次请看看垃圾邮件文件夹）。
4. 可选：双击「Self-test.cmd」做一次本机自检（约 1 分钟，不发邮件）。

之后照常运行你的程序（命令行、VS Code、PyCharm、Jupyter 都可以）。
运行超过 2 分钟、看起来是实验的程序会被自动识别；结束时你会收到一封完整报告。
浏览器面板随时可以再打开：再次双击「Start ResearchMonitor.vbs」。

如果识别得不准：在面板首页对候选程序点「监控它」或「忽略」，或在设置页填关键词。
退出：双击「Stop ResearchMonitor.vbs」（正在运行的程序不受影响）。
数据位置：%USERPROFILE%\\.researchmonitor
"""


def strip(pydir: str) -> None:
    for d in STRIP_DIRS:
        shutil.rmtree(os.path.join(pydir, d), ignore_errors=True)
    for pat in STRIP_GLOBS:
        for p in glob.glob(os.path.join(pydir, pat), recursive=True):
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            elif os.path.exists(p):
                os.remove(p)
    ext = os.path.join(pydir, "EXTERNALLY-MANAGED")
    for p in glob.glob(os.path.join(pydir, "Lib", "EXTERNALLY-MANAGED")) + [ext]:
        if os.path.exists(p):
            os.remove(p)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", required=True, help="Windows CPython 3.12 directory (contains python.exe)")
    ap.add_argument("--wheel", required=True, help="researchmonitor wheel to bundle")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    args = ap.parse_args()
    version = os.path.basename(args.wheel).split("-")[1]
    work = os.path.join(args.out, "bundle")
    shutil.rmtree(work, ignore_errors=True)
    app = os.path.join(work, "ResearchMonitor")
    pydir = os.path.join(app, "python")
    shutil.copytree(args.python, pydir, ignore=lambda d, names: [n for n in names
                                                                 if os.path.islink(os.path.join(d, n))])
    strip(pydir)
    site = os.path.join(pydir, "Lib", "site-packages")
    os.makedirs(site, exist_ok=True)
    if shutil.which("uv"):
        # uv evaluates environment markers for the *target* platform (pip --platform does not), so Windows-only
        # dependencies such as pywin32-ctypes (keyring -> Windows Credential Manager) are included.
        pip = ["uv", "pip", "install", "--quiet", "--target", site, "--python-platform", "x86_64-pc-windows-msvc",
               "--python-version", "3.12", "--only-binary", ":all:"]
    else:
        pip = [sys.executable, "-m", "pip", "install", "--quiet", "--no-compile", "--target", site,
               "--platform", "win_amd64", "--python-version", "3.12", "--implementation", "cp",
               "--only-binary=:all:"]
    subprocess.check_call(pip + ["psutil>=5.9", "nvidia-ml-py>=11", "keyring>=23"])
    subprocess.check_call(pip + ["--no-deps", args.wheel])
    for p in glob.glob(os.path.join(site, "bin")):
        shutil.rmtree(p, ignore_errors=True)
    for junk in (".lock", "example.py", "README.txt"):  # stray top-level files shipped by some wheels / uv
        if os.path.exists(os.path.join(site, junk)):
            os.remove(os.path.join(site, junk))
    files = {"Start ResearchMonitor.vbs": VBS_START, "Stop ResearchMonitor.vbs": VBS_STOP}
    for name, text in files.items():
        # Windows Script Host reads UTF-16 LE with BOM as Unicode (needed for the Chinese message box text)
        with open(os.path.join(app, name), "w", encoding="utf-16", newline="\r\n") as f:
            f.write(text)
    with open(os.path.join(app, "Self-test.cmd"), "w", encoding="ascii", newline="") as f:
        f.write(CMD_SELFTEST)
    with open(os.path.join(app, "Command line.cmd"), "w", encoding="ascii", newline="") as f:
        f.write(CMD_CONSOLE)
    with open(os.path.join(app, "README.txt"), "w", encoding="utf-8-sig", newline="\r\n") as f:
        f.write(README)
    zpath = os.path.join(args.out, f"ResearchMonitor-{version}-windows-x64.zip")
    if os.path.exists(zpath):
        os.remove(zpath)
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for dirpath, _, names in os.walk(app):
            for n in sorted(names):
                full = os.path.join(dirpath, n)
                z.write(full, os.path.relpath(full, work))
    size = os.path.getsize(zpath) / 2**20
    print(f"built {zpath} ({size:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
