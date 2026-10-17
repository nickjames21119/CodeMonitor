# CodeMonitor

**Zero-config monitoring for long-running experiments — one e-mail report when your program finishes, fails, stalls or is interrupted.**

**零配置的长时间实验监控工具：程序结束、出错、卡住或被中断时，自动发一封完整的邮件报告。**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-%E2%89%A53.9-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

[English](#english) · [中文](#中文)

---

<a id="english"></a>

## English

### Overview

CodeMonitor watches the programs you already run — model training, inference, simulations, data processing — without changing how you start them and without being installed into your Python environment. It recognises your experiments among everything else running on the computer, follows their CPU / GPU / disk activity and their console output, and when a program ends it sends **one** e-mail explaining what happened and why.

### Features

- **Automatic detection.** A lightweight background agent scores running processes by features: interpreter (Python, R, Julia, MATLAB…), script name and experiment-like arguments (`train`, `eval`, `--epochs`, `--lr`…), CUDA compute, sustained CPU, memory, launched from a terminal / IDE, conda or venv interpreter. Browsers, chat apps, IDEs, package managers, notebook servers, language servers and web servers are excluded. Unsure cases can be confirmed with one click (*Watch* / *Ignore*).
- **Run-state timeline.** Every 15 s each job is classified as *GPU compute*, *CPU compute*, *disk I/O*, *light load*, *idle* or *paused*; consecutive states form a timeline. A job that stops computing and printing for a configurable time is reported as a *suspected stall* (it is never killed).
- **Reads output without code changes.** Redirected stdout, log files the program writes, growing log files in the script folder, the text of the program's **terminal window** (Windows) or its tmux pane (Linux). Progress (`Epoch k/N`, tqdm bars, ETA), evaluation metrics (`val_*`, `eval_*`, `test_*`, best values), checkpoint saves, completion messages and NaN losses are extracted.
- **Explains why a program ended.** Combines the real exit code (Windows, even for programs it did not start), the last error / traceback, the resource curve before the end (memory or GPU memory exhaustion, compute stopping abruptly), files written at the end and host restarts into a verdict with a confidence level and the evidence behind it — e.g. *CUDA out of memory (high)*, *interrupted by Ctrl+C (high)*, *most likely completed normally (medium)*.
- **One report per job.** Verdict, evidence, timeline, resource peaks, progress and metrics, files written, traceback and last output (secrets redacted), suggested next steps. Optional intermediate-result e-mails (rate-limited) and one-time alerts for stalls and NaN losses.
- **Reliable delivery.** Notifications are stored in a local SQLite outbox and retried with back-off; restarts and network outages do not lose reports. A job that ends while the computer is off is reported after the next start.
- **Lightweight.** One process at below-normal priority. Measured: ~0.14 % of one CPU core and ~29 MB RAM when idle, ~0.20 % while following a job.
- **Local-first and private.** Data stays on your computer; the dashboard listens on `127.0.0.1` only; credentials are kept in the Windows Credential Manager (or an owner-only file on Linux).
- **Optional power-loss alerts** through [healthchecks.io](https://healthchecks.io): if the computer dies while jobs run, you are alerted from outside the machine.

### Quick start — Windows (portable, no Python needed)

1. Download the Windows portable zip from [Releases](../../releases). Right-click → *Properties* → tick **Unblock**, then extract it to a permanent folder.
2. Double-click **`Start ResearchMonitor.vbs`**. The settings page opens in your browser.
3. Enter the recipient address, choose how e-mail is sent (see [E-mail delivery](#e-mail-delivery)), tick *Start automatically at login*, and click **Save and send test e-mail**.
4. Optional: double-click **`Self-test.cmd`** for an end-to-end check on this computer (about one minute, no e-mail is sent).

From now on just run your experiments as usual. Double-click `Start ResearchMonitor.vbs` again to open the dashboard; `Stop ResearchMonitor.vbs` stops monitoring (running programs are not affected).

### Quick start — Linux / macOS / from source

```bash
git clone https://github.com/nickjames21119/CodeMonitor.git
cd CodeMonitor
pip install .                 # optional GPU support: pip install ".[gpu]"
rmon start                    # starts the background agent and prints the dashboard link
rmon service install          # start automatically at login (systemd user service or crontab)
```

On Linux, redirect your program's output to a file (`python train.py > train.log 2>&1`) or run it inside **tmux** so the report can include the error text.

### E-mail delivery

| Method | What you need |
|---|---|
| **Resend** (recommended) | Sign up at [resend.com](https://resend.com) **with the recipient address**, create an API key. The test sender `onboarding@resend.dev` can only deliver to the address you signed up with. |
| QQ / 163 Mail | Enable SMTP in the mailbox settings and generate an **authorization code**. |
| Gmail | An app password (2-step verification required). |
| Other SMTP | Host, port, `ssl` / `starttls`, username and password. |

> Outlook.com / Hotmail no longer accept password-based SMTP. They work fine as the **recipient**; send through one of the methods above.

### Usage

**Dashboard** (`rmon dashboard`, or double-click `Start ResearchMonitor.vbs`): running jobs with live state and progress, detected-but-not-monitored candidates with *Watch* / *Ignore* buttons, finished jobs with their verdicts, delivery history and settings.

**Detection rules** — when a program is missed or picked up by mistake:

```bash
rmon watch train.py              # always monitor programs whose command line or folder contains this
rmon ignore my_web_server.py     # never monitor these
rmon jobs                        # what is monitored now, and the candidates with their scores
```

**Command line reference**

| Command | Purpose |
|---|---|
| `rmon start` / `rmon stop-agent` | Start / stop background monitoring |
| `rmon ls`, `rmon status [ID]` | Recent jobs; details of one job |
| `rmon logs [ID] -f` | Show or follow captured output |
| `rmon notifications`, `rmon retry` | Delivery history; re-send failed messages |
| `rmon test-email`, `rmon doctor` | Test delivery; check configuration |
| `rmon selftest` | End-to-end self-test (no e-mail sent) |
| `rmon run -- <command>` | *Precise mode*: start a program under supervision (real exit code on every OS, `--expect` result validation, `--timeout`) |

**Optional in-code hints** (no-ops when not monitored, standard library only):

```python
import researchmonitor as rm
rm.report(epoch=epoch, step=step, loss=float(loss))   # progress
rm.checkpoint(path)                                   # latest checkpoint
rm.result(acc=acc)                                    # final metrics
if rm.should_stop():                                  # graceful stop requested
    save(); break
```

### When e-mails are sent

| Event | Content | Frequency |
|---|---|---|
| Program ends (success, failure, interruption, host restart) | Full report with verdict, evidence, timeline, metrics, last output | **one per job** |
| New evaluation results appear in the output | Latest and best metrics, progress, ETA | rate-limited (default: at most every 2 h), can be turned off |
| No computation and no output for a long time | Suspected-stall alert (the job is not stopped) | at most once |
| Loss becomes NaN / Inf | Alert | at most once |
| Computer loses power or crashes (optional) | Sent by healthchecks.io | after ~10 min |

### How it works

```text
your program (unchanged) ──►  background agent (one process, low priority)
                                 ├─ every 20 s  process scan → feature score → start following
                                 ├─ every 15 s  CPU / memory / GPU / disk I/O → run-state timeline
                                 ├─ every 30–60 s  new log lines / terminal text → progress, metrics, errors
                                 ├─ on exit     exit code + output + resource curve + files → verdict
                                 └─ SQLite outbox → e-mail (retried) · local dashboard on 127.0.0.1
```

### Limitations

- On Linux the exit code of a process that CodeMonitor did not start cannot be read (an OS restriction); the verdict then relies on output, resources and files. Use `rmon run` when an exact exit code matters.
- Output printed to a plain Linux terminal (not tmux) cannot be read from outside.
- Programs started without a console on Windows (e.g. `pythonw`) only provide output through log files.
- Jobs inside WSL appear to Windows as `vmmem`; run a Linux copy of CodeMonitor inside WSL.
- Detection is heuristic; use *Watch* / *Ignore* to correct it.

### Development

```bash
pip install -e ".[test]"
pytest                                                   # unit, end-to-end and dashboard tests
python tools/build_windows_bundle.py --python <win-cpython-dir> --wheel dist/<wheel>   # Windows portable zip
```

Data directory: `%USERPROFILE%\.researchmonitor` (Windows) or `~/.researchmonitor`; override with `RMON_HOME`.

### License

[MIT](LICENSE)

---

<a id="中文"></a>

## 中文

### 简介

CodeMonitor 用来监控你平时运行的程序，包括模型训练、推理、仿真和数据处理。它**不需要改变你启动程序的方式，也不需要装进你的 Python 环境**。它会从电脑上正在运行的进程中认出你的实验，跟踪 CPU、GPU、磁盘活动和程序输出；程序结束时，它会发**一封**邮件，说明发生了什么、为什么。

### 功能

- **自动识别**
  - 后台程序按特征给每个进程打分，加分项包括：解释器（Python、R、Julia、MATLAB…）、脚本名和实验类参数（`train`、`eval`、`--epochs`、`--lr`…）、CUDA 计算、持续占用 CPU、内存大、由终端或 IDE 启动、使用 conda / venv 解释器。
  - 以下程序一律排除：浏览器、聊天软件、IDE、包管理器、Jupyter 服务端、语言服务器、Web 服务器。
  - 拿不准的程序，可以在面板上一键「监控它 / 忽略」。
- **运行状态时间线**
  - 每 15 秒把任务归为一种状态：GPU 计算、CPU 计算、数据读写、轻负载、空闲或暂停，连起来就是一条时间线。
  - 程序长时间既不计算也不输出时，会提醒「疑似卡死」，但不会结束程序。
- **不改代码也能读输出**
  - 能读的来源：重定向的输出文件、程序写的日志、脚本目录中增长的日志、Windows 上程序**终端窗口里的文字**、Linux 上的 tmux 窗格。
  - 能提取的内容：进度（`Epoch k/N`、tqdm 进度条、剩余时间）、评估指标（`val_*`、`eval_*`、`test_*` 及其最好值）、checkpoint 保存、完成信号、NaN loss。
- **说明结束原因**
  - 综合这些证据下结论：真实退出码（Windows 上不是本软件启动的程序也能读到）、最后的报错和 traceback、结束前的资源曲线（内存或显存耗尽、计算突然停止）、最后写出的文件、电脑是否重启。
  - 结论附带置信度和依据，例如「CUDA 显存不足（高）」「被 Ctrl+C 中断（高）」「很可能正常完成（中）」。
- **每个任务一封报告**
  - 报告内容：结论与依据、时间线、资源峰值、进度与指标、写出的文件、报错和最后输出（已隐去密钥类信息）、处理建议。
  - 可选的中间结果邮件有频率上限；疑似卡死和 NaN 各最多提醒一次。
- **可靠送达**：邮件先存进本地 SQLite 发件箱，失败会自动重试，重启或断网都不会丢。电脑关机期间结束的任务，会在下次开机后补发报告。
- **轻量**：只有一个低优先级进程。实测空闲时约占单核 CPU 的 0.14%、内存约 29 MB；跟踪任务时约 0.20%。
- **本地优先、注重隐私**：数据只存在本机；面板只监听 `127.0.0.1`；密码和密钥存在 Windows 凭据管理器里（Linux 上存为仅本人可读的文件）。
- **可选的断电 / 死机提醒**：通过 [healthchecks.io](https://healthchecks.io) 实现。任务运行中电脑失联时，由外部服务发邮件提醒你。

### 快速开始：Windows 便携版（无需安装 Python）

1. 从 [Releases](../../releases) 下载 Windows 便携版 zip。右键 → 属性 → 勾选「**解除锁定**」，再解压到一个固定的文件夹。
2. 双击 **`Start ResearchMonitor.vbs`**，浏览器会打开设置页。
3. 填写收件邮箱，选择发信方式（见[发信方式](#发信方式)），勾选「开机后自动开始监控」，点「**保存并发送测试邮件**」。
4. 可选：双击 **`Self-test.cmd`** 做一次本机端到端自检，约 1 分钟，不发邮件。

之后照常运行你的实验即可。再次双击 `Start ResearchMonitor.vbs` 会打开面板；双击 `Stop ResearchMonitor.vbs` 会退出监控，正在运行的程序不受影响。

### 快速开始：Linux / macOS / 源码安装

```bash
git clone https://github.com/nickjames21119/CodeMonitor.git
cd CodeMonitor
pip install .                 # 需要 GPU 监控：pip install ".[gpu]"
rmon start                    # 启动后台监控，并打印面板链接
rmon service install          # 开机自启（systemd 用户服务或 crontab）
```

在 Linux 上，请把程序输出重定向到文件（`python train.py > train.log 2>&1`），或在 **tmux** 中运行，这样报告里才能带上报错原文。

### 发信方式

| 方式 | 需要准备 |
|---|---|
| **Resend**（推荐） | 用**收件邮箱**在 [resend.com](https://resend.com) 注册并创建 API Key。测试发件人 `onboarding@resend.dev` 只能发给注册时用的那个邮箱。 |
| QQ / 163 邮箱 | 在邮箱设置里开启 SMTP，生成**授权码**。 |
| Gmail | 应用专用密码（需先开启两步验证）。 |
| 其他 SMTP | 服务器、端口、`ssl` / `starttls`、用户名和密码。 |

> Outlook.com / Hotmail 已不支持用密码登录 SMTP。它们可以正常作为**收件邮箱**，发信请用上表中的方式。

### 使用方法

**面板**（`rmon dashboard`，或双击 `Start ResearchMonitor.vbs`）包括：
- 正在运行的任务，以及它们的实时状态和进度；
- 识别到但未监控的候选程序，每个都有「监控它 / 忽略」按钮；
- 已结束的任务及其结论；
- 邮件发送记录；
- 设置。

**识别规则**：某个程序漏识别或被误识别时使用：

```bash
rmon watch train.py              # 命令行或目录中包含该文字的程序一定监控
rmon ignore my_web_server.py     # 一定不监控
rmon jobs                        # 查看正在监控的任务，以及候选程序和它们的得分
```

**常用命令**

| 命令 | 作用 |
|---|---|
| `rmon start` / `rmon stop-agent` | 启动 / 停止后台监控 |
| `rmon ls`、`rmon status [ID]` | 最近的任务；某个任务的详情 |
| `rmon logs [ID] -f` | 查看或实时跟踪捕获到的输出 |
| `rmon notifications`、`rmon retry` | 查看邮件记录；重发失败的邮件 |
| `rmon test-email`、`rmon doctor` | 测试发信；检查配置 |
| `rmon selftest` | 端到端自检（不发邮件） |
| `rmon run -- <命令>` | **精确模式**：由本软件启动程序，任何系统上都能拿到真实退出码，并支持 `--expect` 结果校验和 `--timeout` |

**可选：在代码里提供更多信息**（不被监控时什么都不做，只依赖标准库）：

```python
import researchmonitor as rm
rm.report(epoch=epoch, step=step, loss=float(loss))   # 进度
rm.checkpoint(path)                                   # 最近的 checkpoint
rm.result(acc=acc)                                    # 最终指标
if rm.should_stop():                                  # 收到停止请求时优雅退出
    save(); break
```

### 什么时候发邮件

| 事件 | 内容 | 频率 |
|---|---|---|
| 程序结束（成功、失败、中断、电脑重启） | 完整报告：结论、依据、时间线、指标、最后输出 | **每个任务一封** |
| 输出中出现新的评估结果 | 最新和最好的指标、进度、预计剩余时间 | 有频率上限（默认最多每 2 小时一封），可关闭 |
| 长时间没有计算也没有输出 | 疑似卡死提醒（不会结束程序） | 最多一次 |
| loss 变为 NaN / Inf | 提醒 | 最多一次 |
| 电脑断电或死机（可选） | 由 healthchecks.io 发出 | 约 10 分钟后 |

### 工作原理

```text
你的程序（无需改动） ──►  后台监控（单进程，低优先级）
                            ├─ 每 20 秒   扫描进程 → 特征打分 → 开始跟踪
                            ├─ 每 15 秒   CPU / 内存 / GPU / 磁盘 IO → 运行状态时间线
                            ├─ 每 30–60 秒 新日志行 / 终端文字 → 进度、指标、报错
                            ├─ 结束时     退出码 + 输出 + 资源曲线 + 文件 → 结论
                            └─ SQLite 发件箱 → 邮件（自动重试） · 本地面板 127.0.0.1
```

### 已知限制

- Linux 上读不到不是由本软件启动的进程的退出码（系统限制），这时结论依据输出、资源和文件来判断。需要精确退出码时，请用 `rmon run`。
- 普通 Linux 终端（非 tmux）里的输出无法从外部读取。
- Windows 上没有控制台窗口的程序（如 `pythonw`）只能通过日志文件读取输出。
- WSL 里的任务在 Windows 侧只显示为 `vmmem` 进程，请在 WSL 内另外运行一份 CodeMonitor。
- 识别是启发式的，可以用「监控它 / 忽略」纠正。

### 开发

```bash
pip install -e ".[test]"
pytest                                                   # 单元、端到端和面板测试
python tools/build_windows_bundle.py --python <win-cpython-dir> --wheel dist/<wheel>   # 打包 Windows 便携版
```

数据目录：Windows 为 `%USERPROFILE%\.researchmonitor`，Linux 为 `~/.researchmonitor`；可用环境变量 `RMON_HOME` 修改。

### 许可证

[MIT](LICENSE)
