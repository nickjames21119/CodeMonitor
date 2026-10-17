# ResearchMonitor 实施方案与 V1 实现说明

日期：2026-10-16　·　对应设计文档：`ModelDesign.md` v1.0

## 0. 结论

先在你自己的电脑上做一个**能独立工作的单机版**，把设计文档里最值钱的三件事做扎实：**拿到真实结果**（进程监督 + 结果校验）、**消息一定送到**（持久化发件箱 + 重试）、**电脑挂了也有人知道**（外部看门狗）。事件单 / 确认 / 升级提醒也先在本机实现，等单机版在真实训练上用一两周、证明可靠后，再把同一套事件模型推到 V2 服务器和 V3 Slurm。

## 1. 几个关键判断

| # | 判断 | 理由 | 落在代码哪里 |
|---|---|---|---|
| 1 | **Outlook 只收信，不发信** | 微软已关闭 Outlook.com 的 SMTP 基本认证和应用密码，只剩 OAuth（需要 Azure 应用注册，不适合个人工具）。改用 Resend（HTTPS API，用 Outlook 地址注册即可发给自己）或 QQ/163 授权码 SMTP。 | `notify/channels.py` |
| 2 | **远程看门狗先外包给 healthchecks.io** | 原则 2「远程监控必须独立于被监控主机」。自建服务器是 V2 的工作量；healthchecks.io 免费、本身就是 dead-man's switch，且能经 API 在空闲时暂停，避免关机误报。 | `heartbeat.py` |
| 3 | **每个任务一个独立的小监控进程**，而不是一个大守护进程托管所有任务 | 原则 1。监控进程脱离终端（Linux 新 session，Windows DETACHED + 尝试脱离 Job Object），所以关终端、关面板、agent 重启都不影响任务；它是任务的父进程，能拿到**权威退出码**。 | `supervisor.py` |
| 4 | **任务输出直接写文件，不走管道** | 设计 §14.1 要求持续读管道防死锁；直接把 stdout/stderr 交给日志文件从根上消除死锁，而且监控进程即使崩溃，任务也不会因管道断开而死。 | `supervisor.run_managed` |
| 5 | **状态变化与通知在同一个 SQLite 事务里入队**（outbox 模式） | 原则 7。断网、重启都不丢；按 `group_key` 幂等；租约式领取保证多个进程不会同时发同一封；SMTP 无法做到 exactly-once，保留每次尝试的审计。 | `store.py` `notify/__init__.py` |
| 6 | **证据强度决定状态能否被覆盖** | 父进程退出码(3) > 附着观察(2) > 恢复推断(1)。终态只能被更强证据改写，绝不回退到运行中（T09）。 | `store.transition` |
| 7 | **attach 模式结局是 UNKNOWN**，附带“推测原因” | 原则 3、4：非子进程的退出码拿不到，就不假装知道。日志里的 traceback、结果校验作为推测证据单列，置信度标为 inferred。 | `supervisor.finish_watch` |
| 8 | **严重级别按影响定** | 运行 ≥2 h 或 `--priority high` 的失败是 P1（会提醒），短任务是 P2，成功是 P3；同主机同原因 ≥3 个任务失败升为 P0。 | `engine.severity_for` |
| 9 | **本地 Web 面板代替 PySide6 桌面程序** | 零额外依赖，Windows/Linux 一样，和 V2 的 Web 面板同一套页面结构。只监听 127.0.0.1，一次性登录链接 + CSRF + Host 校验；所有改状态的操作都是 POST。 | `dashboard.py` |

## 2. 需求覆盖（设计 §2.1）

| ID | 需求 | V1 状态 |
|---|---|---|
| FR-01/02/03 | 监控执行、成功、异常终止 | ✅ 托管模式拿真实退出码；Linux 信号、Windows NTSTATUS 解码 |
| FR-04/05 | 邮件、附结果与错误报告 | ✅ 中/英 HTML+纯文本；traceback 摘录、输出末尾附件、小文件附件、大文件给路径+SHA-256 |
| FR-06 | 不改源码监控已有进程 | ✅ `rmon attach`（UNKNOWN 语义） |
| FR-07 | CPU/RAM/GPU/磁盘 | ✅ 进程树采样；NVML 或 nvidia-smi；显存区分“本进程”与“整卡” |
| FR-08 | 卡死检测 | ✅ 有进度记录按进度间隔自适应阈值，否则看输出/CPU/GPU 活动；只警告不杀 |
| FR-09/10 | 独立远程监控、断连检测 | ✅（外包）healthchecks.io；重启后本机补报 HOST_REBOOTED |
| FR-11 | 未发送事件持久化重试 | ✅ 指数退避约 12 h；无 agent 时由结束的监控进程继续重试 |
| FR-12/13/14 | 严重级别、确认、升级 | ✅ P0–P3；CLI/面板确认；按级别提醒；snooze |
| FR-15 | 桌面与 Web 面板 | ✅ 本地 Web 面板（见判断 9） |
| FR-16 | Slurm | ⏳ V3 |
| FR-17 | 历史记录 | ✅ runs / events / incidents / notifications / 采样 |
| FR-18 | 多台设备 | ⏳ V2（每台机器可各自安装，共用同一个收件箱和看门狗账号） |
| FR-19 | 团队值班 | ⏳ V3 |
| FR-20 | 自动诊断 | ✅ 失败分类 + 每类 runbook |
| FR-21 | 自动恢复 | ❌ 按设计默认关闭（不自动改配置、不自动重启） |

## 3. 测试用例（设计 §18.1）

`pytest` 共 62 项，Linux 上 Python 3.9 与 3.13 全部通过；`rmon selftest` 在用户机器上复跑核心路径。

| 用例 | 状态 | 用例 | 状态 |
|---|---|---|---|
| T01 正常退出 | ✅ | T11 P1 未确认升级 | ✅ |
| T02 Python 异常 | ✅ | T12 确认后停止升级 | ✅ |
| T03 退出 0 但缺结果 | ✅（含旧文件、NaN、JSON 损坏） | T13 未授权确认 | ✅（无会话 / 错 CSRF / 外部 Host / 外部 Origin / GET） |
| T04 附着进程消失 | ✅ UNKNOWN | T14 日志含密钥 | ✅ 脱敏 |
| T05 监控进程崩溃 | ✅ 任务存活则接管，都死则 LOST | T15 卡死 | ✅ 只警告，恢复后自动解除 |
| T06 断网 | ✅ 本地保留、恢复后送达 | T16–T18 Slurm | ⏳ V3 |
| T07 断电 | ✅ 外部看门狗 + 重启后补报 | T19 PID 复用 | ✅ (pid, 启动时间) 双重身份 |
| T08 重复投递 | ✅ 幂等入队、排他领取 | T20 大文件 | ✅ 只给路径与 SHA-256 |
| T09 乱序 | ✅ 不回退 | T10 邮件超时 | ✅ 有界重试 + 审计 |

另有：超时终止、取消整棵进程树、`should_stop()` 优雅停止、关闭终端任务不受影响、NaN loss、机器层面失败合并为一个事件单与一封汇总邮件、代码层面失败按项目归并、恢复推断被真实结果纠正、Resend/SMTP/Webhook 通道、QQ 邮箱异常 QUIT 回复不重发、带 BOM / GBK 的配置与结果文件。

## 3.1 独立代码审查（2026-10-16）

交付前请另一个审查者通读全部代码，重点看 Windows。发现并已修复：QQ 邮箱对 QUIT 回复异常导致同一封邮件被重复发送（最严重）；记事本保存的带 BOM 配置 / PowerShell 或 GBK 写的结果 JSON 被误判；Windows 下相对路径程序和 .bat 在任务目录里找不到；`--shell` 丢失带空格参数的引号；恢复推断 LOST 后真实结果到来时纠正邮件被吞、旧事件单继续提醒；事件归并过宽导致误报 P0；`--notify none` 仍会发提醒；同一任务可能被两个接管进程同时监控；无 agent 时发信超时会让监控循环卡住约 2 分钟；Windows 无优雅停止（新增 `should_stop()`）；Windows 快速启动关机被误判为监控崩溃；Windows 上面板端口可能与其它程序共用。每一项都补了回归测试。

## 4. 与设计文档不同的地方

1. 远程服务器（FastAPI + PostgreSQL）推迟到 V2；V1 用 healthchecks.io 满足“独立于主机”。
2. 桌面 GUI 用本地 Web 面板代替 PySide6。
3. 本地数据库表：`runs / events / samples / incidents / incident_events / notifications / notification_attempts / kv`，事件带全局唯一 `event_id` 和自增序号，V2 可直接按序号上传。
4. 新增失败码：`NONZERO_EXIT`（非零退出且无可识别错误）、`HOST_REBOOTED`、`NAN_LOSS`、`RESOURCE_*`、`ENDED_UNKNOWN`。
5. 新增 `--timeout`（本地 wall-time 限制，结果为 TIMED_OUT）、`should_stop()` 协作式停止，以及 Windows 下运行期间阻止系统睡眠。
7. 事件归并分两类：机器层面原因按主机归并并可升为 P0、合并成汇总邮件；代码层面原因按 主机+原因+项目 归并，每次运行仍发完整报告。
6. 邮件确认链接没有做：本机面板外网不可达；按 §7.6，确认不能是 GET 链接，远程确认放到 V2。

## 5. 已知限制

- **Windows 路径尚未在真机验证**（开发环境是 Linux）。代码按 Windows 语义编写并经过独立审查，`rmon selftest` 就是为第一次在你电脑上验证准备的。
- Windows 上 `rmon stop` 对不调用 `should_stop()` 的程序是直接终止（没有 Ctrl+C 可用）。
- 没有 agent 时，监控进程死掉、你过了很久才再运行 rmon，会被归为“电脑关机/睡眠/重启”一类（证据写在邮件里）；开着 agent 时 30 秒内就能区分。
- 远程确认（手机上点 ACK）要等 V2。
- 任务日志不轮转；输出极多的程序（如每步打印的进度条）日志会变大，和自己重定向到文件一样。
- GPU 仅支持 NVIDIA；Windows WDDM 模式下拿不到单进程显存，邮件会注明“整卡显存”。
- Linux 若 `KillUserProcesses=yes`，注销会杀掉用户进程；`rmon doctor` 会提示。

## 6. 下一步

| 阶段 | 内容 | 完成标准 |
|---|---|---|
| **现在** | 装到你的电脑，`rmon selftest` → 配置 Resend 与 healthchecks → 用一次真实训练 | 收到成功/失败邮件；拔网线或关机测试看门狗告警 |
| V1.1（1–2 周试用后） | 修试用中发现的问题；`rmon prune` 清理旧数据；日志大小上限；可选系统托盘 | 连续两周无漏报、无误报 |
| V2 远程服务器 | 小云主机上的 FastAPI + PostgreSQL；agent 上传事件（复用本地 outbox 与 event 序号）；服务器端看门狗替代 healthchecks；手机网页 ACK（POST + 签名） | 设计 §18.2 验收 1–6 |
| V3 HPC 与团队 | Slurm 适配器（`sacct` 轮询、区分 job step / array）、多用户、值班表、备份响应人 | T16–T18；在学校集群实测 |

设计 §21 的开放问题在个人模式下的选择：发信 = Resend 或 QQ/163 SMTP；远程 = healthchecks.io（V2 再定机构/云）；P1 = 邮件 + 可选推送（ntfy / Server酱 / Webhook）；单用户；本地数据默认永久保留；校验按项目在 `rmon.toml` 中声明；默认不做任何自动恢复。
