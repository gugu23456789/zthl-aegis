# ZTHL Aegis v0.9.4.1 — 发布说明

> 本说明为人工撰写。v0.9.4.1 是 v0.9.4 的**补丁版**：修 CI 门的依赖缺失与
> Windows 解释器解析缺陷，并把「隔离虚拟环境跑一遍」固化成 CI 作业。无新功能。

## 1. 为什么发这个补丁

v0.9.4 发布后，公开仓 CI 有三个问题：

1. `package + hook integrity` 整 job 红：它跑 `python -m pytest`，但**没有安装 pytest**，
   报错是 `No module named pytest`，不是测试失败。
2. `platform smoke (windows-latest)` 红：解释器解析器在 Windows 上把
   `GK_PY_GLOBS` 里的 `C:\...\py-good` 按 `:` 切开（盘符冒号被当分隔符），候选丢失。
3. 平台判定依赖外部命令 `uname`；测试清空 `PATH` 后取不到，回落成 `wsl`，放大问题 2。

v0.9.4 的发布物包含上述 Windows 解析缺陷，因此补丁版重打发布面。

## 2. 修复

### 2.1 CI 依赖

- `ci.yml` 的 `package-integrity` 增加 `install test deps`（`pip install pytest`）。

### 2.2 解释器解析（`scripts/py_resolve.sh`）

- 平台判定先看 bash 内建 `OSTYPE`（`msys*` / `cygwin*` / `win32*`），`uname` 仅兜底。
- `GK_PY_GLOBS` 多组分隔符按平台区分：POSIX `:`、Windows `;`。
- 两处平台判定同步，避免 `_accept_py.local` 分支重新走回 `uname`。

### 2.3 解析器测试（`scripts/test_py_resolve.py`）

判据不变，只做 Windows 适配：

- 传给 bash 的脚本路径与环境变量统一为 POSIX 形态（`C:/...`）；反斜杠会让
  `BASH_SOURCE` 归一成 `.`，导致 `_root` 算错。
- Windows 布局用例改用**真 venv**（`python -m venv`）代替「改名成 `.exe` 的 shell 脚本」；
  Windows 不执行文本 exe。
- 路径断言用 `cygpath -w` / `os.path.normcase` 归一，避免 `/tmp` 与 `C:\...` 形态差异误报。

### 2.4 新增 `venv (isolated interpreter)` 作业

从零建 `.venv`、装依赖，先断言 `command -v python` 指向 venv，再跑：

- `bash scripts/ci_smoke.sh`（语法 / 编译 / 17 个快速测试）
- 5 个可移植测试文件（pack / py_resolve / opcap alias / package integrity / hook manage）

目的：不再依赖 runner 自带 site-packages，依赖缺失会在建 venv 这一步显式暴露。

## 3. 验证

- 公开仓 CI：`smoke`、`security audit`、`platform smoke (ubuntu-24.04)`、
  `platform smoke (windows-latest)`、`package + hook integrity` 全部 success
  （run `41449509168`；`venv-gate` 随本版新增）。
- 本地：Linux `/opt/spz-py312` 下 `test_py_resolve` 11 passed、
  `test_gk_package_integrity + test_gk_hook_manage` 31 passed；
  Windows（Git Bash）下 `test_py_resolve` 11 passed。
- 导出：见 §5。

## 4. 升级

- 覆盖安装即可，无状态迁移；`install.sh` / `uninstall.sh` 未变。
- 若你在 Windows 上把 `GK_PY_GLOBS` 写成多组，请改用 `;` 分隔（单组不受影响）。

## 5. 产物

```
zthl-aegis-v0.9.4.1.zip
SHA256SUMS
release-manifest.json
```

## 6. 已知限制

- `full regression (self-hosted WSL)` 仍是手动触发的自托管作业，不在公开 runner 常规门内。
- `$WinREAgent` 等系统级残留不在本仓职责内。
