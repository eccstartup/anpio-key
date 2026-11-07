#!/bin/bash
# One-command installation for anpio-key.
#
# Run from a reviewed checkout:
#   ./install.sh
#
# The script builds as you, then asks sudo to create the service accounts,
# install the binary and start the service. It never asks for or stores an
# identity passphrase.
set -euo pipefail

die() { echo "install: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法: ./install.sh [选项]

不带选项时:
  - Linux: 构建并安装 Linux 受保护服务，创建一个默认 Agent 账号 anp-agent
  - macOS: 构建并安装本机预览，使用 _anpagent 账号

选项:
  --admin-user NAME   管理员登录账号（默认 sudo 调用者或当前用户）
  --agent-user NAME   Agent 系统账号，可重复（Linux 默认 anp-agent）
  --tpm-device [PATH] 授予服务访问 TPM 设备，默认 /dev/tpmrm0（仅 Linux）
  --binary PATH       使用已构建的程序，跳过构建
  --sha256 HASH       使用给定的 SHA-256，跳过计算
  --dry-run           只打印计划，不做任何修改
  --status            只读显示安装状态、运行状态和已安装摘要
  --verify            对已安装服务跑只读验收，失败退出 3
  --upgrade           用当前构建替换已安装二进制，保留配置和状态
  --uninstall         停止服务并删除二进制和服务单元，保留配置、状态和账号
  -h, --help          显示本帮助

接管已有命名钥匙身份（macOS 本机预览，安装后、空服务）:
  --adopt             把 anpio-cli 建的命名钥匙身份迁入受保护服务
  --identity FILE     anpio-cli 的 identity.json（绝对路径）
  --cli-binary PATH   已构建的 anpio-cli（绝对路径）
  --cli-sha256 HASH   anpio-cli 的 SHA-256
  --source-root DIR   命名钥匙库，默认管理员主目录下的 .anpio-key
  --target URL        Agent 要访问的完整 HTTPS URL，可重复（至少一个）
  --method METHOD     允许的方法，可重复，默认 POST
  --body-bytes N      有请求体的方法允许的最大字节数，默认 1048576
  --grant-days N      grant 有效天数，默认 30
  --max-uses N        grant 最多签名次数，默认 100
  --enable-ecdh       同时打开 ECDH 数据平面开关（不创建 ECDH grant）

初始化新身份（老路：受保护迁移用；macOS 只用于本机预览）:
  --bootstrap         安装后创建新身份、迁入受保护状态并创建一张 grant
  --did-host HOST     DID 文档所在域名，例如 agents.example.com
  --did-path PATH     DID 路径，默认 agents/anpio-key
  --target URL        Agent 要访问的完整 HTTPS URL
  --method METHOD     允许的方法，可重复，默认 GET
  --body-bytes N      有请求体的方法允许的最大字节数，默认 1048576
  --grant-days N      grant 有效天数，默认 1
  --max-uses N        grant 最多签名次数，默认 100

示例:
  ./install.sh
  ./install.sh --status
  ./install.sh --verify
  ./install.sh --upgrade
  ./install.sh --uninstall
  ./install.sh --agent-user agent-a --agent-user agent-b
  ./install.sh --tpm-device
  sudo ./install.sh --adopt --identity /Users/me/.anpio-cli/agent/default/identity.json \
    --cli-binary /Users/me/anpio-cli/target/release/anpio-cli --cli-sha256 VERIFIED_SHA256 \
    --target https://awiki.me/anp-im/rpc --target https://awiki.me/user-service/v1/did-auth/rpc
  ./install.sh --bootstrap --did-host agents.example.com \
    --target https://api.example.com/v1/status
  sudo ./install.sh --binary /root/anpio-key --sha256 VERIFIED_SHA256 --admin-user operator

不带 --bootstrap / --adopt 时只创建空服务。全新身份用 `anpio-cli did create`
创建后，用 `install.sh --adopt` 迁入系统服务：DID 与已发布文档不变，签名只走
受保护平面。口令始终由你在这个终端输入，不经过 Agent。
EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$SCRIPT_DIR"
ADMIN_USER="${SUDO_USER:-$(id -un)}"
AGENT_USERS=()
TPM_DEVICE=""
BINARY=""
SHA256=""
DRY_RUN=0
ROOT_PHASE=0
BOOTSTRAP=0
COMMAND=install
DID_HOST=""
DID_PATH="agents/anpio-key"
TARGET=""
TARGETS=()
METHODS=()
BODY_BYTES=1048576
GRANT_DAYS=1
GRANT_DAYS_GIVEN=0
MAX_USES=100
IDENTITY=""
SOURCE_ROOT=""
CLI_BINARY=""
CLI_SHA256=""
ENABLE_ECDH=0

while (($#)); do
  case "$1" in
    --admin-user)
      [[ $# -ge 2 ]] || die "--admin-user 需要一个账号名"
      ADMIN_USER="$2"; shift 2 ;;
    --agent-user)
      [[ $# -ge 2 ]] || die "--agent-user 需要一个账号名"
      AGENT_USERS+=("$2"); shift 2 ;;
    --tpm-device)
      if [[ $# -ge 2 && "$2" != -* ]]; then
        TPM_DEVICE="$2"; shift 2
      else
        TPM_DEVICE="/dev/tpmrm0"; shift
      fi ;;
    --bootstrap)
      BOOTSTRAP=1; shift ;;
    --did-host)
      [[ $# -ge 2 ]] || die "--did-host 需要一个域名"
      DID_HOST="$2"; shift 2 ;;
    --did-path)
      [[ $# -ge 2 ]] || die "--did-path 需要一个路径"
      DID_PATH="$2"; shift 2 ;;
    --adopt)
      [[ "$COMMAND" == install ]] || die "只能选择一个动作"
      COMMAND=adopt; shift ;;
    --identity)
      [[ $# -ge 2 ]] || die "--identity 需要一个文件"
      IDENTITY="$2"; shift 2 ;;
    --source-root)
      [[ $# -ge 2 ]] || die "--source-root 需要一个目录"
      SOURCE_ROOT="$2"; shift 2 ;;
    --cli-binary)
      [[ $# -ge 2 ]] || die "--cli-binary 需要一个路径"
      CLI_BINARY="$2"; shift 2 ;;
    --cli-sha256)
      [[ $# -ge 2 ]] || die "--cli-sha256 需要一个值"
      CLI_SHA256="$2"; shift 2 ;;
    --enable-ecdh)
      ENABLE_ECDH=1; shift ;;
    --target)
      [[ $# -ge 2 ]] || die "--target 需要一个 URL"
      TARGET="$2"; TARGETS+=("$2"); shift 2 ;;
    --method)
      [[ $# -ge 2 ]] || die "--method 需要一个方法"
      METHODS+=("$2"); shift 2 ;;
    --body-bytes)
      [[ $# -ge 2 ]] || die "--body-bytes 需要一个数字"
      BODY_BYTES="$2"; shift 2 ;;
    --grant-days)
      [[ $# -ge 2 ]] || die "--grant-days 需要一个数字"
      GRANT_DAYS="$2"; GRANT_DAYS_GIVEN=1; shift 2 ;;
    --max-uses)
      [[ $# -ge 2 ]] || die "--max-uses 需要一个数字"
      MAX_USES="$2"; shift 2 ;;
    --binary)
      [[ $# -ge 2 ]] || die "--binary 需要一个路径"
      BINARY="$2"; shift 2 ;;
    --sha256)
      [[ $# -ge 2 ]] || die "--sha256 需要一个值"
      SHA256="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    --status)
      [[ "$COMMAND" == install ]] || die "只能选择一个动作"
      COMMAND=status; shift ;;
    --verify)
      [[ "$COMMAND" == install ]] || die "只能选择一个动作"
      COMMAND=verify; shift ;;
    --upgrade)
      [[ "$COMMAND" == install ]] || die "只能选择一个动作"
      COMMAND=upgrade; shift ;;
    --uninstall)
      [[ "$COMMAND" == install ]] || die "只能选择一个动作"
      COMMAND=uninstall; shift ;;
    --_root)
      ROOT_PHASE=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      usage >&2; die "未知选项: $1" ;;
  esac
done

case "$(uname -s)" in
  Linux) PLATFORM=linux ;;
  Darwin) PLATFORM=macos ;;
  *) die "只支持 Linux 和 macOS" ;;
esac

case "$PLATFORM" in
  macos)
    CONFIG_PATH=/Library/ANPIOKey/service.json
    BINARY_PATH=/Library/ANPIOKey/bin/anpio-key
    UNIT_PATH=/Library/LaunchDaemons/org.anpio-key.local.plist
    SOCKET_PATH=/Library/ANPIOKey/admin/admin.sock
    ACCOUNTS=(_anpio _anpagent) ;;
  linux)
    CONFIG_PATH=/etc/anpio-key/service.json
    BINARY_PATH=/usr/local/libexec/anpio-key
    UNIT_PATH=/etc/systemd/system/anpio-key.service
    SOCKET_PATH=/run/anpio-key/admin/admin.sock
    ACCOUNTS=() ;;
esac

missing_prerequisite() { echo "install: $*" >&2; exit 4; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Read-only state model. Anything but "none" is never repaired automatically.
detect_state() {
  local config=0 binary=0 unit=0
  [[ -e "$CONFIG_PATH" ]] && config=1
  [[ -e "$BINARY_PATH" ]] && binary=1
  [[ -e "$UNIT_PATH" ]] && unit=1
  if ((config == 0 && binary == 0 && unit == 0)); then
    echo none
  elif ((config == 1 && binary == 1 && unit == 1)); then
    echo installed
  elif ((config == 1 && binary == 0 && unit == 0)); then
    echo data
  else
    echo partial
  fi
}

is_running() {
  if [[ "$PLATFORM" == macos ]]; then
    [[ -S "$SOCKET_PATH" ]]
  else
    systemctl is-active --quiet anpio-key.service 2>/dev/null
  fi
}

describe() { if [[ -e "$1" ]]; then echo 存在; else echo 缺失; fi; }

print_status() {
  local state running digest uid account
  state="$(detect_state)"
  if is_running; then running=运行中; else running=未运行; fi
  if [[ -f "$BINARY_PATH" ]]; then digest="$(sha256_of "$BINARY_PATH")"; else digest="（无二进制）"; fi
  echo "平台:       $PLATFORM"
  echo "状态:       ${state}（${running}）"
  echo "配置:       ${CONFIG_PATH}（$(describe "$CONFIG_PATH")）"
  echo "程序:       ${BINARY_PATH}（$(describe "$BINARY_PATH")）"
  echo "服务单元:   ${UNIT_PATH}（$(describe "$UNIT_PATH")）"
  echo "已安装摘要: $digest"
  if ((${#ACCOUNTS[@]})); then
    for account in "${ACCOUNTS[@]}"; do
      if uid="$(id -u "$account" 2>/dev/null)"; then
        echo "账号:       $account uid=$uid"
      fi
    done
  fi
  case "$state" in
    none) echo "建议:       ./install.sh" ;;
    installed) echo "建议:       ./install.sh --upgrade | --verify | --uninstall" ;;
    data) echo "建议:       服务已卸载；配置、状态和账号保留，恢复或清除见部署文档" ;;
    partial) echo "建议:       人工核对残留后再安装" ;;
  esac
}

upgrade_macos() {
  upgrade_args=(/usr/bin/python3 "$REPO_ROOT/deploy/macos/update-local.py" --binary "$BINARY" --sha256 "$SHA256")
  if [[ -e /Library/ANPIOKey/bin/anpio-key.previous ]]; then
    echo "==> 已有上一版备份，本次先归档到摘要命名的文件"
    upgrade_args+=(--archive-previous)
  fi
  "${upgrade_args[@]}" --apply
}

upgrade_linux() {
  command -v systemctl >/dev/null 2>&1 || missing_prerequisite "缺少 systemctl"
  echo "==> 停止服务（会锁钥匙并作废 grant）"
  systemctl stop anpio-key.service
  if ! python3 "$REPO_ROOT/deploy/linux/install.py" --binary "$BINARY" --sha256 "$SHA256" --update; then
    echo "更新失败；服务保持停止，旧二进制按工具输出保留。" >&2
    systemctl status --no-pager anpio-key.service || true
    exit 3
  fi
  echo "==> 启动服务"
  systemctl start anpio-key.service
  for _ in {1..30}; do [[ -S "$SOCKET_PATH" ]] && break; sleep 1; done
  if ! systemctl is-active --quiet anpio-key.service; then
    systemctl status --no-pager anpio-key.service || true
    journalctl -u anpio-key.service -n 50 --no-pager || true
    exit 3
  fi
  echo "升级完成。服务已重启；旧钥匙需要重新解锁，grant 已按重启语义作废。"
}

verify_install() {
  case "$PLATFORM" in
    macos)
      command -v /usr/bin/python3 >/dev/null 2>&1 || missing_prerequisite "缺少 /usr/bin/python3"
      /usr/bin/python3 "$REPO_ROOT/deploy/macos/acceptance/test-install.py" || exit 3 ;;
    linux)
      command -v runuser >/dev/null 2>&1 || missing_prerequisite "缺少 runuser"
      runuser -u "$ADMIN_USER" -- "$BINARY_PATH" admin --config "$CONFIG_PATH" status || exit 3
      runuser -u "$ADMIN_USER" -- "$BINARY_PATH" probe --security --config "$CONFIG_PATH" || true ;;
  esac
}

if ((${#AGENT_USERS[@]} == 0)); then
  if [[ "$PLATFORM" == linux ]]; then
    AGENT_USERS=("anp-agent")
  else
    AGENT_USERS=("_anpagent")
  fi
fi

if [[ "$COMMAND" == install || "$COMMAND" == upgrade || "$COMMAND" == adopt ]]; then
  [[ "$ADMIN_USER" != "root" ]] || die "管理员不能是 root；请用普通账号运行，或指定 --admin-user"
  for agent in "${AGENT_USERS[@]}"; do
    [[ "$agent" != "root" ]] || die "Agent 不能是 root"
    [[ "$agent" != "$ADMIN_USER" ]] || die "管理员和 Agent 必须是不同账号"
  done
  if [[ "$PLATFORM" == macos ]]; then
    ((${#AGENT_USERS[@]} == 1)) && [[ "${AGENT_USERS[0]}" == "_anpagent" ]] \
      || die "macOS 预览只支持 _anpagent 作为 Agent 账号"
    [[ -z "$TPM_DEVICE" ]] || die "macOS 不使用 --tpm-device"
  fi
fi

if [[ "$COMMAND" == adopt ]]; then
  [[ "$PLATFORM" == macos ]] || die "--adopt 只用于 macOS 本机预览"
  [[ -n "$IDENTITY" ]] || die "--adopt 需要 --identity"
  [[ -n "$CLI_BINARY" ]] || die "--adopt 需要 --cli-binary"
  [[ -n "$CLI_SHA256" ]] || die "--adopt 需要 --cli-sha256"
  ((${#TARGETS[@]})) || die "--adopt 至少需要一个 --target"
  [[ "$IDENTITY" == /* ]] || die "--identity 必须是绝对路径"
  [[ "$CLI_BINARY" == /* ]] || die "--cli-binary 必须是绝对路径"
  [[ -z "$SOURCE_ROOT" || "$SOURCE_ROOT" == /* ]] || die "--source-root 必须是绝对路径"
  [[ -z "$DID_HOST" && "$DID_PATH" == "agents/anpio-key" ]] || die "--adopt 不创建 DID 文档，不接受 --did-host/--did-path"
  [[ -z "$BINARY$SHA256" ]] || die "--adopt 使用已安装的服务程序，不接受 --binary/--sha256"
  [[ "$GRANT_DAYS" =~ ^[0-9]+$ ]] || die "--grant-days 必须是整数"
  [[ "$MAX_USES" =~ ^[0-9]+$ ]] || die "--max-uses 必须是整数"
  [[ "$BODY_BYTES" =~ ^[0-9]+$ ]] || die "--body-bytes 必须是整数"
  [[ "$CLI_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || die "--cli-sha256 必须是 64 位十六进制"
  if ((DRY_RUN == 0)); then
    [[ -f "$IDENTITY" ]] || die "找不到 --identity: $IDENTITY"
    [[ -f "$CLI_BINARY" ]] || die "找不到 --cli-binary: $CLI_BINARY"
  fi
elif ((BOOTSTRAP)); then
  [[ "$COMMAND" == install ]] || die "--bootstrap 只用于安装"
  [[ "$GRANT_DAYS" =~ ^[0-9]+$ ]] || die "--grant-days 必须是整数"
  [[ "$MAX_USES" =~ ^[0-9]+$ ]] || die "--max-uses 必须是整数"
  [[ "$BODY_BYTES" =~ ^[0-9]+$ ]] || die "--body-bytes 必须是整数"
  if ((ROOT_PHASE == 0 && DRY_RUN == 0)); then
    if [[ -z "$DID_HOST" ]]; then
      [[ -t 0 ]] || die "--bootstrap 需要 --did-host，或在终端里运行以便询问"
      read -r -p "DID 文档所在域名（例如 agents.example.com）: " DID_HOST
    fi
    [[ -n "$DID_HOST" ]] || die "DID 域名不能为空"
    if [[ -z "$TARGET" ]]; then
      [[ -t 0 ]] || die "--bootstrap 需要 --target，或在终端里运行以便询问"
      read -r -p "Agent 要访问的完整 URL（例如 https://api.example.com/v1/status）: " TARGET
    fi
    [[ -n "$TARGET" ]] || die "目标 URL 不能为空"
  fi
  if ((DRY_RUN == 0)); then
    [[ "$TARGET" == https://* ]] || die "--target 必须以 https:// 开头"
  fi
elif [[ -n "$DID_HOST$TARGET" || ${#METHODS[@]} -gt 0 ]]; then
  die "身份初始化选项需要同时带上 --bootstrap 或 --adopt"
fi

STATE="$(detect_state)"

if [[ "$COMMAND" == status ]]; then
  print_status
  exit 0
fi

if [[ "$COMMAND" == uninstall ]]; then
  case "$STATE" in
    none|data)
      echo "没有已安装的服务需要卸载（状态: ${STATE}）。"
      echo "配置、状态和账号保留在 ${CONFIG_PATH%/*} 及其之下。"
      exit 0 ;;
  esac
  if ((DRY_RUN)); then
    echo "将停止服务并删除:"
    echo "  $BINARY_PATH"
    echo "  $UNIT_PATH"
    echo "保留: ${CONFIG_PATH}、状态目录和系统账号。"
    exit 0
  fi
  if ((EUID != 0)); then
    echo "==> 卸载需要 root，接着会调用 sudo"
    exec sudo -- "$SCRIPT_DIR/install.sh" --_root --uninstall
  fi
  case "$PLATFORM" in
    macos) /usr/bin/python3 "$REPO_ROOT/deploy/macos/install.py" --uninstall --apply ;;
    linux) python3 "$REPO_ROOT/deploy/linux/install.py" --uninstall ;;
  esac
  exit $?
fi

if [[ "$COMMAND" == verify ]]; then
  [[ "$STATE" == installed ]] || { echo "没有已安装的服务可验收（状态: ${STATE}）。" >&2; exit 2; }
  if ((DRY_RUN)); then
    case "$PLATFORM" in
      macos) echo "将运行只读验收: /usr/bin/python3 deploy/macos/acceptance/test-install.py" ;;
      linux) echo "将运行只读验收: runuser -u ${ADMIN_USER} -- ${BINARY_PATH} admin --config ${CONFIG_PATH} status" ;;
    esac
    echo "只读，不修改任何内容（--dry-run）。"
    exit 0
  fi
  if ((EUID != 0)); then
    exec sudo -- "$SCRIPT_DIR/install.sh" --_root --verify --admin-user "$ADMIN_USER"
  fi
  verify_install
  exit $?
fi

if [[ "$COMMAND" == adopt ]]; then
  [[ "$STATE" == installed ]] \
    || { echo "没有可接管的安装（状态: ${STATE}）；先运行 ./install.sh。" >&2; exit 2; }
  adopt_args=(/usr/bin/python3 "$REPO_ROOT/deploy/macos/adopt-identity.py"
    --config "$CONFIG_PATH" --binary "$BINARY_PATH" --plist "$UNIT_PATH"
    --admin-user "$ADMIN_USER" --agent-user "${AGENT_USERS[0]}"
    --identity "$IDENTITY" --cli-binary "$CLI_BINARY" --cli-sha256 "$CLI_SHA256"
    --body-bytes "$BODY_BYTES" --max-uses "$MAX_USES")
  [[ -n "$SOURCE_ROOT" ]] && adopt_args+=(--source-root "$SOURCE_ROOT")
  ((GRANT_DAYS_GIVEN)) && adopt_args+=(--grant-days "$GRANT_DAYS")
  ((ENABLE_ECDH)) && adopt_args+=(--enable-ecdh)
  for target in "${TARGETS[@]}"; do adopt_args+=(--target "$target"); done
  for method in "${METHODS[@]}"; do adopt_args+=(--method "$method"); done
  if ((DRY_RUN)); then
    "${adopt_args[@]}" --dry-run
    exit $?
  fi
  if ((EUID != 0)); then
    echo "==> 接管身份需要 root，接着会调用 sudo"
    save=(--_root --adopt --admin-user "$ADMIN_USER"
      --identity "$IDENTITY" --cli-binary "$CLI_BINARY" --cli-sha256 "$CLI_SHA256"
      --body-bytes "$BODY_BYTES" --max-uses "$MAX_USES")
    [[ -n "$SOURCE_ROOT" ]] && save+=(--source-root "$SOURCE_ROOT")
    ((GRANT_DAYS_GIVEN)) && save+=(--grant-days "$GRANT_DAYS")
    ((ENABLE_ECDH)) && save+=(--enable-ecdh)
    for target in "${TARGETS[@]}"; do save+=(--target "$target"); done
    for method in "${METHODS[@]}"; do save+=(--method "$method"); done
    exec sudo -- "$SCRIPT_DIR/install.sh" "${save[@]}"
  fi
  "${adopt_args[@]}" --apply
  exit $?
fi

if [[ "$COMMAND" == upgrade ]]; then
  [[ "$STATE" == installed ]] || { echo "没有可升级的安装（状态: ${STATE}）；全新安装请直接运行 ./install.sh。" >&2; exit 2; }
elif [[ "$COMMAND" == install ]]; then
  case "$STATE" in
    installed)
      if is_running; then RUNNING=运行中; else RUNNING=未运行; fi
      echo "已安装（${RUNNING}），没有修改任何内容。"
      echo "换二进制: ./install.sh --upgrade    卸载: ./install.sh --uninstall    状态: ./install.sh --status"
      exit 0 ;;
    data)
      echo "服务已卸载，但配置、状态和账号仍保留在 ${CONFIG_PATH%/*}。" >&2
      echo "默认安装不会覆盖已有配置；恢复二进制或彻底清除需按部署文档人工执行。" >&2
      exit 2 ;;
    partial)
      echo "检测到半成品安装，拒绝自动修复。现存:" >&2
      [[ -e "$CONFIG_PATH" ]] && echo "  配置 $CONFIG_PATH" >&2
      [[ -e "$BINARY_PATH" ]] && echo "  程序 $BINARY_PATH" >&2
      [[ -e "$UNIT_PATH" ]] && echo "  服务单元 $UNIT_PATH" >&2
      echo "先人工核对并清除残留，再重新安装。" >&2
      exit 2 ;;
  esac
fi

BUILD_PENDING=0
if [[ -z "$BINARY" ]]; then
  if ((DRY_RUN)); then
    BINARY="$REPO_ROOT/target/release/anpio-key"
    BUILD_PENDING=1
  else
    command -v cargo >/dev/null 2>&1 \
      || missing_prerequisite "未找到 cargo。先安装 Rust（https://rustup.rs），或用 --binary 指定已构建的程序；也可以不用 sudo 直接运行 ./install.sh，脚本会先构建再提权"
    features="mcp"
    [[ -n "$TPM_DEVICE" ]] && features="$features,hardware-tpm"
    echo "==> 构建 release（features: ${features}）"
    ( cd "$REPO_ROOT" && cargo build --locked --release --features "$features" )
    BINARY="$REPO_ROOT/target/release/anpio-key"
  fi
fi

if ((BUILD_PENDING == 0)); then
  [[ -f "$BINARY" && -x "$BINARY" ]] || die "程序不可执行: $BINARY"
  BINARY="$(cd -- "$(dirname -- "$BINARY")" && pwd -P)/$(basename -- "$BINARY")"
fi

if ((BUILD_PENDING == 0)) && [[ -z "$SHA256" ]]; then
  SHA256="$(sha256_of "$BINARY")"
fi
if [[ -n "$SHA256" ]]; then
  SHA256="$(printf '%s' "$SHA256" | tr 'A-F' 'a-f')"
  [[ "$SHA256" =~ ^[0-9a-f]{64}$ ]] || die "SHA-256 格式不对: $SHA256"
fi

if [[ "$COMMAND" == upgrade && -n "$SHA256" && -f "$BINARY_PATH" ]]; then
  if [[ "$(sha256_of "$BINARY_PATH")" == "$SHA256" ]]; then
    echo "已安装的二进制就是该构建（${SHA256}）；跳过，服务未重启。"
    exit 0
  fi
fi

if ((DRY_RUN)); then
  cat <<EOF
平台:       $PLATFORM
动作:       $COMMAND
当前状态:   $STATE
管理员:     $ADMIN_USER
Agent:      ${AGENT_USERS[*]}
程序:       $BINARY$( ((BUILD_PENDING)) && echo "（将构建）" )
SHA-256:    ${SHA256:-（构建后计算）}
TPM 设备:   ${TPM_DEVICE:-无}
身份初始化: $( ((BOOTSTRAP)) && echo "是" || echo "否" )$(
  if ((BOOTSTRAP)); then
    printf '\nDID 域名:   %s\nDID 路径:   %s\n目标 URL:   %s\n方法:       %s\n有效天数:   %s\n次数上限:   %s\n' \
      "${DID_HOST:-（会询问）}" "$DID_PATH" "${TARGET:-（会询问）}" "${METHODS[*]:-GET}" "$GRANT_DAYS" "$MAX_USES"
  fi
)

将执行:
  - 构建 release（未给 --binary 时）
  - 安装 root 持有的程序、配置和 systemd/launchd 服务（升级时只替换二进制）
  - 启动服务并做只读检查
$( ((BOOTSTRAP)) && printf '  - 生成新身份，离线迁入受保护状态，创建策略和 grant，并解锁\n  - 口令由你在这个终端输入\n' )

尚未修改任何内容（--dry-run）。
EOF
  exit 0
fi

if ((EUID != 0)); then
  echo "==> ${COMMAND} 需要 root，接着会调用 sudo"
  args=(--_root --admin-user "$ADMIN_USER" --binary "$BINARY")
  [[ -n "$SHA256" ]] && args+=(--sha256 "$SHA256")
  [[ "$COMMAND" == upgrade ]] && args+=(--upgrade)
  for agent in "${AGENT_USERS[@]}"; do args+=(--agent-user "$agent"); done
  [[ -n "$TPM_DEVICE" ]] && args+=(--tpm-device "$TPM_DEVICE")
  if ((BOOTSTRAP)); then
    args+=(--bootstrap --did-host "$DID_HOST" --did-path "$DID_PATH" --target "$TARGET"
      --body-bytes "$BODY_BYTES" --grant-days "$GRANT_DAYS" --max-uses "$MAX_USES")
    for method in "${METHODS[@]}"; do args+=(--method "$method"); done
  fi
  exec sudo -- "$SCRIPT_DIR/install.sh" "${args[@]}"
fi

# ---- root phase ----

if [[ "$COMMAND" == upgrade ]]; then
  case "$PLATFORM" in
    macos) upgrade_macos ;;
    linux) upgrade_linux ;;
  esac
  exit $?
fi

[[ "$(id -u "$ADMIN_USER")" != "0" ]] || die "管理员不能是 root"

case "$PLATFORM" in
  linux)
    command -v python3 >/dev/null 2>&1 || die "缺少 python3"
    [[ -d /run/systemd/system ]] || die "systemd 没有运行；本脚本需要一台 systemd Linux 主机"

    for agent in "${AGENT_USERS[@]}"; do
      if ! id -u "$agent" >/dev/null 2>&1; then
        echo "==> 创建 Agent 账号 $agent"
        useradd --create-home --shell /bin/bash --comment "anpio-key Agent" --password '!' "$agent"
      fi
    done

    echo "==> 安装服务和账号"
    args=(python3 "$REPO_ROOT/deploy/linux/install.py" --binary "$BINARY" --sha256 "$SHA256" --admin-user "$ADMIN_USER")
    for agent in "${AGENT_USERS[@]}"; do args+=(--agent-user "$agent"); done
    [[ -n "$TPM_DEVICE" ]] && args+=(--tpm-device "$TPM_DEVICE")
    "${args[@]}"

    echo "==> 启动服务"
    systemctl daemon-reload
    systemctl enable --now anpio-key.service
    for _ in {1..30}; do
      [[ -S /run/anpio-key/admin/admin.sock ]] && break
      sleep 1
    done
    if ! systemctl is-active --quiet anpio-key.service; then
      systemctl status --no-pager anpio-key.service || true
      journalctl -u anpio-key.service -n 50 --no-pager || true
      die "服务没有启动；上面的日志说明了原因"
    fi

    BIN=/usr/local/libexec/anpio-key
    echo "==> 只读检查"
    if command -v runuser >/dev/null 2>&1; then
      runuser -u "$ADMIN_USER" -- "$BIN" admin --config /etc/anpio-key/service.json status || true
      runuser -u "$ADMIN_USER" -- "$BIN" probe --security --config /etc/anpio-key/service.json || true
    fi

    echo
    echo "安装完成。服务已启动，状态目录 /var/lib/anpio-key。"
    echo "管理员: $ADMIN_USER    Agent: ${AGENT_USERS[*]}"

    if ((BOOTSTRAP)); then
      hardware=none
      [[ -n "$TPM_DEVICE" ]] && hardware=tpm
      args=(python3 "$REPO_ROOT/deploy/linux/bootstrap.py"
        --config /etc/anpio-key/service.json --binary "$BIN"
        --admin-user "$ADMIN_USER" --agent-user "${AGENT_USERS[0]}"
        --did-host "$DID_HOST" --did-path "$DID_PATH" --target "$TARGET"
        --body-bytes "$BODY_BYTES" --grant-days "$GRANT_DAYS" --max-uses "$MAX_USES"
        --hardware "$hardware")
      for method in "${METHODS[@]}"; do args+=(--method "$method"); done
      "${args[@]}"
    else
      echo "下一步（身份、热钥匙、策略、grant、解锁）见 deploy/LOCAL-USE.md。"
    fi
    ;;

  macos)
    echo "==> 安装 macOS 本机预览"
    bash "$REPO_ROOT/deploy/macos/setup-local.sh" "$ADMIN_USER" "$SHA256" "$BINARY"
    echo
    if ((BOOTSTRAP)); then
      args=(/usr/bin/python3 "$REPO_ROOT/deploy/macos/bootstrap.py"
        --config /Library/ANPIOKey/service.json
        --binary /Library/ANPIOKey/bin/anpio-key
        --plist /Library/LaunchDaemons/org.anpio-key.local.plist
        --admin-user "$ADMIN_USER" --agent-user "_anpagent"
        --did-host "$DID_HOST" --did-path "$DID_PATH" --target "$TARGET"
        --body-bytes "$BODY_BYTES" --grant-days "$GRANT_DAYS" --max-uses "$MAX_USES")
      for method in "${METHODS[@]}"; do args+=(--method "$method"); done
      "${args[@]}"
    else
      echo "安装完成。本机预览始终 protected_supported=false。"
      echo "管理员: $ADMIN_USER    Agent: _anpagent"
      echo "下一步见 deploy/LOCAL-USE.md。"
    fi
    ;;
esac

echo
echo "注意: Agent 账号不能有 sudo、管理员凭据或 Docker 管理权限。"
echo "安装时使用过 sudo 的 Agent 必须先收回 sudo，边界才成立。"
