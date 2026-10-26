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
  -h, --help          显示本帮助

初始化身份和 grant（安装后在同一个命令里继续；macOS 只用于本机预览）:
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
  ./install.sh --agent-user agent-a --agent-user agent-b
  ./install.sh --tpm-device
  ./install.sh --bootstrap --did-host agents.example.com \
    --target https://api.example.com/v1/status
  sudo ./install.sh --binary /root/anpio-key --sha256 VERIFIED_SHA256 --admin-user operator

不带 --bootstrap 时只创建空服务。身份、策略和 grant 也可以之后按
deploy/LOCAL-USE.md 手动完成。口令始终由你在这个终端输入，不经过 Agent。
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
DID_HOST=""
DID_PATH="agents/anpio-key"
TARGET=""
METHODS=()
BODY_BYTES=1048576
GRANT_DAYS=1
MAX_USES=100

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
    --target)
      [[ $# -ge 2 ]] || die "--target 需要一个 URL"
      TARGET="$2"; shift 2 ;;
    --method)
      [[ $# -ge 2 ]] || die "--method 需要一个方法"
      METHODS+=("$2"); shift 2 ;;
    --body-bytes)
      [[ $# -ge 2 ]] || die "--body-bytes 需要一个数字"
      BODY_BYTES="$2"; shift 2 ;;
    --grant-days)
      [[ $# -ge 2 ]] || die "--grant-days 需要一个数字"
      GRANT_DAYS="$2"; shift 2 ;;
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

if ((${#AGENT_USERS[@]} == 0)); then
  if [[ "$PLATFORM" == linux ]]; then
    AGENT_USERS=("anp-agent")
  else
    AGENT_USERS=("_anpagent")
  fi
fi

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

if ((BOOTSTRAP)); then
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
  die "身份初始化选项需要同时带上 --bootstrap"
fi

if [[ -z "$BINARY" ]]; then
  command -v cargo >/dev/null 2>&1 \
    || die "未找到 cargo。先安装 Rust（https://rustup.rs），或用 --binary 指定已构建的程序；也可以不用 sudo 直接运行 ./install.sh，脚本会先构建再提权"
  features="mcp"
  [[ -n "$TPM_DEVICE" ]] && features="$features,hardware-tpm"
  echo "==> 构建 release（features: $features）"
  ( cd "$REPO_ROOT" && cargo build --locked --release --features "$features" )
  BINARY="$REPO_ROOT/target/release/anpio-key"
fi

[[ -f "$BINARY" && -x "$BINARY" ]] || die "程序不可执行: $BINARY"
BINARY="$(cd -- "$(dirname -- "$BINARY")" && pwd -P)/$(basename -- "$BINARY")"

if [[ -z "$SHA256" ]]; then
  if command -v sha256sum >/dev/null 2>&1; then
    SHA256="$(sha256sum "$BINARY" | awk '{print $1}')"
  else
    SHA256="$(shasum -a 256 "$BINARY" | awk '{print $1}')"
  fi
fi
SHA256="$(printf '%s' "$SHA256" | tr 'A-F' 'a-f')"
[[ "$SHA256" =~ ^[0-9a-f]{64}$ ]] || die "SHA-256 格式不对: $SHA256"

if ((DRY_RUN)); then
  cat <<EOF
平台:       $PLATFORM
管理员:     $ADMIN_USER
Agent:      ${AGENT_USERS[*]}
程序:       $BINARY
SHA-256:    $SHA256
TPM 设备:   ${TPM_DEVICE:-无}
身份初始化: $( ((BOOTSTRAP)) && echo "是" || echo "否" )$(
  if ((BOOTSTRAP)); then
    printf '\nDID 域名:   %s\nDID 路径:   %s\n目标 URL:   %s\n方法:       %s\n有效天数:   %s\n次数上限:   %s\n' \
      "${DID_HOST:-（会询问）}" "$DID_PATH" "${TARGET:-（会询问）}" "${METHODS[*]:-GET}" "$GRANT_DAYS" "$MAX_USES"
  fi
)

将执行:
  - 创建缺失的 Agent 账号（Linux: anp-agent；macOS: _anpagent）
  - 安装 root 持有的程序、配置和 systemd/launchd 服务
  - 启动服务并做只读检查
$( ((BOOTSTRAP)) && printf '  - 生成新身份，离线迁入受保护状态，创建策略和 grant，并解锁\n  - 口令由你在这个终端输入\n' )

尚未修改任何内容（--dry-run）。
EOF
  exit 0
fi

if ((EUID != 0)); then
  echo "==> 安装需要 root，接着会调用 sudo"
  args=(--_root --admin-user "$ADMIN_USER" --binary "$BINARY" --sha256 "$SHA256")
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
