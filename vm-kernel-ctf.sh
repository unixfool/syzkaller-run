#!/bin/bash
# ==============================================================================
#  KernelCTF VM Setup — Ubuntu 24.04 limpia
#  Instala kernel 6.12.89 identico al entorno real de Google kernelCTF
#  Uso: sudo bash vm.sh
# ==============================================================================
# Creador: y2k - Email: y2k@desarrollaria.com
# ==============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
info() { echo -e "${CYAN}[INFO]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }

KERNEL_VER="6.12.89"
KERNEL_SRC="/home/y2k/linux-${KERNEL_VER}"
JOBS=$(nproc)

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║  KernelCTF VM Setup — lts-${KERNEL_VER}          ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════╝${RESET}"
echo ""

# ── Paso 1: Dependencias ──────────────────────────────────────────────────────
info "Paso 1/6: Instalando dependencias..."
sudo apt-get update -qq
sudo apt-get install -y \
    build-essential libncurses-dev bison flex libssl-dev libelf-dev \
    bc dwarves pahole gcc make git wget curl xz-utils python3 \
    socat libgmp-dev libmpc-dev cpio initramfs-tools zstd
ok "Dependencias instaladas"

# ── Paso 2: Verificar source ──────────────────────────────────────────────────
info "Paso 2/6: Verificando kernel source..."
[[ -d "$KERNEL_SRC" ]] || err "No se encuentra $KERNEL_SRC — extrae el tar primero"
ok "Source encontrado en $KERNEL_SRC"

cd "$KERNEL_SRC"

# ── Paso 3: Config kernel ─────────────────────────────────────────────────────
info "Paso 3/6: Aplicando config de kernelCTF..."

# Base: config del sistema actual — incluye todos los drivers del disco
cp /boot/config-$(uname -r) .config

# Aplicar settings de kernelCTF
scripts/config \
    --disable CONFIG_NF_TABLES \
    --disable CONFIG_IO_URING \
    --disable CONFIG_BPF_SYSCALL \
    --set-str CONFIG_SYSTEM_TRUSTED_KEYS "" \
    --set-str CONFIG_SYSTEM_REVOCATION_KEYS "" \
    --set-str CONFIG_LOCALVERSION "" \
    --enable CONFIG_KASAN \
    --enable CONFIG_KASAN_GENERIC \
    --enable CONFIG_KASAN_INLINE \
    --disable CONFIG_KASAN_OUTLINE \
    --enable CONFIG_KCOV \
    --enable CONFIG_KCOV_INSTRUMENT_ALL \
    --enable CONFIG_KCOV_ENABLE_COMPARISONS \
    --enable CONFIG_DEBUG_INFO \
    --enable CONFIG_DEBUG_INFO_DWARF5 \
    --disable CONFIG_DEBUG_INFO_NONE \
    --disable CONFIG_DEBUG_INFO_DWARF4 \
    --enable CONFIG_DEBUG_INFO_BTF \
    --enable CONFIG_UNIX \
    --enable CONFIG_FUTEX \
    --enable CONFIG_PERF_EVENTS \
    --enable CONFIG_RD_GZIP \
    --enable CONFIG_RD_ZSTD \
    --enable CONFIG_BLK_DEV_INITRD \
    --disable CONFIG_MODULE_SIG \
    --disable CONFIG_MODULE_SIG_ALL \
    --disable CONFIG_MODULE_SIG_FORCE \
    --disable CONFIG_SECURITY_LOCKDOWN_LSM

# Resolver dependencias sin preguntar
make olddefconfig
ok "Config aplicada — módulos irán a /lib/modules/${KERNEL_VER}"

# ── Paso 4: Compilar ──────────────────────────────────────────────────────────
info "Paso 4/6: Compilando kernel con $JOBS threads (30-60 min)..."
make -j"$JOBS"
ok "Kernel compilado"

# ── Paso 5: Instalar módulos y kernel ────────────────────────────────────────
info "Paso 5/6: Instalando módulos..."
sudo make modules_install
ok "Módulos instalados en /lib/modules/${KERNEL_VER}"

info "Instalando kernel en /boot..."
sudo cp arch/x86/boot/bzImage /boot/vmlinuz-${KERNEL_VER}
sudo cp System.map /boot/System.map-${KERNEL_VER}
sudo cp .config /boot/config-${KERNEL_VER}

info "Generando initramfs..."
sudo update-initramfs -c -k ${KERNEL_VER}
ok "initramfs generado"

# ── Paso 6: sysctl + GRUB ────────────────────────────────────────────────────
info "Paso 6/6: Configurando sysctl y GRUB..."

sudo tee /etc/sysctl.d/99-kernelctf.conf > /dev/null << 'EOF'
kernel.perf_event_paranoid = 2
user.max_user_namespaces = 0
kernel.unprivileged_bpf_disabled = 2
kernel.dmesg_restrict = 0
EOF
ok "Sysctl configurado"

sudo update-grub

# Establecer kernel 6.12.89 como default en GRUB
sudo sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT="1>2"/' /etc/default/grub
sudo update-grub
ok "GRUB configurado"

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══ Setup completado ══${RESET}"
echo ""
echo -e "  Kernel:          ${KERNEL_VER}"
echo -e "  Módulos:         /lib/modules/${KERNEL_VER}"
echo -e "  KASAN:           activado"
echo -e "  KCOV:            activado"
echo -e "  io_uring:        deshabilitado"
echo -e "  nftables:        deshabilitado"
echo -e "  BPF unpriv:      deshabilitado"
echo -e "  user namespaces: bloqueados"
echo -e "  perf_paranoid:   2"
echo ""
echo -e "${BOLD}${YELLOW}Reiniciando en 5 segundos...${RESET}"
sleep 5
sudo reboot
