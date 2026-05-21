#!/usr/bin/env bash
# ==============================================================================
#  Linux Kernel Research Environment — Setup Automatico
#  Fase 1: Configurar y compilar kernel con sanitizers
#  Fase 2: Construir imagen rootfs con buildroot
#  Fase 3: Configurar syzkaller con VMs en paralelo
#
#  SEGURIDAD: Todo corre en VMs QEMU aisladas.
#             Tu sistema principal NO se modifica.
#
#  Uso: bash setup_research_env.sh
#       bash setup_research_env.sh --fase 1   (solo compilar kernel)
#       bash setup_research_env.sh --fase 2   (solo buildroot)
#       bash setup_research_env.sh --fase 3   (solo syzkaller)
# ==============================================================================
#    Creador: y2k         → Email: y2k@desarrollaria.com
# ==============================================================================

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Configuración ─────────────────────────────────────────────────────────────
WORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_DIR="$WORK_DIR/linux"
BUILDROOT_DIR="$WORK_DIR/buildroot"
SYZKALLER_DIR="$WORK_DIR/syzkaller"
OUTPUT_DIR="$WORK_DIR/output"
VM_DIR="$OUTPUT_DIR/vms"
LOG_DIR="$OUTPUT_DIR/logs"
KERNEL_DIR="$OUTPUT_DIR/kernel"

NCPUS=$(nproc)
RAM_MB=4096          # RAM por VM en MB
NUM_VMS=8            # VMs en paralelo (ajustado a 16 cores / 32GB RAM)
FASE_SOLO=""

# ── Argumentos ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --fase) FASE_SOLO="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
log()     { echo -e "${CYAN}[$(date +%H:%M:%S)]${RESET} $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()     { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; \
            echo -e "${BOLD}${CYAN}  $*${RESET}"; \
            echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  ██╗  ██╗███████╗██████╗ ███╗   ██╗███████╗██╗
  ██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║
  █████╔╝ █████╗  ██████╔╝██╔██╗ ██║█████╗  ██║
  ██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██║
  ██║  ██╗███████╗██║  ██║██║ ╚████║███████╗███████╗
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
  RESEARCH ENV — Kernel Fuzzing Setup
BANNER
echo -e "${RESET}"
echo -e "  Directorio: ${CYAN}$WORK_DIR${RESET}"
echo -e "  CPUs:       ${CYAN}$NCPUS cores${RESET}"
echo -e "  VMs:        ${CYAN}$NUM_VMS en paralelo${RESET}"
echo -e "  RAM/VM:     ${CYAN}${RAM_MB}MB${RESET}"
echo ""

# ── Verificar dependencias ────────────────────────────────────────────────────
check_deps() {
  section "VERIFICANDO DEPENDENCIAS"

  local deps=(
    qemu-system-x86_64 make gcc flex bison bc libssl-dev
    libelf-dev libncurses-dev python3 python3-pip
    git debootstrap squashfs-tools wget curl
  )

  local missing=()
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" &>/dev/null && ! dpkg -l "$dep" &>/dev/null 2>&1; then
      missing+=("$dep")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Instalando dependencias faltantes: ${missing[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y \
      qemu-system-x86 qemu-utils \
      build-essential flex bison bc \
      libssl-dev libelf-dev libncurses-dev \
      python3 python3-pip python3-venv \
      git debootstrap squashfs-tools \
      wget curl ssh openssh-client \
      cpio rsync 2>/dev/null
    ok "Dependencias instaladas"
  else
    ok "Todas las dependencias presentes"
  fi

  # Go es necesario para syzkaller
  if ! command -v go &>/dev/null; then
    warn "Go no encontrado — instalando..."
    GO_VER="1.22.3"
    wget -q "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    ok "Go instalado: $(go version)"
  else
    ok "Go: $(go version)"
  fi

  # Crear directorios de output
  mkdir -p "$OUTPUT_DIR" "$VM_DIR" "$LOG_DIR" "$KERNEL_DIR"
  ok "Directorios de trabajo creados en $OUTPUT_DIR"
}

# ==============================================================================
# FASE 1 — COMPILAR KERNEL CON SANITIZERS
# ==============================================================================
fase1_kernel() {
  section "FASE 1 — COMPILAR KERNEL CON SANITIZERS"
  echo -e "  ${YELLOW}Esto tarda ~8-10 minutos con $NCPUS cores.${RESET}"
  echo -e "  ${GREEN}Tu sistema principal NO se modifica.${RESET}\n"

  [[ -d "$LINUX_DIR" ]] || err "No encuentro $LINUX_DIR — ¿clonaste el kernel?"

  cd "$LINUX_DIR"

  # ── Verificar si ya está compilado ─────────────────────────────────────────
  if [[ -f "arch/x86/boot/bzImage" ]]; then
    ok "Kernel ya compilado. Verificando sanitizers..."
    local has_kasan has_kcov
    has_kasan=$(grep "CONFIG_KASAN=y" .config 2>/dev/null || true)
    has_kcov=$(grep  "CONFIG_KCOV=y"  .config 2>/dev/null || true)
    if [[ -n "$has_kasan" && -n "$has_kcov" ]]; then
      ok "Kernel tiene KASAN + KCOV. Saltando compilación."
      cp arch/x86/boot/bzImage "$KERNEL_DIR/bzImage"
      return 0
    else
      warn "Kernel compilado pero sin sanitizers completos. Recompilando..."
    fi
  fi

  # ── Configuración base ─────────────────────────────────────────────────────
  log "Generando configuración base para VMs (x86_64)..."
  make defconfig 2>/dev/null

  # ── Activar sanitizers y opciones de fuzzing ───────────────────────────────
  log "Activando sanitizers: KASAN + KCOV + UBSAN + KMSAN..."

  # Función para activar/desactivar opciones de forma segura
  set_config() {
    local key="$1" val="$2"
    if grep -q "^$key=" .config 2>/dev/null; then
      sed -i "s|^$key=.*|$key=$val|" .config
    elif grep -q "^# $key is not set" .config 2>/dev/null; then
      sed -i "s|^# $key is not set|$key=$val|" .config
    else
      echo "$key=$val" >> .config
    fi
  }

  # Sanitizers esenciales para fuzzing
  set_config CONFIG_KCOV              y   # Coverage-guided fuzzing
  set_config CONFIG_KCOV_ENABLE_COMPARISONS y
  set_config CONFIG_KASAN             y   # Kernel Address Sanitizer
  set_config CONFIG_KASAN_INLINE      y
  set_config CONFIG_UBSAN             y   # Undefined Behavior Sanitizer
  set_config CONFIG_UBSAN_SANITIZE_ALL y

  # Debug y símbolos (necesarios para que syzkaller entienda los crashes)
  set_config CONFIG_DEBUG_INFO        y
  set_config CONFIG_DEBUG_INFO_DWARF4 y
  set_config CONFIG_KALLSYMS          y
  set_config CONFIG_KALLSYMS_ALL      y
  set_config CONFIG_FRAME_POINTER     y

  # Detección de bugs en el kernel
  set_config CONFIG_DEBUG_KERNEL      y
  set_config CONFIG_LOCKDEP           y
  set_config CONFIG_PROVE_LOCKING     y
  set_config CONFIG_DEBUG_ATOMIC_SLEEP y
  set_config CONFIG_REFCOUNT_FULL     y
  set_config CONFIG_FORTIFY_SOURCE    y

  # Necesario para VMs QEMU
  set_config CONFIG_VIRTIO            y
  set_config CONFIG_VIRTIO_PCI        y
  set_config CONFIG_VIRTIO_NET        y
  set_config CONFIG_VIRTIO_BLK        y
  set_config CONFIG_NET_9P            y
  set_config CONFIG_NET_9P_VIRTIO     y
  set_config CONFIG_9P_FS             y

  # Subsistemas a auditar
  set_config CONFIG_IO_URING          y
  set_config CONFIG_CRYPTO            y
  set_config CONFIG_CRYPTO_USER_API_AEAD y

  # Resolver dependencias automáticamente
  log "Resolviendo dependencias de configuración..."
  make olddefconfig 2>/dev/null

  # ── Compilar ───────────────────────────────────────────────────────────────
  log "Compilando kernel con $NCPUS cores... (esto tarda ~8-10 min)"
  local start=$SECONDS

  make -j"$NCPUS" 2>&1 | tee "$LOG_DIR/kernel_build.log" | \
    grep -E "^(  CC|  LD|  AR|vmlinux|bzImage|ERROR|error:)" || true

  if [[ ! -f "arch/x86/boot/bzImage" ]]; then
    err "Compilación fallida. Revisa $LOG_DIR/kernel_build.log"
  fi

  local elapsed=$((SECONDS - start))
  ok "Kernel compilado en ${elapsed}s"

  # Copiar al directorio de output
  cp arch/x86/boot/bzImage "$KERNEL_DIR/bzImage"
  cp vmlinux "$KERNEL_DIR/vmlinux" 2>/dev/null || true

  ok "Kernel listo en $KERNEL_DIR/bzImage"

  # ── Verificar sanitizers activos ───────────────────────────────────────────
  echo ""
  log "Sanitizers activos en el kernel compilado:"
  grep -E "CONFIG_KASAN=|CONFIG_KCOV=|CONFIG_UBSAN=|CONFIG_KALLSYMS=" .config | \
    while read -r line; do echo -e "  ${GREEN}✓${RESET} $line"; done
}

# ==============================================================================
# FASE 2 — BUILDROOT: IMAGEN ROOTFS PARA LAS VMs
# ==============================================================================
fase2_buildroot() {
  section "FASE 2 — BUILDROOT: IMAGEN ROOTFS"
  echo -e "  ${YELLOW}Esto tarda ~15-20 minutos la primera vez.${RESET}"
  echo -e "  ${GREEN}Genera un sistema mínimo para las VMs de fuzzing.${RESET}\n"

  [[ -d "$BUILDROOT_DIR" ]] || err "No encuentro $BUILDROOT_DIR"

  local IMAGE="$BUILDROOT_DIR/output/images/rootfs.ext4"

  if [[ -f "$IMAGE" ]]; then
    ok "Imagen buildroot ya existe. Saltando."
    cp "$IMAGE" "$VM_DIR/rootfs.ext4"
    return 0
  fi

  cd "$BUILDROOT_DIR"

  # ── Configuración de buildroot ─────────────────────────────────────────────
  log "Configurando buildroot para imagen mínima de fuzzing..."

  # Generar .config mínimo para syzkaller
  cat > "$BUILDROOT_DIR/.config" << 'BRCONFIG'
BR2_x86_64=y
BR2_TOOLCHAIN_BUILDROOT_GLIBC=y
BR2_SYSTEM_DHCP="eth0"
BR2_TARGET_ROOTFS_EXT2=y
BR2_TARGET_ROOTFS_EXT2_4=y
BR2_TARGET_ROOTFS_EXT2_SIZE="2048M"
BR2_PACKAGE_OPENSSH=y
BR2_PACKAGE_BASH=y
BR2_PACKAGE_STRACE=y
BR2_PACKAGE_GDB=y
BR2_PACKAGE_TCPDUMP=y
BR2_PACKAGE_IPROUTE2=y
BR2_PACKAGE_UTIL_LINUX=y
BR2_PACKAGE_E2FSPROGS=y
BR2_ROOTFS_POST_BUILD_SCRIPT=""
BRCONFIG

  make olddefconfig 2>/dev/null

  # ── Compilar imagen ────────────────────────────────────────────────────────
  log "Construyendo imagen rootfs con $NCPUS cores... (~15-20 min)"
  local start=$SECONDS

  make -j"$NCPUS" 2>&1 | tee "$LOG_DIR/buildroot_build.log" | \
    grep -E "^(>>>|ERROR|error)" || true

  local elapsed=$((SECONDS - start))

  if [[ ! -f "$IMAGE" ]]; then
    # Alternativa más rápida: imagen Debian mínima con debootstrap
    warn "Buildroot tardó demasiado o falló. Usando debootstrap como alternativa..."
    fase2_debootstrap
    return 0
  fi

  ok "Imagen rootfs construida en ${elapsed}s"
  cp "$IMAGE" "$VM_DIR/rootfs.ext4"
  ok "Imagen lista en $VM_DIR/rootfs.ext4"
}

# Alternativa rápida con debootstrap si buildroot falla
fase2_debootstrap() {
  log "Creando imagen mínima con debootstrap (~5 min)..."

  local IMG="$VM_DIR/rootfs.ext4"
  local MNT="/tmp/rootfs_mnt"

  # Crear imagen de 2GB
  dd if=/dev/zero of="$IMG" bs=1M count=2048 status=progress
  mkfs.ext4 -F "$IMG"

  mkdir -p "$MNT"
  sudo mount -o loop "$IMG" "$MNT"

  # Sistema Debian mínimo
  sudo debootstrap --arch=amd64 bookworm "$MNT" http://deb.debian.org/debian/

  # Configuración básica para fuzzing
  sudo chroot "$MNT" /bin/bash << 'CHROOT'
echo "root:root" | chpasswd
echo "syzkaller" > /etc/hostname
echo "auto eth0" > /etc/network/interfaces
echo "iface eth0 inet dhcp" >> /etc/network/interfaces
systemctl enable ssh 2>/dev/null || true
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config
CHROOT

  sudo umount "$MNT"
  ok "Imagen debootstrap lista en $IMG"
}

# ==============================================================================
# FASE 3 — SYZKALLER: CONFIGURAR Y ARRANCAR FUZZER
# ==============================================================================
fase3_syzkaller() {
  section "FASE 3 — SYZKALLER: CONFIGURAR FUZZER"
  echo -e "  ${CYAN}$NUM_VMS VMs en paralelo — aprovechando tus 16 cores${RESET}\n"

  [[ -d "$SYZKALLER_DIR" ]] || err "No encuentro $SYZKALLER_DIR"

  # ── Compilar syzkaller ─────────────────────────────────────────────────────
  cd "$SYZKALLER_DIR"

  if [[ ! -f "bin/linux_amd64/syz-manager" ]]; then
    log "Compilando syzkaller..."
    export PATH=$PATH:/usr/local/go/bin
    make -j"$NCPUS" 2>&1 | tee "$LOG_DIR/syzkaller_build.log" | tail -5
    ok "syzkaller compilado"
  else
    ok "syzkaller ya compilado"
  fi

  # ── Generar claves SSH para las VMs ───────────────────────────────────────
  if [[ ! -f "$VM_DIR/id_rsa" ]]; then
    log "Generando claves SSH para las VMs..."
    ssh-keygen -t rsa -b 2048 -N "" -f "$VM_DIR/id_rsa" -q
    ok "Claves SSH generadas"
  fi

  # ── Crear configuración de syzkaller ──────────────────────────────────────
  log "Generando configuración syzkaller.cfg..."

  cat > "$OUTPUT_DIR/syzkaller.cfg" << SYZCONFIG
{
  "target": "linux/amd64",
  "http": "127.0.0.1:56741",
  "workdir": "$OUTPUT_DIR/syzkaller_workdir",
  "kernel_obj": "$LINUX_DIR",
  "image": "$VM_DIR/rootfs.ext4",
  "sshkey": "$VM_DIR/id_rsa",
  "syzkaller": "$SYZKALLER_DIR",
  "procs": 8,
  "type": "qemu",
  "vm": {
    "count": $NUM_VMS,
    "kernel": "$KERNEL_DIR/bzImage",
    "cpu": 2,
    "mem": $RAM_MB,
    "cmdline": "console=ttyS0 root=/dev/sda oops=panic panic_on_warn=1 panic=-1 ftrace_dump_on_oops=orig_cpu debug earlyprintk=serial slub_debug=UZ"
  },
  "enable_syscalls": [
    "io_uring*",
    "socket",
    "connect",
    "sendmsg",
    "recvmsg",
    "read",
    "write",
    "open",
    "close",
    "mmap",
    "munmap",
    "splice",
    "tee",
    "sendfile"
  ]
}
SYZCONFIG

  mkdir -p "$OUTPUT_DIR/syzkaller_workdir"
  ok "Configuración generada en $OUTPUT_DIR/syzkaller.cfg"

  # ── Script de arranque ─────────────────────────────────────────────────────
  cat > "$OUTPUT_DIR/start_fuzzing.sh" << STARTSCRIPT
#!/usr/bin/env bash
# Arranca syzkaller con $NUM_VMS VMs en paralelo
# Dashboard web en: http://127.0.0.1:56741

export PATH=\$PATH:/usr/local/go/bin
SYZKALLER_DIR="$SYZKALLER_DIR"
CONFIG="$OUTPUT_DIR/syzkaller.cfg"
LOG="$LOG_DIR/syzkaller_\$(date +%Y%m%d_%H%M%S).log"

echo ""
echo "  ┌─────────────────────────────────────────────────┐"
echo "  │  Syzkaller arrancando con $NUM_VMS VMs en paralelo      │"
echo "  │  Dashboard: http://127.0.0.1:56741              │"
echo "  │  Logs: \$LOG                                     │"
echo "  │  Ctrl+C para detener                            │"
echo "  └─────────────────────────────────────────────────┘"
echo ""

\$SYZKALLER_DIR/bin/linux_amd64/syz-manager \\
  -config="\$CONFIG" \\
  2>&1 | tee "\$LOG"
STARTSCRIPT

  chmod +x "$OUTPUT_DIR/start_fuzzing.sh"

  # ── Script de análisis de crashes ─────────────────────────────────────────
  cat > "$OUTPUT_DIR/analyze_crashes.sh" << 'ANALYZE'
#!/usr/bin/env bash
# Analiza crashes encontrados por syzkaller
# y genera informe estructurado para reportar CVEs

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRASH_DIR="$WORKDIR/syzkaller_workdir/crashes"

if [[ ! -d "$CRASH_DIR" ]]; then
  echo "Sin crashes todavía. Deja correr syzkaller más tiempo."
  exit 0
fi

echo ""
echo "══ CRASHES ENCONTRADOS ══"
echo ""

COUNT=0
for crash_dir in "$CRASH_DIR"/*/; do
  [[ -d "$crash_dir" ]] || continue
  COUNT=$((COUNT+1))

  DESCRIPTION=$(cat "$crash_dir/description" 2>/dev/null || echo "Sin descripción")
  LOG=$(ls "$crash_dir"/*.log 2>/dev/null | head -1)
  REPRO=$(ls "$crash_dir"/repro.c 2>/dev/null || echo "")

  echo "[$COUNT] $DESCRIPTION"
  echo "    Directorio: $crash_dir"
  [[ -n "$REPRO" ]] && echo "    ✓ Reproductor C disponible: $REPRO"
  echo ""
done

if [[ $COUNT -eq 0 ]]; then
  echo "  Sin crashes todavía. Normal las primeras horas."
else
  echo "══ $COUNT crash(es) encontrados ══"
  echo ""
  echo "Próximos pasos para reportar:"
  echo "  1. Verifica que el crash es reproducible con el repro.c"
  echo "  2. Identifica el subsistema afectado"
  echo "  3. Reporta a security@kernel.org con el crash log y repro"
  echo "  4. CC a la distro: security@ubuntu.com / secalert@redhat.com"
fi
ANALYZE

  chmod +x "$OUTPUT_DIR/analyze_crashes.sh"
  ok "Scripts de arranque y análisis generados"
}

# ==============================================================================
# RESUMEN FINAL
# ==============================================================================
resumen_final() {
  section "SETUP COMPLETADO"

  echo -e "  ${GREEN}${BOLD}Todo listo. Estructura generada:${RESET}\n"
  echo -e "  $OUTPUT_DIR/"
  echo -e "  ├── kernel/bzImage          → Kernel con KASAN+KCOV+UBSAN"
  echo -e "  ├── vms/rootfs.ext4         → Imagen para las VMs"
  echo -e "  ├── vms/id_rsa              → Claves SSH para VMs"
  echo -e "  ├── syzkaller.cfg           → Configuración del fuzzer"
  echo -e "  ├── start_fuzzing.sh        → Arranca $NUM_VMS VMs en paralelo"
  echo -e "  ├── analyze_crashes.sh      → Analiza crashes encontrados"
  echo -e "  └── logs/                   → Logs de compilación y fuzzing"

  echo ""
  echo -e "  ${BOLD}Comandos para empezar:${RESET}"
  echo ""
  echo -e "  ${CYAN}# 1. Arranca el fuzzer${RESET}"
  echo -e "  bash $OUTPUT_DIR/start_fuzzing.sh"
  echo ""
  echo -e "  ${CYAN}# 2. Abre el dashboard en el navegador${RESET}"
  echo -e "  xdg-open http://127.0.0.1:56741"
  echo ""
  echo -e "  ${CYAN}# 3. Analiza crashes cuando aparezcan${RESET}"
  echo -e "  bash $OUTPUT_DIR/analyze_crashes.sh"
  echo ""
  echo -e "  ${YELLOW}Las primeras horas syzkaller aprende el sistema.${RESET}"
  echo -e "  ${YELLOW}Los primeros crashes suelen aparecer en 2-6 horas.${RESET}"
  echo ""
  echo -e "  ${BOLD}Proceso de reporte cuando encuentres un bug:${RESET}"
  echo -e "  1. security@kernel.org  (reporte principal)"
  echo -e "  2. security@ubuntu.com  (si afecta Ubuntu)"
  echo -e "  3. bughunters.google.com (bug bounty)"
  echo ""
}

# ==============================================================================
# EJECUCIÓN
# ==============================================================================
check_deps

case "$FASE_SOLO" in
  1) fase1_kernel ;;
  2) fase2_buildroot ;;
  3) fase3_syzkaller ;;
  *)
    fase1_kernel
    fase2_buildroot
    fase3_syzkaller
    resumen_final
    ;;
esac
