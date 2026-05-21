#!/usr/bin/env bash
# ==============================================================================
#  setup_image.sh — Creación definitiva de imagen para syzkaller
#  Soluciona todos los problemas de red y SSH de una vez
#  Uso: sudo bash setup_image.sh
# ==============================================================================
#    Creador: y2k         → Email: y2k@desarrollaria.com
# ==============================================================================

set -euo pipefail

# ── Configuración ─────────────────────────────────────────────────────────────
WORK_DIR="$HOME/Work/LinuxScan"
ROOTFS="$WORK_DIR/output/vms/rootfs.ext4"
SSH_KEY="$WORK_DIR/output/vms/id_rsa"
MOUNT="/tmp/rootfs_mnt"
KERNEL="$WORK_DIR/output/kernel/bzImage"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }
info() { echo -e "${CYAN}[INFO]${RESET} $*"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

# ── Verificar root ────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || err "Ejecuta con sudo: sudo bash setup_image.sh"

# ── Verificar dependencias ────────────────────────────────────────────────────
for cmd in qemu-system-x86_64 debootstrap ssh-keygen; do
  command -v "$cmd" &>/dev/null || apt-get install -y qemu-system-x86 debootstrap openssh-client
done

# ── Paso 1: Parar syzkaller si está corriendo ─────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━ PASO 1: Parar syzkaller ━━━${RESET}"
pkill -f "syz-manager" 2>/dev/null || true
pkill -f "qemu-system-x86_64" 2>/dev/null || true
sleep 3
ok "Syzkaller detenido"

# ── Paso 2: Crear imagen nueva ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━ PASO 2: Crear imagen nueva (2GB) ━━━${RESET}"
mkdir -p "$(dirname "$ROOTFS")"
dd if=/dev/zero of="$ROOTFS" bs=1M count=2048 status=progress
mkfs.ext4 -F "$ROOTFS"
ok "Imagen creada: $ROOTFS"

# ── Paso 3: Montar imagen ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━ PASO 3: Montar imagen ━━━${RESET}"
mkdir -p "$MOUNT"
mountpoint -q "$MOUNT" && umount "$MOUNT" 2>/dev/null || true
mount -o loop "$ROOTFS" "$MOUNT"
ok "Imagen montada en $MOUNT"

# ── Paso 4: Instalar sistema base ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━ PASO 4: Instalar Debian base (~5 min) ━━━${RESET}"
debootstrap --arch=amd64 bookworm "$MOUNT" http://deb.debian.org/debian/
ok "Sistema base instalado"

# ── Paso 5: Configurar sistema ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━ PASO 5: Configurar sistema ━━━${RESET}"

# Montar sistemas de archivos necesarios para chroot
mount -t proc proc "$MOUNT/proc"
mount -t sysfs sysfs "$MOUNT/sys"
mount -t devtmpfs devtmpfs "$MOUNT/dev" 2>/dev/null || mount --bind /dev "$MOUNT/dev"
mount -t devpts devpts "$MOUNT/dev/pts"

chroot "$MOUNT" /bin/bash << 'CHROOT'
set -e

# Contraseña root
echo "root:root" | chpasswd

# Hostname
echo "syzkaller" > /etc/hostname
echo "127.0.0.1 syzkaller" >> /etc/hosts

# Instalar paquetes necesarios
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    openssh-server \
    isc-dhcp-client \
    net-tools \
    ifupdown \
    iproute2 \
    iputils-ping \
    curl \
    wget \
    strace \
    2>/dev/null

# Configurar red — nombre correcto de interfaz para QEMU e1000
cat > /etc/network/interfaces << 'NET'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp

auto enp0s3
iface enp0s3 inet dhcp
NET

# Configurar SSH optimizado para syzkaller
cat > /etc/ssh/sshd_config << 'SSH'
Port 22
PermitRootLogin yes
PermitEmptyPasswords yes
AuthorizedKeysFile /root/.ssh/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication yes
UsePAM no
UseDNS no
ChallengeResponseAuthentication no
PrintMotd no
PrintLastLog no
TCPKeepAlive yes
ClientAliveInterval 10
ClientAliveCountMax 3
LoginGraceTime 30
SSH

# Crear script de inicio de red que funciona siempre
cat > /etc/rc.local << 'RC'
#!/bin/bash
# Levantar red al arrancar — funciona con cualquier nombre de interfaz
for iface in eth0 enp0s3 ens3 ens4; do
    if ip link show "$iface" &>/dev/null; then
        ip link set "$iface" up
        dhclient "$iface" -timeout 30 2>/dev/null &
    fi
done
exit 0
RC
chmod +x /etc/rc.local

# Habilitar rc.local en systemd
cat > /etc/systemd/system/rc-local.service << 'SVC'
[Unit]
Description=RC Local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=30
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC

# Habilitar servicios
systemctl enable ssh 2>/dev/null || true
systemctl enable rc-local 2>/dev/null || true
systemctl disable systemd-logind 2>/dev/null || true

# Configurar fstab
echo "/dev/sda / ext4 errors=remount-ro 0 1" > /etc/fstab

# Configurar locale para evitar warnings
echo "LANG=C" > /etc/default/locale

CHROOT

ok "Sistema configurado"

# ── Paso 6: Instalar clave SSH ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━ PASO 6: Instalar clave SSH ━━━${RESET}"

# Generar claves si no existen
if [[ ! -f "$SSH_KEY" ]]; then
    mkdir -p "$(dirname "$SSH_KEY")"
    ssh-keygen -t rsa -b 2048 -N "" -f "$SSH_KEY" -q
    ok "Claves SSH generadas"
fi

mkdir -p "$MOUNT/root/.ssh"
cp "${SSH_KEY}.pub" "$MOUNT/root/.ssh/authorized_keys"
chmod 700 "$MOUNT/root/.ssh"
chmod 600 "$MOUNT/root/.ssh/authorized_keys"
ok "Clave SSH instalada"

# ── Paso 7: Desmontar ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━ PASO 7: Desmontar imagen ━━━${RESET}"
umount "$MOUNT/dev/pts" 2>/dev/null || true
umount "$MOUNT/dev" 2>/dev/null || true
umount "$MOUNT/sys" 2>/dev/null || true
umount "$MOUNT/proc" 2>/dev/null || true
umount "$MOUNT"
ok "Imagen desmontada correctamente"

# ── Paso 8: Verificar imagen ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━ PASO 8: Verificar imagen ━━━${RESET}"
e2fsck -f -y "$ROOTFS" 2>/dev/null || true
ok "Imagen verificada"

# ── Paso 9: Actualizar config syzkaller ───────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━ PASO 9: Actualizar configuración syzkaller ━━━${RESET}"

# Detectar usuario real (no root)
REAL_USER=$(logname 2>/dev/null || echo "${SUDO_USER:-$USER}")
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

cat > "$WORK_DIR/output/syzkaller.cfg" << EOF
{
  "target": "linux/amd64",
  "http": "127.0.0.1:56741",
  "workdir": "$WORK_DIR/output/syzkaller_workdir",
  "kernel_obj": "$WORK_DIR/linux",
  "image": "$ROOTFS",
  "sshkey": "$SSH_KEY",
  "ssh_user": "root",
  "syzkaller": "$WORK_DIR/syzkaller",
  "procs": 8,
  "sandbox": "none",
  "cover": true,
  "reproduce": true,
  "type": "qemu",
  "vm": {
    "count": 8,
    "kernel": "$KERNEL",
    "cpu": 2,
    "mem": 3072,
    "cmdline": "console=ttyS0 root=/dev/sda rw oops=panic panic_on_warn=1 panic=-1 earlyprintk=serial",
    "qemu_args": "-enable-kvm",
    "boot_time": 600
  }
}
EOF

ok "Configuración syzkaller actualizada"

# ── Resumen ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${GREEN}  IMAGEN LISTA — Todo configurado correctamente${RESET}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  Imagen:     $ROOTFS"
echo -e "  Clave SSH:  $SSH_KEY"
echo -e "  Config:     $WORK_DIR/output/syzkaller.cfg"
echo ""
echo -e "  ${BOLD}Verificación manual (opcional):${RESET}"
echo -e "  ${CYAN}qemu-system-x86_64 -m 2048 -smp 2 -enable-kvm \\${RESET}"
echo -e "  ${CYAN}  -kernel $KERNEL \\${RESET}"
echo -e "  ${CYAN}  -hda $ROOTFS -snapshot \\${RESET}"
echo -e "  ${CYAN}  -append 'console=ttyS0 root=/dev/sda rw' \\${RESET}"
echo -e "  ${CYAN}  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:10022-:22 \\${RESET}"
echo -e "  ${CYAN}  -device e1000,netdev=net0 -nographic${RESET}"
echo ""
echo -e "  ${BOLD}Arrancar syzkaller:${RESET}"
echo -e "  ${CYAN}bash $WORK_DIR/syz.sh start${RESET}"
echo ""
