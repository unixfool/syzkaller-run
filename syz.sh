#!/usr/bin/env bash
# ==============================================================================
#  Syzkaller Manager — Gestión completa del entorno de fuzzing
#  Uso:
#    bash syz.sh start    → arranca syzkaller
#    bash syz.sh stop     → para syzkaller
#    bash syz.sh restart  → reinicia syzkaller
#    bash syz.sh status   → estado de VMs y crashes
#    bash syz.sh crashes  → muestra crashes encontrados
#    bash syz.sh logs     → muestra logs en tiempo real
#    bash syz.sh fix-ssh  → corrige problema de SSH en la imagen
# ==============================================================================
#    Creador: y2k         → Email: y2k@desarrollaria.com
# ==============================================================================

# ── Configuración ─────────────────────────────────────────────────────────────
WORK_DIR="$HOME/Work/LinuxScan"
SYZKALLER="$WORK_DIR/syzkaller/bin/syz-manager"
CONFIG="$WORK_DIR/output/syzkaller.cfg"
LOG_DIR="$WORK_DIR/output/logs"
WORKDIR="$WORK_DIR/output/syzkaller_workdir_6.12.89"
ROOTFS="$WORK_DIR/output/vms/rootfs.ext4"
SSH_KEY="$WORK_DIR/output/vms/id_rsa"
MOUNT_POINT="/tmp/rootfs_mnt"
PIDFILE="/tmp/syzkaller.pid"

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()      { echo -e "${GREEN}[OK]${RESET} $*"; }
err()     { echo -e "${RED}[ERROR]${RESET} $*"; }
info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }

export PATH=$PATH:/usr/local/go/bin

# ── Funciones ─────────────────────────────────────────────────────────────────

cmd_start() {
  if pgrep -f "syz-manager" > /dev/null 2>&1; then
    warn "Syzkaller ya está corriendo."
    cmd_status
    return
  fi

  mkdir -p "$LOG_DIR"
  LOG="$LOG_DIR/syzkaller_$(date +%Y%m%d_%H%M%S).log"

  echo ""
  echo -e "${BOLD}${CYAN}Arrancando Syzkaller...${RESET}"
  echo -e "  Config:    $CONFIG"
  echo -e "  Log:       $LOG"
  echo -e "  Dashboard: http://127.0.0.1:56741"
  echo ""

  nohup "$SYZKALLER" -config="$CONFIG" > "$LOG" 2>&1 &
  echo $! > "$PIDFILE"

  sleep 2

  if pgrep -f "syz-manager" > /dev/null 2>&1; then
    ok "Syzkaller arrancado (PID: $(cat $PIDFILE))"
    echo ""
    info "Ver logs en tiempo real:  bash syz.sh logs"
    info "Ver estado de VMs:        bash syz.sh status"
    info "Dashboard:                http://127.0.0.1:56741"
    info "Para detener:             bash syz.sh stop"
  else
    err "Error al arrancar. Revisa: $LOG"
  fi
}

cmd_stop() {
  if ! pgrep -f "syz-manager" > /dev/null 2>&1; then
    warn "Syzkaller no está corriendo."
    return
  fi

  info "Parando Syzkaller..."
  pkill -f "syz-manager" 2>/dev/null || true
  sleep 2
  pkill -9 -f "syz-manager" 2>/dev/null || true
  pkill -f "qemu-system-x86_64" 2>/dev/null || true
  rm -f "$PIDFILE"
  ok "Syzkaller detenido."
}

cmd_restart() {
  info "Reiniciando Syzkaller..."
  cmd_stop
  sleep 2
  cmd_start
}

cmd_status() {
  echo ""
  echo -e "${BOLD}══ Estado de Syzkaller ══${RESET}"
  echo ""

  # Estado del proceso
  if pgrep -f "syz-manager" > /dev/null 2>&1; then
    ok "syz-manager corriendo (PID: $(pgrep -f syz-manager))"
  else
    err "syz-manager NO está corriendo"
  fi

  # VMs activas
  VM_COUNT=$(ps aux | grep qemu | grep -v grep | wc -l)
  info "VMs QEMU activas: $VM_COUNT"

  # Último log
  LAST_LOG=$(ls -t "$LOG_DIR"/*.log 2>/dev/null | head -1)
  if [[ -n "$LAST_LOG" ]]; then
    info "Último log: $LAST_LOG"
    echo ""
    echo -e "${BOLD}Últimas líneas del log:${RESET}"
    tail -10 "$LAST_LOG" | while read -r line; do
      echo "  $line"
    done
  fi

  # Crashes
  echo ""
  cmd_crashes_summary
}

cmd_logs() {
  LAST_LOG=$(ls -t "$LOG_DIR"/*.log 2>/dev/null | head -1)
  if [[ -z "$LAST_LOG" ]]; then
    err "No hay logs disponibles. ¿Arrancaste syzkaller?"
    return
  fi
  info "Mostrando log en tiempo real (Ctrl+C para salir):"
  echo ""
  tail -f "$LAST_LOG"
}

cmd_crashes_summary() {
  CRASH_DIR="$WORKDIR/crashes"

  if [[ ! -d "$CRASH_DIR" ]]; then
    warn "Sin directorio de crashes todavía."
    return
  fi

  COUNT=0
  REAL_COUNT=0

  for crash_dir in "$CRASH_DIR"/*/; do
    [[ -d "$crash_dir" ]] || continue
    COUNT=$((COUNT+1))
    DESC=$(cat "$crash_dir/description" 2>/dev/null || echo "Sin descripción")

    # Ignorar errores de SSH que no son bugs reales
    if echo "$DESC" | grep -q "can't ssh"; then
      continue
    fi

    REAL_COUNT=$((REAL_COUNT+1))
    echo -e "  ${RED}[CRASH $REAL_COUNT]${RESET} $DESC"
    echo -e "  ${CYAN}Dir:${RESET} $crash_dir"

    # ¿Tiene reproductor?
    if [[ -f "$crash_dir/repro.c" ]]; then
      echo -e "  ${GREEN}✓ repro.c disponible — listo para reportar${RESET}"
    elif [[ -f "$crash_dir/repro.prog" ]]; then
      echo -e "  ${YELLOW}✓ repro.prog disponible${RESET}"
    fi
    echo ""
  done

  if [[ $REAL_COUNT -eq 0 ]]; then
    if [[ $COUNT -gt 0 ]]; then
      warn "Solo errores de SSH encontrados ($COUNT) — VMs aún inicializando"
    else
      info "Sin crashes todavía — syzkaller está aprendiendo el sistema"
    fi
  else
    echo -e "${GREEN}${BOLD}$REAL_COUNT crash(es) reales encontrados${RESET}"
    echo ""
    echo -e "Próximos pasos:"
    echo -e "  1. Verifica el crash con el repro.c"
    echo -e "  2. Reporta en: security@kernel.org"
    echo -e "  3. Bug bounty: bughunters.google.com"
  fi
}

cmd_crashes() {
  echo ""
  echo -e "${BOLD}${CYAN}══ Crashes Encontrados ══${RESET}"
  echo ""
  cmd_crashes_summary
}

cmd_fix_ssh() {
  info "Corrigiendo SSH en la imagen rootfs..."

  # Parar syzkaller si está corriendo
  if pgrep -f "syz-manager" > /dev/null 2>&1; then
    warn "Parando syzkaller primero..."
    cmd_stop
    sleep 2
  fi

  # Montar imagen
  mkdir -p "$MOUNT_POINT"
  if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    sudo umount "$MOUNT_POINT" 2>/dev/null || true
  fi

  sudo mount -o loop "$ROOTFS" "$MOUNT_POINT" || {
    err "No se puede montar $ROOTFS"
    return 1
  }

  # Instalar clave SSH
  sudo mkdir -p "$MOUNT_POINT/root/.ssh"
  sudo cp "${SSH_KEY}.pub" "$MOUNT_POINT/root/.ssh/authorized_keys"
  sudo chmod 700 "$MOUNT_POINT/root/.ssh"
  sudo chmod 600 "$MOUNT_POINT/root/.ssh/authorized_keys"

  # Corregir configuración SSH
  sudo chroot "$MOUNT_POINT" /bin/bash << 'EOF'
# Configuración SSH optimizada para fuzzing
cat > /etc/ssh/sshd_config << 'SSHCONF'
PermitRootLogin yes
PermitEmptyPasswords yes
AuthorizedKeysFile .ssh/authorized_keys
UsePAM no
UseDNS no
ChallengeResponseAuthentication no
PrintMotd no
SSHCONF

# Deshabilitar servicios que bloquean el arranque
systemctl disable systemd-logind 2>/dev/null || true
systemctl disable networking 2>/dev/null || true
systemctl enable ssh 2>/dev/null || true
EOF

  sudo umount "$MOUNT_POINT"
  ok "SSH corregido en la imagen"

  # Reiniciar syzkaller
  info "Reiniciando syzkaller..."
  sleep 1
  cmd_start
}

cmd_help() {
  echo ""
  echo -e "${BOLD}${CYAN}Syzkaller Manager${RESET}"
  echo ""
  echo -e "  ${BOLD}bash syz.sh start${RESET}    → Arranca syzkaller en background"
  echo -e "  ${BOLD}bash syz.sh stop${RESET}     → Para syzkaller y VMs"
  echo -e "  ${BOLD}bash syz.sh restart${RESET}  → Reinicia syzkaller"
  echo -e "  ${BOLD}bash syz.sh status${RESET}   → Estado actual y últimas líneas del log"
  echo -e "  ${BOLD}bash syz.sh crashes${RESET}  → Muestra bugs encontrados"
  echo -e "  ${BOLD}bash syz.sh logs${RESET}     → Log en tiempo real (Ctrl+C para salir)"
  echo -e "  ${BOLD}bash syz.sh fix-ssh${RESET}  → Corrige problema de SSH en la imagen"
  echo ""
  echo -e "  Dashboard: ${CYAN}http://127.0.0.1:56741${RESET}"
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
case "${1:-help}" in
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  restart) cmd_restart ;;
  status)  cmd_status ;;
  crashes) cmd_crashes ;;
  logs)    cmd_logs ;;
  fix-ssh) cmd_fix_ssh ;;
  *)       cmd_help ;;
esac
