#!/usr/bin/env bash
# ==============================================================================
#  check_crashes.sh — Revisar crashes nuevos de syzkaller
#  Uso: bash check_crashes.sh
# ==============================================================================
#    Creador: y2k         → Email: y2k@desarrollaria.com
# ==============================================================================

WORK_DIR="$HOME/Work/LinuxScan"
CRASH_DIR="$WORK_DIR/output/syzkaller_workdir/crashes"
REPORTED_FILE="$WORK_DIR/output/reported_crashes.txt"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# Crear archivo de crashes ya reportados si no existe
touch "$REPORTED_FILE"

clear
echo -e "${BOLD}${CYAN}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║     SYZKALLER CRASH CHECKER               ║"
echo "  ║     LinuxScan — y2k@desarrollaria.com     ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  Fecha: $(date)"
echo -e "  Crashes dir: $CRASH_DIR"
echo ""

# ── Ignorar estos crashes — son de infraestructura, no bugs reales ────────────
IGNORE_LIST=(
  "can't ssh into the instance"
  "failed to read from qemu"
  "no output from test machine"
  "lost connection to test machine"
  "executor failed"
)

is_ignored() {
  local desc="$1"
  for ignore in "${IGNORE_LIST[@]}"; do
    if echo "$desc" | grep -qi "$ignore"; then
      return 0
    fi
  done
  return 1
}

# ── Contar crashes ────────────────────────────────────────────────────────────
TOTAL=0
REAL=0
NEW=0
HAVE_REPRO=0

echo -e "${BOLD}══ CRASHES ENCONTRADOS ══${RESET}"
echo ""

for crash_dir in "$CRASH_DIR"/*/; do
  [[ -d "$crash_dir" ]] || continue
  TOTAL=$((TOTAL+1))

  DESC=$(cat "$crash_dir/description" 2>/dev/null || echo "Sin descripción")
  HASH=$(basename "$crash_dir")

  # Ignorar crashes de infraestructura
  if is_ignored "$DESC"; then
    continue
  fi

  REAL=$((REAL+1))

  # Comprobar si tiene reproductor
  HAS_REPRO=false
  REPRO_TYPE=""
  if [[ -f "$crash_dir/repro.c" ]]; then
    HAS_REPRO=true
    REPRO_TYPE="repro.c (C)"
    HAVE_REPRO=$((HAVE_REPRO+1))
  elif [[ -f "$crash_dir/repro.cprog" ]]; then
    HAS_REPRO=true
    REPRO_TYPE="repro.cprog"
    HAVE_REPRO=$((HAVE_REPRO+1))
  elif [[ -f "$crash_dir/repro.prog" ]]; then
    HAS_REPRO=true
    REPRO_TYPE="repro.prog (syzkaller)"
    HAVE_REPRO=$((HAVE_REPRO+1))
  fi

  # Comprobar si ya fue reportado
  IS_NEW=true
  if grep -q "$HASH" "$REPORTED_FILE" 2>/dev/null; then
    IS_NEW=false
  else
    NEW=$((NEW+1))
  fi

  # Mostrar crash
  if $IS_NEW; then
    echo -e "  ${RED}[NUEVO]${RESET} ${BOLD}$DESC${RESET}"
  else
    echo -e "  ${YELLOW}[YA REPORTADO]${RESET} $DESC"
  fi

  echo -e "  ${CYAN}Hash:${RESET}  $HASH"
  echo -e "  ${CYAN}Dir:${RESET}   $crash_dir"

  if $HAS_REPRO; then
    echo -e "  ${GREEN}✓ Reproductor: $REPRO_TYPE${RESET}"
  else
    echo -e "  ${YELLOW}✗ Sin reproductor todavía${RESET}"
  fi

  # Mostrar logs disponibles
  LOG_COUNT=$(ls "$crash_dir"log* 2>/dev/null | wc -l)
  echo -e "  ${CYAN}Logs:${RESET}  $LOG_COUNT ficheros"

  # Mostrar primera línea del report si existe
  if [[ -f "$crash_dir/report0" ]]; then
    SUBSYSTEM=$(grep "WARNING\|BUG\|KASAN\|use-after-free\|null-ptr" "$crash_dir/report0" 2>/dev/null | head -1)
    [[ -n "$SUBSYSTEM" ]] && echo -e "  ${CYAN}Tipo:${RESET}  $SUBSYSTEM"
  fi

  echo ""
done

# ── Resumen ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}══ RESUMEN ══${RESET}"
echo ""
echo -e "  Total crashes:        $TOTAL"
echo -e "  ${GREEN}Bugs reales:          $REAL${RESET}"
echo -e "  ${GREEN}Con reproductor:      $HAVE_REPRO${RESET}"
echo -e "  ${RED}Nuevos sin reportar:  $NEW${RESET}"
echo ""

# ── Instrucciones para reportar los nuevos ────────────────────────────────────
if [[ $NEW -gt 0 ]]; then
  echo -e "${BOLD}${RED}Tienes $NEW crash(es) nuevo(s) para reportar.${RESET}"
  echo ""
  echo -e "  Para reportar ejecuta:"
  echo -e "  ${CYAN}bash ~/Work/LinuxScan/report_crash.sh <hash>${RESET}"
  echo ""

  echo -e "${BOLD}Crashes nuevos pendientes de reportar:${RESET}"
  for crash_dir in "$CRASH_DIR"/*/; do
    [[ -d "$crash_dir" ]] || continue
    DESC=$(cat "$crash_dir/description" 2>/dev/null || echo "Sin descripción")
    HASH=$(basename "$crash_dir")
    is_ignored "$DESC" && continue
    grep -q "$HASH" "$REPORTED_FILE" 2>/dev/null && continue
    echo -e "  ${RED}►${RESET} $DESC"
    echo -e "    bash ~/Work/LinuxScan/report_crash.sh $HASH"
    echo ""
  done
else
  echo -e "${GREEN}Sin crashes nuevos pendientes de reportar.${RESET}"
fi

# ── Estado de syzkaller ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══ ESTADO SYZKALLER ══${RESET}"
echo ""
if pgrep -f "syz-manager" > /dev/null 2>&1; then
  echo -e "  ${GREEN}✓ Syzkaller corriendo${RESET}"
  VM_COUNT=$(ps aux | grep qemu | grep -v grep | wc -l)
  echo -e "  ${GREEN}✓ VMs activas: $VM_COUNT${RESET}"
else
  echo -e "  ${RED}✗ Syzkaller NO está corriendo${RESET}"
  echo -e "  Arranca con: bash ~/Work/LinuxScan/syz.sh start"
fi

# Mostrar últimas líneas del log
LAST_LOG=$(ls -t "$WORK_DIR/output/logs/"*.log 2>/dev/null | head -1)
if [[ -n "$LAST_LOG" ]]; then
  echo ""
  echo -e "  ${BOLD}Últimas líneas del log:${RESET}"
  tail -5 "$LAST_LOG" | while read -r line; do
    echo -e "  $line"
  done
fi

echo ""
echo -e "  Dashboard: ${CYAN}http://127.0.0.1:56741${RESET}"
echo ""
