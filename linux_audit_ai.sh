#!/usr/bin/env bash
# ==============================================================================
#  Linux Security Auditor + IA Local (Ollama)
#  Uso: sudo bash linux_audit_ai.sh [--full] [--model llama3.1:8b]
#  Propósito: auditoría defensiva + análisis inteligente con LLM local
# ==============================================================================
#    Creador: y2k         → Email: y2k@desarrollaria.com
# ==============================================================================

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Argumentos ────────────────────────────────────────────────────────────────
FULL_SCAN=false
AI_MODEL="deepseek-coder-v2:16b"
REPORT_FILE="/tmp/linux_audit_$(date +%Y%m%d_%H%M%S).txt"
USE_AI=true

for i in "$@"; do
  case $i in
    --full)         FULL_SCAN=true ;;
    --no-ai)        USE_AI=false ;;
    --model)        AI_MODEL="${2:-llama3.1:8b}"; shift ;;
    --report)       REPORT_FILE="${2:-$REPORT_FILE}"; shift ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
SCORE=0; TOTAL=0; FINDINGS=()

pass()    { echo -e "  ${GREEN}[PASS]${RESET} $*"; SCORE=$((SCORE+1)); TOTAL=$((TOTAL+1)); }
warn()    { echo -e "  ${YELLOW}[WARN]${RESET} $*"; TOTAL=$((TOTAL+1)); FINDINGS+=("WARN: $*"); }
fail()    { echo -e "  ${RED}[FAIL]${RESET} $*"; TOTAL=$((TOTAL+1)); FINDINGS+=("FAIL: $*"); }
info()    { echo -e "  ${CYAN}[INFO]${RESET} $*"; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

require_root() {
  [[ $EUID -eq 0 ]] || { echo -e "${RED}Ejecuta con sudo.${RESET}"; exit 1; }
}

require_root

# ── Banner ────────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗     █████╗ ██╗
  ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝    ██╔══██╗██║
  ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝     ███████║██║
  ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗     ██╔══██║██║
  ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗    ██║  ██║██║
  ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝
BANNER
echo -e "${RESET}"
echo -e "  ${BOLD}Linux Security Auditor + IA Local${RESET}"
echo -e "  Modelo: ${CYAN}${AI_MODEL}${RESET} | Informe: ${REPORT_FILE}"
echo -e "  Fecha:  $(date)"
echo ""

{
  echo "============================================================"
  echo " Linux Security Audit + AI Report"
  echo " Fecha:  $(date)"
  echo " Host:   $(hostname)"
  echo " Modelo: $AI_MODEL"
  echo "============================================================"
} > "$REPORT_FILE"

# ==============================================================================
# 1. SISTEMA
# ==============================================================================
section "1. SISTEMA OPERATIVO Y KERNEL"

KERNEL=$(uname -r)
DISTRO=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "desconocido")
DISTRO_VERSION=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "?")
ARCH=$(uname -m)

info "Kernel:   $KERNEL"
info "Distro:   $DISTRO $DISTRO_VERSION ($ARCH)"
info "Hostname: $(hostname)"
info "Uptime:   $(uptime -p 2>/dev/null || uptime)"

KERNEL_MAJOR=$(echo "$KERNEL" | cut -d. -f1)
[[ "$KERNEL_MAJOR" -ge 6 ]] && pass "Kernel reciente ($KERNEL)" || warn "Kernel $KERNEL — considera actualizar"

echo "Kernel: $KERNEL | Distro: $DISTRO $DISTRO_VERSION" >> "$REPORT_FILE"

# ==============================================================================
# 2. ACTUALIZACIONES
# ==============================================================================
section "2. ACTUALIZACIONES DE SEGURIDAD"

if command -v apt &>/dev/null; then
  apt-get update -qq 2>/dev/null
  SEC=$(apt-get --just-print upgrade 2>/dev/null | grep -ic "security" || true)
  ALL=$(apt-get --just-print upgrade 2>/dev/null | grep -c "^Inst" || true)
  info "Pendientes: $ALL total, $SEC de seguridad"
  [[ "$SEC" -gt 0 ]] && fail "$SEC actualizaciones de seguridad — ejecuta: apt upgrade" || pass "Sin actualizaciones críticas pendientes"
elif command -v dnf &>/dev/null; then
  SEC=$(dnf updateinfo list security 2>/dev/null | wc -l)
  [[ "$SEC" -gt 1 ]] && fail "$SEC actualizaciones de seguridad — dnf upgrade" || pass "Sin actualizaciones críticas"
fi

# ==============================================================================
# 3. MÓDULOS DEL KERNEL
# ==============================================================================
section "3. MÓDULOS DEL KERNEL PELIGROSOS"

declare -A MODS=(
  [algif_aead]="Copy Fail — page cache corruption (CVE-2024)"
  [dccp]="Protocolo obsoleto con historial de CVEs"
  [sctp]="Múltiples CVEs históricos"
  [rds]="RDS socket vulnerabilities"
  [tipc]="CVEs de RCE remoto"
  [bluetooth]="KNOB/BIAS attacks"
  [firewire_core]="DMA attacks"
  [thunderbolt]="DMA attacks"
  [usb_storage]="Exposición por USB"
)

for mod in "${!MODS[@]}"; do
  if lsmod 2>/dev/null | grep -q "^$mod"; then
    warn "Cargado: ${BOLD}$mod${RESET} — ${MODS[$mod]}"
  else
    pass "No cargado: $mod"
  fi
done

# ==============================================================================
# 4. SYSCTL
# ==============================================================================
section "4. PARÁMETROS SYSCTL"

check_sysctl() {
  local key="$1" expected="$2" desc="$3"
  local val; val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
  if [[ "$val" == "$expected" ]]; then
    pass "$key = $val ($desc)"
  else
    fail "$key = $val (esperado: $expected) — $desc"
  fi
}

check_sysctl "kernel.randomize_va_space"          "2" "ASLR completo"
check_sysctl "kernel.dmesg_restrict"              "1" "dmesg restringido"
check_sysctl "kernel.kptr_restrict"               "2" "Punteros de kernel ocultos"
check_sysctl "kernel.yama.ptrace_scope"           "1" "ptrace restringido"
check_sysctl "net.ipv4.conf.all.rp_filter"        "1" "Reverse path filtering"
check_sysctl "net.ipv4.conf.all.accept_redirects" "0" "Sin ICMP redirects"
check_sysctl "net.ipv4.tcp_syncookies"            "1" "Protección SYN flood"
check_sysctl "fs.protected_hardlinks"             "1" "Hardlinks protegidos"
check_sysctl "fs.protected_symlinks"              "1" "Symlinks protegidos"
check_sysctl "fs.suid_dumpable"                   "0" "Core dumps SUID off"
check_sysctl "kernel.unprivileged_bpf_disabled"   "1" "BPF sin privilegios off"
check_sysctl "net.core.bpf_jit_harden"            "2" "BPF JIT hardening"

# ==============================================================================
# 5. SUID/SGID
# ==============================================================================
section "5. BINARIOS SUID/SGID"

SUID_BINS=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
SUID_COUNT=$(echo "$SUID_BINS" | grep -c . || true)
info "Total SUID/SGID encontrados: $SUID_COUNT"

UNUSUAL=(python3 python perl ruby lua awk find vim nano tee nc netcat wget curl bash dash)
while IFS= read -r bin; do
  [[ -z "$bin" ]] && continue
  base=$(basename "$bin")
  for u in "${UNUSUAL[@]}"; do
    [[ "$base" == "$u" ]] && fail "SUID inusual: $bin"
  done
  echo "SUID: $bin" >> "$REPORT_FILE"
done <<< "$SUID_BINS"

# ==============================================================================
# 6. USUARIOS
# ==============================================================================
section "6. USUARIOS Y AUTENTICACIÓN"

UID0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
[[ $(echo "$UID0" | grep -c .) -gt 1 ]] && fail "Múltiples UID 0: $UID0" || pass "Solo root con UID 0"

EMPTY=$(awk -F: '($2==""||$2=="!!"||$2=="!"){print $1}' /etc/shadow 2>/dev/null || true)
[[ -n "$EMPTY" ]] && fail "Usuarios sin contraseña: $EMPTY" || pass "Todos los usuarios tienen contraseña"

SSH_ROOT=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null || echo "no configurado")
echo "$SSH_ROOT" | grep -qi " yes" && fail "SSH permite login como root" || pass "SSH root login: $SSH_ROOT"

SSH_PASS=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null || echo "no configurado")
echo "$SSH_PASS" | grep -qi " yes" && warn "SSH acepta contraseñas — prefiere solo claves" || pass "SSH: solo claves"

# ==============================================================================
# 7. SUDO
# ==============================================================================
section "7. CONFIGURACIÓN SUDO"

NOPASSWD=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)
[[ -n "$NOPASSWD" ]] && warn "Reglas NOPASSWD: $NOPASSWD" || pass "Sin reglas NOPASSWD"

# ==============================================================================
# 8. FIREWALL
# ==============================================================================
section "8. FIREWALL"

if command -v ufw &>/dev/null; then
  UFW=$(ufw status 2>/dev/null | head -1)
  echo "$UFW" | grep -qi "active" && pass "UFW activo" || fail "UFW inactivo — ejecuta: ufw enable"
elif command -v firewall-cmd &>/dev/null; then
  firewall-cmd --state 2>/dev/null | grep -qi "running" && pass "firewalld activo" || fail "firewalld inactivo"
else
  fail "Sin firewall detectado"
fi

# ==============================================================================
# 9. PERMISOS
# ==============================================================================
section "9. PERMISOS DE ARCHIVOS CRÍTICOS"

check_perm() {
  local file="$1" exp="$2" desc="$3"
  [[ ! -e "$file" ]] && { info "$file no existe"; return; }
  local actual; actual=$(stat -c "%a" "$file" 2>/dev/null)
  [[ "$actual" == "$exp" ]] && pass "$file ($actual)" || fail "$file permisos $actual (esperado $exp) — $desc"
}

check_perm "/etc/passwd"          "644" "Legible por todos"
check_perm "/etc/shadow"          "640" "Solo root/shadow"
check_perm "/etc/sudoers"         "440" "Solo lectura root"
check_perm "/etc/ssh/sshd_config" "600" "Solo root"
check_perm "/tmp"                 "1777" "Sticky bit"

WORLDWRITE=$(find / -xdev -type f -perm -0002 \
  ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" \
  2>/dev/null | head -10)
[[ -n "$WORLDWRITE" ]] && { warn "Archivos world-writable:"; echo "$WORLDWRITE" | while read -r f; do warn "  $f"; done; } \
                       || pass "Sin archivos world-writable peligrosos"

# ==============================================================================
# 10. VERSIONES Y CVEs
# ==============================================================================
section "10. VERSIONES DE SOFTWARE Y CVEs CONOCIDOS"

check_version() {
  local name="$1" cmd="$2" note="$3"
  local ver; ver=$(eval "$cmd" 2>/dev/null | head -1 || echo "no instalado")
  info "$name: $ver"
  info "  → $note"
  echo "VERSION $name: $ver | $note" >> "$REPORT_FILE"
}

check_version "OpenSSL"    "openssl version"               "CVE-2022-0778, CVE-2022-3786 — actualiza a 3.x"
check_version "OpenSSH"    "ssh -V 2>&1"                   "CVE-2023-38408 si < 9.3p2"
check_version "sudo"       "sudo --version | head -1"      "CVE-2021-3156 Baron Samedit si < 1.9.5p2"
check_version "glibc"      "ldd --version | head -1"       "CVE-2023-4911 Looney Tunables si < 2.38"
check_version "curl"       "curl --version | head -1"      "CVE-2023-38545 si < 8.4.0"
check_version "Python3"    "python3 --version"             "Verificar versión con soporte activo"
check_version "nginx"      "nginx -v 2>&1"                 "CVE-2021-23017 si < 1.21.0"
check_version "apache2"    "apache2 -v 2>/dev/null | head -1" "CVE-2021-41773 si 2.4.49"
check_version "Docker"     "docker --version 2>/dev/null"  "CVE-2019-5736 en versiones antiguas"

# ==============================================================================
# 11. PROTECCIONES DEL KERNEL
# ==============================================================================
section "11. PROTECCIONES DEL KERNEL"

ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
case "$ASLR" in
  2) pass "ASLR completo (nivel 2)" ;;
  1) warn "ASLR parcial (nivel 1)" ;;
  0) fail "ASLR deshabilitado" ;;
esac

grep -qi "nx\|xd" /proc/cpuinfo 2>/dev/null && pass "NX/XD bit activo" || warn "NX/XD no detectado"

if command -v aa-status &>/dev/null; then
  aa-status 2>/dev/null | grep -qi "profiles are loaded" && pass "AppArmor activo" || warn "AppArmor inactivo"
elif command -v getenforce &>/dev/null; then
  SE=$(getenforce 2>/dev/null)
  [[ "$SE" == "Enforcing" ]] && pass "SELinux Enforcing" || fail "SELinux: $SE"
else
  warn "Sin MAC (AppArmor/SELinux)"
fi

# ==============================================================================
# 12. LOGS
# ==============================================================================
section "12. SISTEMA DE LOGS"

systemctl is-active --quiet auditd 2>/dev/null && pass "auditd activo" || warn "auditd inactivo — instala: apt install auditd"
systemctl is-active --quiet rsyslog 2>/dev/null && pass "rsyslog activo" || warn "rsyslog inactivo"

info "Últimos intentos SSH fallidos (24h):"
journalctl -u sshd --since "24 hours ago" 2>/dev/null \
  | grep -i "failed\|invalid" | tail -5 \
  | while read -r line; do warn "  $line"; done || true

# ==============================================================================
# SCAN COMPLETO
# ==============================================================================
if [[ "$FULL_SCAN" == true ]]; then
  section "SCAN COMPLETO — INTEGRIDAD DE BINARIOS"
  if command -v debsums &>/dev/null; then
    debsums --silent 2>/dev/null | while read -r line; do
      fail "Binario modificado: $line"
      echo "MODIFIED: $line" >> "$REPORT_FILE"
    done
    pass "Verificación debsums completada"
  elif command -v rpm &>/dev/null; then
    rpm -Va 2>/dev/null | grep "^..5" | while read -r line; do
      fail "Hash diferente: $line"
      echo "MODIFIED: $line" >> "$REPORT_FILE"
    done
    pass "Verificación rpm -Va completada"
  else
    warn "Instala debsums para verificación de integridad: apt install debsums"
  fi
fi

# ==============================================================================
# RESUMEN
# ==============================================================================
section "RESUMEN"

PERCENT=$((SCORE * 100 / TOTAL))
echo ""
echo -e "  ${BOLD}Puntuación: ${SCORE}/${TOTAL} (${PERCENT}%)${RESET}"

if   [[ "$PERCENT" -ge 80 ]]; then echo -e "  ${GREEN}Estado: BUENO${RESET}"
elif [[ "$PERCENT" -ge 60 ]]; then echo -e "  ${YELLOW}Estado: MEJORABLE${RESET}"
else                                echo -e "  ${RED}Estado: CRÍTICO${RESET}"
fi

echo ""
echo -e "  ${BOLD}Hallazgos:${RESET}"
for f in "${FINDINGS[@]}"; do
  [[ "$f" == FAIL* ]] && echo -e "  ${RED}►${RESET} ${f#FAIL: }" || echo -e "  ${YELLOW}►${RESET} ${f#WARN: }"
done

{
  echo ""
  echo "PUNTUACIÓN: $SCORE/$TOTAL ($PERCENT%)"
  echo ""
  echo "HALLAZGOS:"
  for f in "${FINDINGS[@]}"; do echo "  - $f"; done
} >> "$REPORT_FILE"

# ==============================================================================
# ANÁLISIS CON IA LOCAL (OLLAMA)
# ==============================================================================
section "ANÁLISIS CON IA LOCAL — $AI_MODEL"

if [[ "$USE_AI" == false ]]; then
  info "Análisis IA omitido (--no-ai)"
  echo -e "\n  Informe guardado: ${BOLD}${REPORT_FILE}${RESET}"
  exit 0
fi

# Comprobar si Ollama está instalado
if ! command -v ollama &>/dev/null; then
  echo ""
  echo -e "  ${YELLOW}Ollama no está instalado.${RESET}"
  echo -e "  Instálalo con:"
  echo -e "  ${CYAN}curl -fsSL https://ollama.com/install.sh | sh${RESET}"
  echo -e "  ${CYAN}ollama pull ${AI_MODEL}${RESET}"
  echo ""
  echo -e "  Informe guardado: ${BOLD}${REPORT_FILE}${RESET}"
  exit 0
fi

# Comprobar si Ollama está corriendo
if ! ollama list &>/dev/null 2>&1; then
  echo -e "  ${YELLOW}Iniciando Ollama...${RESET}"
  ollama serve &>/dev/null &
  sleep 3
fi

# Comprobar si el modelo está disponible
if ! ollama list 2>/dev/null | grep -q "${AI_MODEL%%:*}"; then
  echo -e "  ${YELLOW}Modelo $AI_MODEL no encontrado. Descargando...${RESET}"
  ollama pull "$AI_MODEL"
fi

echo ""
echo -e "  ${CYAN}Enviando resultados a ${BOLD}${AI_MODEL}${RESET}${CYAN} para análisis...${RESET}"
echo ""

# Construir resumen para el modelo
FINDINGS_TEXT=$(printf '%s\n' "${FINDINGS[@]}")
SYSTEM_INFO="Kernel: $KERNEL | Distro: $DISTRO $DISTRO_VERSION | Arch: $ARCH"

PROMPT="Eres un experto en seguridad defensiva de Linux con 20 años de experiencia.
Analiza los siguientes hallazgos de una auditoría de seguridad y responde SOLO en español con:

1. RESUMEN EJECUTIVO (2-3 líneas del estado general)
2. RIESGOS CRÍTICOS (ordenados de mayor a menor severidad, con CVE si aplica)
3. COMANDOS DE CORRECCIÓN (exactos y listos para ejecutar por cada problema)
4. RECOMENDACIONES ADICIONALES DE HARDENING

Sistema auditado: $SYSTEM_INFO
Puntuación: $SCORE/$TOTAL ($PERCENT%)

HALLAZGOS:
$FINDINGS_TEXT

Sé conciso, técnico y práctico. No expliques conceptos básicos."

# Llamar al modelo y mostrar respuesta en tiempo real
echo -e "${BOLD}${GREEN}┌─ Análisis IA ────────────────────────────────────────────┐${RESET}"
echo ""

ollama run "$AI_MODEL" "$PROMPT" 2>/dev/null | while IFS= read -r line; do
  echo -e "  $line"
done

AI_ANALYSIS=$(ollama run "$AI_MODEL" "$PROMPT" 2>/dev/null || echo "Error al contactar con el modelo")

echo ""
echo -e "${BOLD}${GREEN}└──────────────────────────────────────────────────────────┘${RESET}"

# Guardar análisis IA en el informe
{
  echo ""
  echo "============================================================"
  echo " ANÁLISIS IA — $AI_MODEL"
  echo "============================================================"
  echo "$AI_ANALYSIS"
  echo ""
  echo "COMANDOS DE HARDENING BASE:"
  echo "  apt update && apt upgrade -y"
  echo "  ufw enable"
  echo "  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"
  echo "  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"
  echo "  echo 'kernel.randomize_va_space=2' >> /etc/sysctl.d/99-hardening.conf"
  echo "  echo 'kernel.dmesg_restrict=1' >> /etc/sysctl.d/99-hardening.conf"
  echo "  echo 'kernel.kptr_restrict=2' >> /etc/sysctl.d/99-hardening.conf"
  echo "  echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.d/99-hardening.conf"
  echo "  sysctl --system"
} >> "$REPORT_FILE"

echo ""
echo -e "  ${CYAN}Informe completo guardado en: ${BOLD}${REPORT_FILE}${RESET}"
echo ""
