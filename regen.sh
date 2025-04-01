#!/bin/bash

# Configuración de manejo de errores
set -eo pipefail

# Definición de colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Función de registro
log() {
  local level=$1; shift
  local color
  case "$level" in
    "INFO") color="$GREEN" ;;
    "WARN") color="$YELLOW" ;;
    "ERROR") color="$RED" ;;
    "DEBUG") color="$BLUE" ;;
    *) color="$NC" ;;
  esac
  echo -e "${color}[$level]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

# Verificar permisos de administrador
check_permissions() {
  if [ "$(id -u)" -ne 0 ]; then
    log "ERROR" "Se requieren permisos de administrador. Ejecute con sudo:"
    echo "  sudo $0"
    exit 1
  fi
}

# Buscar directorio de instalación de Cursor
find_cursor_dir() {
  local possible_dirs=(
    "/opt/Cursor"
    "/opt/cursor-bin"
    "/usr/lib/cursor"
    "$HOME/.cursor"
  )

  for dir in "${possible_dirs[@]}"; do
    if [ -d "$dir" ]; then
      echo "$dir"
      return 0
    fi
  done

  # Si no se encuentra, devolver un valor predeterminado en lugar de terminar
  log "WARN" "No se pudo encontrar el directorio de Cursor, usando valor predeterminado"
  echo "Cursor"
}

# Obtener PIDs de Cursor
get_cursor_pids() {
  # Obtener nuestro propio PID
  local current_pid=$$
  
  # Buscar procesos con nombres relacionados con Cursor, excluyendo nuestro PID
  pids=$(pgrep -i "cursor|electron" 2>/dev/null | grep -v "$current_pid" || true)
  
  # Buscar procesos adicionales relacionados con Cursor
  additional_pids=$(ps aux | grep -i "[c]ursor" | awk '{print $2}' | grep -v "$current_pid" || true)
  
  # Combinar, eliminar duplicados y espacios en blanco
  local all_pids=$(echo "$pids $additional_pids" | tr ' ' '\n' | grep -v "^$" | sort -u | tr '\n' ' ')
  echo "$all_pids" | xargs
}

# Terminar procesos de Cursor
terminate_cursor() {
  log "INFO" "Verificando si Cursor está en ejecución..."
  local pids=$(get_cursor_pids)
  
  if [ -z "$pids" ]; then
    log "INFO" "No se encontraron procesos de Cursor en ejecución"
    return 0
  fi

  log "WARN" "Se encontraron los siguientes procesos de Cursor:"
  echo "----------------------------------------"
  if [ -n "$pids" ]; then
    ps -fp $pids 2>/dev/null || log "WARN" "No se pudieron mostrar los detalles del proceso"
  fi
  echo "----------------------------------------"

  read -r -p "¿Desea cerrar Cursor antes de continuar? [s/N] " response </dev/tty
  if [[ "$response" =~ ^([sS][iI]|[sS])$ ]]; then
    log "INFO" "Intentando cerrar Cursor de forma segura..."
    kill -TERM $pids 2>/dev/null || true
    sleep 2

    local remaining=$(get_cursor_pids)
    if [ -n "$remaining" ]; then
      log "WARN" "Algunos procesos persisten. Intentando forzar cierre..."
      kill -9 $remaining 2>/dev/null || true
      sleep 1
    fi

    log "INFO" "Cursor se ha cerrado correctamente"
  else
    log "WARN" "Continuando sin cerrar Cursor. Algunos cambios podrían no aplicarse correctamente."
  fi
}

# Realizar copia de seguridad
backup_files() {
  local user_home=$1
  local cursor_dir=$(find_cursor_dir)
  local cursor_dir_name=$(basename "$cursor_dir" 2>/dev/null || echo "Cursor")
  local config_dir="$user_home/.config/$cursor_dir_name/User/globalStorage"
  local storage_file="$config_dir/storage.json"
  local backup_dir="$config_dir/backups"

  mkdir -p "$backup_dir"
  local timestamp=$(date +%Y%m%d_%H%M%S)

  # Asegurar permisos correctos
  chown -R $(logname):$(logname) "$config_dir" 2>/dev/null || true
  chmod -R 755 "$config_dir" 2>/dev/null || true

  if [ -f "$storage_file" ]; then
    cp "$storage_file" "$backup_dir/storage.json.bak_$timestamp"
    chmod 644 "$backup_dir/storage.json.bak_$timestamp" 2>/dev/null || true
    log "INFO" "Configuración respaldada en: $backup_dir/storage.json.bak_$timestamp"
  else
    log "WARN" "No se encontró el archivo de almacenamiento en $storage_file"
  fi

  local machine_id="/etc/machine-id"
  if [ -f "$machine_id" ]; then
    cp "$machine_id" "$backup_dir/machine-id.bak_$timestamp"
    chmod 644 "$backup_dir/machine-id.bak_$timestamp" 2>/dev/null || true
    log "INFO" "ID de máquina respaldado"
  fi
}

# Generar nuevos IDs
generate_ids() {
  local user_home=$1
  local cursor_dir=$(find_cursor_dir)
  local cursor_dir_name=$(basename "$cursor_dir" 2>/dev/null || echo "Cursor")
  local config_dir="$user_home/.config/$cursor_dir_name/User/globalStorage"
  local config_file="$config_dir/storage.json"

  local new_machine_id=$(uuidgen | tr -d '-')
  local new_device_id=$(uuidgen)
  local new_sqm_id="$(uuidgen | tr '[:lower:]' '[:upper:]')"

  log "DEBUG" "Generando nuevos IDs:"
  log "DEBUG" "ID de máquina: $new_machine_id"
  log "DEBUG" "ID de dispositivo: $new_device_id"
  log "DEBUG" "ID de telemetría: $new_sqm_id"

  if [ ! -d "$config_dir" ]; then
    mkdir -p "$config_dir"
  fi
  
  if [ -f "$config_file" ]; then
    chattr -i "$config_file" 2>/dev/null || true
  fi

  chown -R $(logname):$(logname) "$config_dir"
  chmod -R 755 "$config_dir"

  if [ ! -f "$config_file" ]; then
    echo '{}' > "$config_file"
  fi

  echo "$new_machine_id" | tr -d '-' | cut -c1-32 > "/etc/machine-id"

  tmp_file=$(mktemp)
  jq --arg machine "$new_machine_id" \
     --arg device "$new_device_id" \
     --arg sqm "{$new_sqm_id}" \
     '.telemetry.machineId = $machine |
      .telemetry.devDeviceId = $device |
      .telemetry.sqmId = $sqm' "$config_file" > "$tmp_file"

  mv "$tmp_file" "$config_file"
  chmod 644 "$config_file"
  chown $(logname):$(logname) "$config_file"
  chattr -i "$config_file" 2>/dev/null || true
}

# Mostrar menú y obtener confirmación
mostrar_menu() {
  clear
  echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║${NC}             ${GREEN}↺ CURSOR ID RENEW TOOL ↺${NC}                 	${BLUE}       ║${NC}"
  echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo
  echo -e "${YELLOW}▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀${NC}"
  echo -e "${GREEN}✓ DESCRIPCIÓN:${NC}"
  echo -e "  Esta herramienta actualiza los identificadores únicos de Cursor,"
  echo -e "  lo que puede ayudar a resolver problemas de licencia y renovar"
  echo -e "  la identificación del dispositivo en el sistema."
  echo
  echo -e "${GREEN}✓ ACCIONES QUE SE REALIZARÁN:${NC}"
  echo
  echo -e "  ${BLUE}1.${NC} Detectar instalación de Cursor y procesos activos"
  echo -e "     ${YELLOW}→${NC} Verificará si Cursor está en ejecución"
  echo -e "     ${YELLOW}→${NC} Ofrecerá cerrar la aplicación de forma segura"
  echo
  echo -e "  ${BLUE}2.${NC} Crear copias de seguridad automáticas"
  echo -e "     ${YELLOW}→${NC} Respaldará archivos de configuración actuales"
  echo -e "     ${YELLOW}→${NC} Guardará el ID de máquina original"
  echo -e "     ${YELLOW}→${NC} Almacenará todo con marca de tiempo para recuperación"
  echo
  echo -e "  ${BLUE}3.${NC} Generar nuevos identificadores"
  echo -e "     ${YELLOW}→${NC} ID de máquina: Identificador único del sistema"
  echo -e "     ${YELLOW}→${NC} ID de dispositivo: Reconocimiento del hardware"
  echo -e "     ${YELLOW}→${NC} ID de telemetría: Renovación de datos estadísticos"
  echo 
  echo -e "${GREEN}✓ BENEFICIOS:${NC}"
  echo -e "  • Soluciona problemas de autorización"
  echo -e "  • Restablece el estado del editor"
  echo -e "  • Mantiene la privacidad de su instalación"
  echo -e "  • Proceso automático y seguro"
  echo
  echo -e "${RED}▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄${NC}"
  echo -e "${RED}⚠ NOTA IMPORTANTE:${NC}"
  echo -e "  Este proceso es seguro, pero modificará la configuración de"
  echo -e "  Cursor. Todas las copias de seguridad se guardan automáticamente."
  echo -e "${RED}▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄${NC}"
  echo
  
  while true; do
    echo -e "${GREEN}¿Desea continuar con el proceso?${NC}"
    read -r -p "[s/N] " response </dev/tty
    case "$response" in
      [sS]|[sS][iI])
        echo -e "${GREEN}▶ Iniciando el proceso...${NC}"
        sleep 1
        return 0
        ;;
      [nN]|[nN][oO]|"")
        echo -e "${YELLOW}▶ Operación cancelada por el usuario${NC}"
        log "INFO" "Operación cancelada por el usuario"
        exit 0
        ;;
      *)
        echo -e "${RED}✗ Por favor, responda 's' (sí) o 'n' (no)${NC}"
        ;;
    esac
  done
}

# Función principal
main() {
  check_permissions
  mostrar_menu

  local current_user=$(logname 2>/dev/null || echo "$SUDO_USER")
  local user_home=$(getent passwd "$current_user" | cut -d: -f6)

  terminate_cursor
  backup_files "$user_home"
  generate_ids "$user_home"

  echo
  echo -e "${GREEN}¡Proceso completado con éxito!${NC}"
  echo -e "${YELLOW}Acciones realizadas:${NC}"
  echo "- Se verificó el estado de Cursor"
  echo "- Se creó una copia de seguridad de la configuración"
  echo "- Se generaron nuevos IDs"
  echo
  echo -e "${GREEN}Por favor, reinicie Cursor para aplicar los cambios.${NC}"
}

main "$@"
