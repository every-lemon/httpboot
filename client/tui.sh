#!/bin/bash
# All program output stays off the terminal while a dialog owns it.
export TERM=${TERM:-linux}
if [[ -r /httpboot/boot-guard.sh ]]; then source /httpboot/boot-guard.sh; fi
export NEWT_COLORS='root=white,black window=white,black border=white,black title=white,black textbox=white,black acttextbox=white,black shadow=black,black listbox=white,black actlistbox=black,white actsellistbox=black,white button=black,white actbutton=white,gray fullscale=black,white emptyscale=white,black checkbox=white,black actcheckbox=black,white compactbutton=black,white sellistbox=black,white roottext=white,black'
# PID 1 has no controlling terminal. Reopen the device after each dialog's
# session exits; an inherited descriptor can otherwise return EOF at the next
# dialog. Network/recovery shells that already own a terminal retain it.
tui_run() {
    if ( : </dev/tty ) 2>/dev/null; then
        whiptail "$@" <"${TTY:-/dev/tty}"
    else
        setsid --wait --ctty whiptail "$@" <"${TTY:-/dev/tty}"
    fi
}
tui_menu() { tui_run --title "HTTP Boot - $1" --menu "$2" 20 76 11 "${@:3}" 3>&1 >"${TTY:-/dev/tty}" 2>&3; }
tui_input() { tui_run --title "HTTP Boot - $1" --inputbox "$2" 10 76 "${3:-}" 3>&1 >"${TTY:-/dev/tty}" 2>&3; }
tui_password() { tui_run --title "HTTP Boot - $1" --passwordbox "$2" 10 76 3>&1 >"${TTY:-/dev/tty}" 2>&3; }
tui_message() {
    local flattened=${2//$'\n'/} scroll=()
    if (( ${#2} > 700 || ${#2}-${#flattened} > 12 )); then scroll=(--scrolltext); fi
    tui_run --title "HTTP Boot - $1" "${scroll[@]}" --msgbox "$2" 20 76 >"${TTY:-/dev/tty}" 2>&1
}

# Indeterminate stages do not invent percentages; download gauges carry byte totals.
tui_stage() { tui_run --title "HTTP Boot" --infobox "$1" 8 76 >"${TTY:-/dev/tty}" 2>&1; }
