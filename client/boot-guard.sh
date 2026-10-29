#!/bin/bash
# Protect the boot transaction; restore ordinary terminal behavior at handoff.
BOOT_GUARD_STATE=${BOOT_GUARD_STATE:-/run/httpboot/boot-terminal}
BOOT_GUARD_ENV=${BOOT_GUARD_ENV:-/httpboot/boot-env}
export BOOT_GUARD_STATE BOOT_GUARD_ENV
boot_guard_signals() { trap '' INT QUIT TSTP; }
boot_guard_console() {
    local terminal=${TTY:-/dev/console} settings
    if [[ ! -f $BOOT_GUARD_STATE ]]; then
        settings=$(stty -g <"$terminal")
        mkdir -p "${BOOT_GUARD_STATE%/*}"
        (umask 077; printf '%s\n' "$settings" >"$BOOT_GUARD_STATE")
    fi
    stty intr undef quit undef susp undef <"$terminal"
}
boot_guard_restore_console() {
    local settings
    if [[ -f $BOOT_GUARD_STATE ]]; then
        read -r settings <"$BOOT_GUARD_STATE"
        stty "$settings" <"${TTY:-/dev/console}"
    fi
}
boot_guard_shell() {
    boot_guard_restore_console
    local session=()
    if ! ( : </dev/tty ) 2>/dev/null; then session=(setsid --wait --ctty); fi
    # A new Bash cannot reset a signal ignored on entry. env resets it first.
    "$BOOT_GUARD_ENV" --default-signal=INT,QUIT,TSTP "${session[@]}" \
        /bin/bash --noprofile --norc <"${TTY:-/dev/console}" >"${TTY:-/dev/console}" 2>&1 || true
    boot_guard_console
}
