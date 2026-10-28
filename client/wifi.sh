#!/bin/bash
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
source /httpboot/tui.sh
started=false
wifi_ready=false
wifi_stage=adapter-discovery
wifi_failure() {
    local status=$1
    trap - ERR
    if [[ -f /httpboot/v2/boot_reports.py ]];then
        python3 - "$wifi_stage" <<'REPORT' || true
import sys
from pathlib import Path
sys.path.insert(0,'/httpboot/v2')
from boot_reports import collect,store
report=collect('wifi-'+sys.argv[1],'setup-failed')
for folder in (Path('/run/httpboot-v2/reports'),Path('/run/httpboot-v2/media/httpboot-v2/identity/reports')):
    if 'media' in folder.parts and not Path('/run/httpboot-v2/media').is_mount():continue
    try:store(folder,report)
    except OSError:pass
REPORT
    fi
    # Never echo BASH_COMMAND: it can contain a password or an SSID.
    tui_message 'Wi-Fi setup stopped' "Stage: $wifi_stage (status $status).
Choose Diagnostics from the network menu for hardware details.
Press Enter to return; no automatic connection retry will run." || true
    exit "$status"
}
trap 'wifi_failure "$?"' ERR
wifi_dialog_failed() {
    # Escape/Cancel is a deliberate return; terminal failures are not.
    [[ $1 == 1 ]] && exit 1
    wifi_failure "$1"
}
WPA_CLIENT_DIR=/run/httpboot/wpa-client
mkdir -p "$WPA_CLIENT_DIR"
chmod 700 "$WPA_CLIENT_DIR"
show_diagnostics() {
    echo '=== Wi-Fi diagnostics (credentials are not displayed) ==='
    rfkill list || true
    ip -4 addr show || true
    ip link show || true
    ip route show || true
    if [[ -n "${iface:-}" ]]; then
        echo "Interface: $iface"
        wpa_cli -s "$WPA_CLIENT_DIR" -p /run/wpa_supplicant -i "$iface" status 2>/dev/null |
            sed -n '/^wpa_state=/p;/^ssid=/p;/^bssid=/p;/^key_mgmt=/p;/^freq=/p;/^ip_address=/p' || true
    fi
    if [[ -f /run/httpboot/wpa.log ]]; then
        echo 'Recent supplicant events:'
        tail -n 35 /run/httpboot/wpa.log |
            sed -E 's/(psk|password|passphrase)=[^ ]+/\1=[redacted]/g' || true
    fi
    for log in /run/httpboot/wpa-control.log /run/httpboot/dhcp.log; do
        if [[ -s "$log" ]];then echo "Network stage log: ${log##*/}";tail -n 20 "$log";fi
    done
    echo 'Recent wireless kernel messages:'
    if command -v dmesg >/dev/null; then
        dmesg | grep -iE 'iwl|rtw|ath|firmware|cfg80211|wlan|wlp|crypto|ccm|cmac|gcm' | tail -n 25 || true
    else
        echo 'Kernel log reader is unavailable in this older image.'
    fi
    if [[ -n "${iface:-}" && -f /sys/class/net/$iface/device/uevent ]]; then
        cat "/sys/class/net/$iface/device/uevent"
    fi
    grep -E '^name[[:space:]]*:.*(aes|ccm|cmac|gcm)' /proc/crypto || true
    echo '=== End diagnostics ==='
}
stop_wifi() {
    [[ "$started" == true ]] || return 0
    wpa_cli -s "$WPA_CLIENT_DIR" -p /run/wpa_supplicant -i "$iface" terminate >/dev/null 2>&1 || true
    if [[ -f /run/httpboot/wpa.pid ]]; then
        local pid
        read -r pid </run/httpboot/wpa.pid || true
        if [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]]; then
            kill "$pid" 2>/dev/null || true
            for ((n=0; n<20; n++)); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
        fi
    fi
}
trap 'if [[ "$wifi_ready" != true ]]; then stop_wifi; fi' EXIT
interfaces=()
for ((attempt=0; attempt<20; attempt++)); do
    interfaces=()
    for device in /sys/class/net/*; do
        [[ -d "$device/wireless" || -d "$device/phy80211" ]] && interfaces+=("${device##*/}")
    done
    ((${#interfaces[@]})) && break
    sleep 1
done
if ((${#interfaces[@]} == 0)); then
    echo 'No Wi-Fi device detected. Check selected modules and firmware.'
    if [[ -f /httpboot/v2/boot_reports.py ]];then python3 /httpboot/v2/boot_reports.py --stage wifi-device-discovery >/run/httpboot/network-report.txt || true;fi
    show_diagnostics
    if action=$(tui_menu 'No wireless adapter' 'No Wi-Fi interface has appeared yet.' retry 'Rescan adapters' diagnostics 'Show diagnostics' shell 'Recovery shell'); then
        case $action in diagnostics) tui_message 'Wi-Fi diagnostics' "$(show_diagnostics)";; shell) /bin/bash;; esac
    fi
    exit 1
fi
if ((${#interfaces[@]} == 1)); then
    iface=${interfaces[0]}
else
    rows=();for item in "${interfaces[@]}";do rows+=("$item" 'Wireless adapter');done
    iface=$(tui_menu 'Wireless adapter' 'Select an adapter' "${rows[@]}") || wifi_dialog_failed "$?"
fi
wifi_stage=adapter-enable
rfkill unblock wifi >/dev/null 2>&1 || true
ip link set "$iface" up
iw dev "$iface" set power_save off >/dev/null 2>&1 || true
rows=()
[[ ! -f /httpboot/wifi.age ]] || rows+=(1 'Unlock saved Wi-Fi preset')
rows+=(2 'Connect to another Wi-Fi network' 3 'Show Wi-Fi diagnostics' 4 'Recovery shell')
wifi_stage=network-action
choice=$(tui_menu 'Wi-Fi' 'Choose a network action. Passwords remain private.' "${rows[@]}") || wifi_dialog_failed "$?"
case "$choice" in
    3) tui_message 'Wi-Fi diagnostics' "$(show_diagnostics)"; exit 1 ;;
    4) /bin/bash; exit 1 ;;
    1)
        [[ -f /httpboot/wifi.age ]] || { echo 'No preset is included. Choose another network.'; exit 1; }
        passphrase=$(tui_password 'Saved Wi-Fi' 'Unlock the encrypted Wi-Fi preset') || wifi_dialog_failed "$?"
        if ! printf '%s\n' "$passphrase" | /httpboot/age-unlock /httpboot/wifi.age >/run/httpboot/wifi.conf; then
            rm -f /run/httpboot/wifi.conf
            unset passphrase
            tui_message 'Preset unlock failed' 'The preset could not be unlocked. Retry or choose another network.'
            exit 1
        fi
        unset passphrase
        ;;
    2)
        wifi_stage=network-scan
        tui_stage 'Scanning wireless networks…' || true
        rows=()
        # Keep scan failures out of process substitutions: the inherited ERR
        # trap must never open competing dialogs from a pipeline child.
        scan_output='';scan_ok=false
        for scan_attempt in 1 2 3; do
            if scan_output=$(iw dev "$iface" scan 2>/run/httpboot/wifi-scan.log); then scan_ok=true;break;fi
            (( scan_attempt == 3 )) || sleep 1
        done
        if [[ $scan_ok == true ]];then
            while IFS= read -r item;do [[ -z $item ]] || rows+=("$item" 'Available wireless network');done < <(printf '%s\n' "$scan_output" | sed -n 's/^[[:space:]]*SSID: //p' | sort -u)
        fi
        unset scan_output
        rows+=(manual 'Enter a hidden or unlisted SSID')
        wifi_stage=network-selection
        scan_prompt='Select a network'
        [[ $scan_ok == true ]] || scan_prompt='Scan failed after three attempts. Enter an unlisted network manually, or press Escape to return.'
        ssid=$(tui_menu 'Network' "$scan_prompt" "${rows[@]}") || wifi_dialog_failed "$?"
        if [[ $ssid == manual ]];then ssid=$(tui_input 'Network name' 'SSID') || wifi_dialog_failed "$?";fi
        [[ -n "$ssid" && ${#ssid} -le 32 && "$ssid" != *'"'* && "$ssid" != *'\'* ]] || {
            echo 'Use an SSID of 1–32 characters without quotes/backslashes in this initial TUI.'; exit 1;
        }
        wifi_stage=password-entry
        password=$(tui_password 'Wi-Fi password' "Password for $ssid") || wifi_dialog_failed "$?"
        if (( ${#password}<8 || ${#password}>63 ));then
            unset password
            tui_message 'Wi-Fi password' 'Enter a WPA password of 8–63 characters. No connection was attempted.'
            exit 1
        fi
        wifi_stage=configuration
        {
            printf 'ctrl_interface=/run/wpa_supplicant\n'
            printf '%s\n' "$password" | wpa_passphrase "$ssid" |
                sed '/^[[:space:]]*#psk=/d'
        } >/run/httpboot/wifi.conf
        unset password
        ;;
    *) exit 1 ;;
esac
chmod 600 /run/httpboot/wifi.conf
wifi_stage=kernel-encryption
for module in ccm cmac gcm; do
    if ! modprobe "$module"; then
        tui_message "Wi-Fi encryption unavailable" "Kernel support is missing: $module. Update this USB using the Server menu."
        exit 1
    fi
done
mkdir -p /run/wpa_supplicant
# Both preset and temporary config files include ctrl_interface. The -C flag
# cannot replace this setting when wpa_supplicant is given a config with -c.
# Keep encrypted presets intact, including SAE/PMF settings. Never force WPA2
# on a WPA3 network. The manual path advertises transition-mode compatibility.
if grep -q '^[[:space:]]*psk=' /run/httpboot/wifi.conf && ! grep -q 'key_mgmt=' /run/httpboot/wifi.conf;then
    sed -i '/^[[:space:]]*psk=/a\    key_mgmt=WPA-PSK WPA-PSK-SHA256\n    ieee80211w=1' /run/httpboot/wifi.conf
fi
wifi_stage=association
wpa_supplicant -B -i "$iface" -c /run/httpboot/wifi.conf -P /run/httpboot/wpa.pid -f /run/httpboot/wpa.log
started=true
connected=false
last_state=''
for ((attempt=0; attempt<60; attempt++)); do
    status=$(wpa_cli -s "$WPA_CLIENT_DIR" -p /run/wpa_supplicant -i "$iface" status 2>/run/httpboot/wpa-control.log) || status=''
    state=$(printf '%s\n' "$status" | sed -n 's/^wpa_state=//p')
    if [[ "$state" != "$last_state" ]]; then
        tui_stage "Connecting Wi-Fi: ${state:-waiting for control socket}" || true
        last_state=$state
    fi
    if [[ "$state" == COMPLETED ]]; then connected=true; break; fi
    sleep 1
done
if [[ "$connected" != true ]]; then
    if [[ ! -S /run/wpa_supplicant/$iface ]]; then
        echo 'Wi-Fi control socket was not created. Check wpa_supplicant startup/driver errors above.'
    else
        echo 'Association failed. Check the password, network security, and signal.'
        if grep -qE 'key addition failed|Failed to set PTK' /run/httpboot/wpa.log; then
            echo 'The kernel rejected key installation. WRONG_KEY alone does not establish that the password is incorrect.'
        fi
    fi
    show_diagnostics
    tui_message 'Wi-Fi connection failed' "$(show_diagnostics)"
    exit 1
fi
printf '%s\n' "$iface" >/run/httpboot/interface
wifi_stage=network-address
tui_stage 'Obtaining a Wi-Fi network address…' || true
if ! dhclient -4 -1 -v -cf /httpboot/dhclient.conf -sf /httpboot/dhclient-script \
    -pf /run/httpboot/dhcp.pid -lf /run/httpboot/dhcp.leases "$iface" >/run/httpboot/dhcp.log 2>&1; then
    echo 'DHCP failed.'
    show_diagnostics
    tui_message 'DHCP failed' "$(show_diagnostics)"
    exit 1
fi
wifi_ready=true
