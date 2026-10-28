#!/bin/bash
# Early wired networking; Wi-Fi is the fallback. Credentials remain in RAM.
set -Eeuo pipefail
source /httpboot/boot.conf
source /httpboot/tui.sh
mkdir -p /run/httpboot
tui_stage 'Checking Ethernet adapters…'
for attempt in {1..8}; do
    found=0
    for device in /sys/class/net/*; do
        name=${device##*/}
        [[ $name != lo && ! -d $device/wireless && -e $device/device ]] || continue
        found=1
        ip link set "$name" up || continue
        # USB adapters and emulated e1000 need time to negotiate carrier after
        # being brought up. A single immediate read falsely reports no Ethernet.
        for link_attempt in {1..5}; do
            [[ $(cat "$device/carrier" 2>/dev/null || true) == 1 ]] && break
            sleep 1
        done
        [[ $(cat "$device/carrier" 2>/dev/null || true) == 1 ]] || continue
        tui_stage "Obtaining an Ethernet address on $name…"
        if dhclient -4 -1 -v -cf /httpboot/dhclient.conf -sf /httpboot/dhclient-script \
            -pf /run/httpboot/dhcp.pid -lf /run/httpboot/dhcp.leases "$name" >/run/httpboot/dhcp.log 2>&1; then
            if [[ ${HTTPBOOT_PROTOCOL:-1} == 2 ]];then
                printf "ethernet\n" >/run/httpboot/network-type
                printf "%s\n" "$name" >/run/httpboot/interface
                exit 0
            fi
            echo "Ethernet obtained an address. Checking Ubuntu image: $IMAGE_URL"
            if curl --fail --show-error --head --connect-timeout 5 --max-time 10 "$IMAGE_URL" \
                >/run/httpboot/http-probe.headers 2>/run/httpboot/http-probe.log; then
                printf 'ethernet\n' >/run/httpboot/network-type
                printf '%s\n' "$name" >/run/httpboot/interface
                exit 0
            fi
            echo 'Ethernet DHCP succeeded, but the Ubuntu image could not be fetched.'
            cat /run/httpboot/http-probe.log
            sed -n '/^HTTP\//p' /run/httpboot/http-probe.headers
            echo 'Check that the Server is reachable and the release named above still exists. Refresh an old SD card after recreating server storage.'
        fi
        if [[ -f /run/httpboot/dhcp.pid ]]; then
            kill "$(cat /run/httpboot/dhcp.pid)" 2>/dev/null || true
            rm -f /run/httpboot/dhcp.pid
        fi
        ip -4 addr flush dev "$name" || true
        ip route del default dev "$name" 2>/dev/null || true
    done
    (( found )) && break
    sleep 1
    udevadm settle --timeout=2 || true
done
while true; do
    choice=$(tui_menu 'Network connection' 'Choose how to continue' w 'Connect using Wi-Fi' e 'Rescan Ethernet' r 'Offline recovery' d 'Hardware diagnostics / save report' x 'Export diagnostic report to USB' s 'Recovery shell') || continue
    case "$choice" in
        e) exec /bin/bash /httpboot/network.sh;;
        r) exit 2;;
        d) if [[ ${HTTPBOOT_PROTOCOL:-1} == 2 ]];then python3 /httpboot/v2/boot_reports.py >/run/httpboot/network-report.txt;tui_message 'Hardware diagnostics' "$(cat /run/httpboot/network-report.txt)";else tui_message 'Diagnostics' 'Use the Wi-Fi diagnostics menu.';fi;;
        x) if [[ ${HTTPBOOT_PROTOCOL:-1} == 2 ]];then target=$(tui_input 'Export diagnostics' 'Mounted USB path:') || continue;if ! python3 /httpboot/v2/boot_reports.py --export "$target";then tui_message "Export failed" "Choose an explicitly mounted writable USB filesystem.";fi;fi;;
        s) /bin/bash;;
        w|'')
            if /bin/bash /httpboot/wifi.sh; then
                printf 'wifi\n' >/run/httpboot/network-type
                exit 0
            fi;;
    esac
done
