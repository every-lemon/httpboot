#!/bin/bash
# Sourced by early userspace; also exercised without mounting anything in tests.
check_image_memory() {
    local bytes=$1 total_kib=$2 available_kib=$3
    if [[ ! "$bytes" =~ ^[0-9]{1,12}$ || ! "$total_kib" =~ ^[0-9]{1,12}$ || ! "$available_kib" =~ ^[0-9]{1,12}$ ]]; then
        echo 'Cannot determine image size or available RAM; refusing an unbounded RAM download.'
        return 1
    fi
    local size=$((10#$bytes)) total=$((10#$total_kib * 1024)) available=$((10#$available_kib * 1024))
    if ((size <= 0 || size > total * 3 / 4 || size + 2147483648 > available)); then
        echo 'Not enough RAM: the compressed desktop must fit in RAM with at least 2 GiB left for startup.'
        return 1
    fi
}
