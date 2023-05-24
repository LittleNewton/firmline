#!/bin/sh
# Find files to process in the tadiphone repo group
find raw-dataset/tadiphone -mindepth 1 -maxdepth 1 -type d \
    | while read -r i; do 
        find "$i"/vendor/firmware \
            "$i"/system/vendor/firmware \
            "$i"/system/etc/firmware \
            "$i"/vendor/etc/firmware \
            "$i"/vendor/lib/firmware \
            "$i"/system/system/etc/firmware \
            "$i"/usr/lib/firmware \
            -type f 2>/dev/null
        done

# Find files to process in the linux-firmware repository
find raw-dataset/linux-firmware-20230210/ -type f \
    | xargs file \
    | awk -F ": *" '$2 !~ / text/ {print $1}'

# Find files to process in IHEX download
find raw-dataset/ihex-github -mindepth 1 -type f -name '*.ihex'

# Find files to process in Roccat download
find raw-dataset/roccat -type f

# Find files to process in FirmXRay
find raw-dataset/firmxray/dataset/ -mindepth 2 -type f

# Find files to process in monolithic firmware
find raw-dataset/monolithic-firmware-collection-a2458fe3e0b3a92318591ce8a1707ffe62d29335/ -mindepth 2 -type f -not -ipath '*/utils/*' -not -iname 'README.md'
