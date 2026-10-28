"""Select Ubuntu modules actually available for the chosen kernel, with firmware parity."""
from pathlib import Path
from common import run
OPTIONAL=('xhci_pci','xhci_hcd','ehci_pci','ehci_hcd','ohci_pci','ohci_hcd','af_alg','algif_aead','algif_skcipher','algif_hash','ecb','cbc','ctr','cbcmac','aes_generic','aesni_intel','aes_x86_64','ghash_generic','sha256_generic','sha256_ssse3','cryptd','crypto_simd','hmac','drbg','cfg80211','mac80211','rtw88_8822be','rtw88_8822ce','rtw88_8723de','rtw88_8821cu','rtw88_8822bu','rtw89_8851be','rtw89_8852be','rtw89_8852ae','rtw89_8852ce','ath9k','ath9k_htc','ath10k_pci','ath12k_pci','mt7921e','mt7921u','mt7925e','mt7925u','mt76x2u','brcmfmac','brcmsmac','rtsx_pci','rtsx_pci_sdmmc','rtsx_usb','rtsx_usb_sdmmc','sdhci_pci','sdhci_acpi','mmc_block','usbhid','hid_generic','i8042','atkbd')
def extend_modules(root,kernel,modules):
    candidates={p.name.split('.ko')[0].replace('-','_') for base in ('lib/modules','usr/lib/modules') for p in (root/base/kernel).rglob('*.ko*')}
    tree=root/'lib/modules'/kernel
    if not tree.exists():tree=root/'usr/lib/modules'/kernel
    if (tree/'modules.builtin').exists():candidates.update(Path(x).name.split('.ko')[0].replace('-','_') for x in (tree/'modules.builtin').read_text().splitlines())
    selected=list(modules)
    for name in OPTIONAL:
        if name not in candidates:continue
        # Optional support is advertised only when all installed-module firmware
        # requirements have at least one available provider in this Ubuntu image.
        info=run(['chroot',root,'modinfo','-k',kernel,'-F','firmware',name],capture_output=True,text=True).stdout.splitlines()
        if info and not any(list((root/'lib/firmware').glob(pattern+suffix)) for pattern in info for suffix in ('','.zst','.xz')):continue
        if name not in selected:selected.append(name)
    return selected
