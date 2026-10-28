"""Extract the kernel's ordered newc/compressed initramfs stream for inspection.

Ubuntu unmkinitramfs treats the compressed tail as a single compressor stream.
A valid zstd base followed by a gzip repair overlay therefore exits with cpio
'premature end of archive'. Decode each frame and each archive separately.
"""
import ctypes
import ctypes.util
import gzip
import lzma
import subprocess
import zlib
from pathlib import Path


def _archive(data,start):
    pos=start;names=[]
    while True:
        header=data[pos:pos+110]
        if len(header)!=110 or header[:6] not in (b'070701',b'070702'):raise ValueError('Invalid initramfs newc header')
        try:size=int(header[54:62],16);length=int(header[94:102],16)
        except ValueError as exc:raise ValueError('Invalid initramfs newc length') from exc
        if not 0<length<=4096:raise ValueError('Invalid initramfs path length')
        offset=pos+110;raw=data[offset:offset+length]
        if len(raw)!=length or raw[-1:]!=b'\0':raise ValueError('Truncated initramfs name')
        name=raw[:-1].decode('utf-8',errors='surrogateescape')
        payload=(offset+length+3)&~3;end=(payload+size+3)&~3
        if end>len(data):raise ValueError('Truncated initramfs payload')
        if name=='TRAILER!!!':return end,names
        path=Path(name)
        if path.is_absolute() or '..' in path.parts:raise ValueError('Unsafe initramfs path')
        names.append(path);pos=end


def _zstd(data):
    library=ctypes.util.find_library('zstd')
    if not library:raise ValueError('libzstd is required to inspect the initramfs')
    lib=ctypes.CDLL(library)
    lib.ZSTD_findFrameCompressedSize.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    lib.ZSTD_findFrameCompressedSize.restype=ctypes.c_size_t
    lib.ZSTD_isError.argtypes=[ctypes.c_size_t];lib.ZSTD_isError.restype=ctypes.c_uint
    buffer=ctypes.create_string_buffer(data)
    size=lib.ZSTD_findFrameCompressedSize(buffer,len(data))
    if lib.ZSTD_isError(size) or not 0<size<=len(data):raise ValueError('Invalid zstd initramfs frame')
    result=subprocess.run(['zstd','-q','-d','-c'],input=data[:size],capture_output=True,check=True)
    return result.stdout,size


def extract(image,destination):
    destination=Path(destination)
    if destination.exists():raise ValueError('Initramfs inspection destination must be new')
    destination.mkdir(parents=True,mode=0o700)
    root=destination.resolve();archives=0
    def unpack(data):
        nonlocal archives
        pos=0
        while pos<len(data):
            while pos<len(data) and data[pos]==0:pos+=1
            if pos==len(data):break
            tail=data[pos:]
            if tail.startswith((b'070701',b'070702')):
                end,names=_archive(data,pos)
                for name in names:
                    if name==Path('.'):continue
                    # Existing parent symlinks must not escape the extraction root.
                    for parent in (root/name).parents:
                        if parent==root:break
                        if not parent.resolve().is_relative_to(root):raise ValueError('Initramfs symlink escapes inspection directory')
                result=subprocess.run(['cpio','-idu','--quiet','--no-absolute-filenames','--preserve-modification-time'],
                                      input=data[pos:end],cwd=root,capture_output=True)
                if result.returncode:raise ValueError('Initramfs cpio extraction failed: '+result.stderr.decode(errors='replace')[-800:])
                archives+=1;pos=end;continue
            if tail.startswith(b'\x1f\x8b'):
                decoder=zlib.decompressobj(31);raw=decoder.decompress(tail)+decoder.flush()
                if not decoder.eof:raise ValueError('Truncated gzip initramfs frame')
                consumed=len(tail)-len(decoder.unused_data)
            elif tail.startswith(b'\x28\xb5\x2f\xfd') or (len(tail)>=4 and 0x184D2A50<=int.from_bytes(tail[:4],'little')<=0x184D2A5F):
                raw,consumed=_zstd(tail)
            elif tail.startswith(b'\xfd7zXZ\0'):
                decoder=lzma.LZMADecompressor();raw=decoder.decompress(tail)
                if not decoder.eof:raise ValueError('Truncated xz initramfs frame')
                consumed=len(tail)-len(decoder.unused_data)
            else:raise ValueError('Unsupported or invalid initramfs compression')
            unpack(raw);pos+=consumed
    unpack(Path(image).read_bytes())
    if not archives:raise ValueError('Initramfs contains no cpio archives')
    return destination
