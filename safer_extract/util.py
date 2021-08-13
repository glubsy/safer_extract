from typing import Optional
from pathlib import Path 
from logging import getLogger
import unicodedata

log = getLogger()

# Maximum number of bytes/chars in a filename
MAX_NAME_LEN = 255


def get_dest_dir(filepath: Path, 
                 dest_dir: Optional[Path], 
                 create_subdir: bool = True) -> Path:
    """Return the directory where the archive should be expanded into."""
    custom = False
    if dest_dir is None:
        # by default, use the directory holding this file
        dest_dir = filepath.absolute().parent
    else:
        custom = True
        dest_dir = dest_dir.absolute()

    if create_subdir:
        # /path/to/blahfile.meh.rar will extract to /path/to/custom/blahfile
        dest_dir = dest_dir / filepath.stem

        if dest_dir.is_file():
            dest_dir = dest_dir.with_suffix(".d")

    # Append number to stem to avoid the existing file
    num = 1
    while dest_dir.is_file():
        dest_dir = dest_dir.parent / (
            dest_dir.stem + "_##num##" + dest_dir.suffix
        ).replace("##num##", str(num)) 
        num += 1
        if num > 10:
            log.debug("Too many attempts at renaming destination directory.")
            break

    if dest_dir.is_file():
        log.warning(
            f"{dest_dir} already existed and is a file, not a directory! "
            f"Will not create subdirectory during extraction!")
        return filepath.absolute().parent
    return dest_dir



def truncate_utf8(bytestr: bytes, maxlen: int) -> str:
    # from https://stackoverflow.com/questions/1809531
    while (bytestr[maxlen - 1] & 0xc0 == 0xc0):
        maxlen -= 1
    return bytestr[:maxlen].decode('utf-8', errors='ignore')


def simple_truncate(unistr: str, maxsize: int) -> str:
    # from https://joernhees.de/blog/2010/12/14/how-to-restrict-the-length-of-a-unicode-string/
    if not unicodedata.is_normalized("NFC", unistr):
        unistr = unicodedata.normalize("NFC", unistr)
    return str(
        unistr.encode("utf-8")[:maxsize], 
        encoding="utf-8", errors='ignore'
    )


def sanitized(filename: str, isfile: bool = False) -> str:
    """Remove characters in name that are illegal in some file systems, and
    make sure it is not too long, including the extension."""
    extension = ""

    if isfile:
        # Preserve any .extension part 
        ext_idx = filename.rfind(".")
        if ext_idx > -1:
            extension = filename[ext_idx:]
            if not extension.isascii():
                # There is a risk that we failed to detect an actual extension.
                # Only preserve extension if it is valid ASCII, otherwise ignore it.
                extension = ""

    if extension:
        filename = filename[:-len(extension)]

    print(f"Sanitize isolated filename {filename}, extension {extension}")
    if not filename.isascii():
        name_bytes = filename.encode('utf-8')
        length_bytes = len(name_bytes)
        log.debug(
            f"Length of problematic filename is {length_bytes} bytes "
            f"{'<' if length_bytes < MAX_NAME_LEN else '>='} {MAX_NAME_LEN}")
        if length_bytes > MAX_NAME_LEN:
            # filename = truncate_utf8(name_bytes, MAX_NAME_LEN - len(extension))
            # Simpler and seems to work
            filename = simple_truncate(filename, MAX_NAME_LEN - len(extension))
    else:
        filename = "".join(
            c for c in filename if 31 < ord(c) and c not in r'<>:"/\|?*'
        )
        # Coerce filename length to 255 characters which is a common limit.
        filename = filename[:MAX_NAME_LEN - len(extension)]
    
    log.debug(f"Sanitized name: {filename + extension} "
              f"({len((filename + extension).encode('utf-8'))} bytes)")
    assert(
        len(
            filename.encode('utf-8') + extension.encode('utf-8')
        ) <= MAX_NAME_LEN
    )
    return filename + extension
