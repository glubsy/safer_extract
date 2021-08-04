#!/bin/env python3
from sys import argv, stdout
from os import makedirs, sep, walk
from subprocess import DEVNULL, run, CalledProcessError, STDOUT, PIPE, DEVNULL
from mimetypes import guess_extension, guess_type
from pathlib import Path
from typing import Optional, Union, Tuple
from os.path import expanduser, dirname
import unicodedata
import logging

log = logging.getLogger()
log.setLevel(logging.DEBUG)

FAIL_SOUND = expanduser(
    "~/Music/sfx/242503__gabrielaraujo__failure-wrong-action.wav"
)
WARNING_SOUND = expanduser(
    "~/Music/sfx/350860__cabled-mess__blip-c-07.wav"
)
SUCCESS_SOUND = expanduser(
    "~/Music/sfx/256113_3263906-lq.ogg"
)
# Maximum number of bytes/chars in a filename
MAX_NAME_LEN = 255

# TODO ask for password (remove -p-) with zenity
# TODO retry extraction of file too long with
# unrar -inul p archive.rar overly-long-file-name > shorter-name

# [0] regular extract
# [1] list content
# [2] extract to stdout
extractors = {
    "unrar": [
        [
            "unrar", "x",
            #"-or",  # rename files if name already taken
            "-o-",  # DEBUG don't overwrite
            "-kb", "-c-", "-p-", "-ierr",
            "-x'*.txt'", "--",
            "##TARGET##", "##DESTDIR##"
        ],
        [
            "unrar", "lb", "##TARGET##"
        ],
        [
            "unrar", "-inul", "p", "-o+", "##TARGET##", "##PROBFILE##"
        ]
    ],
    "7z": [
        "7z", "x", "##TARGET##",
        # "-w", "##DESTDIR##", # change cwd
        "-o*", # automatic create output directory
        # "-o##DESTDIR##", # manual output directory
        "-x!*.txt",  # exclude txt files
    ],
    "unzip": [
        "unzip", "-d", "##DESTDIR##", "##TARGET##"
    ],
    "unp": [
        "unp", "##TARGET##", "-u", "##DESTDIR##"
    ],
    "ark": [
        "ark", "--batch", "-o", "##DESTDIR##", "##TARGET##"
    ],
}

# The order matter for ranking
ext_to_extractor = {
    ".rar": ["unrar", "7z", "ark"],
    # ".rar": ["7z"],
    ".zip": ["7z", "unzip", "ark"],
    "*": ["unp", "ark"]
}


def cmd_generator(
    filepath: Path,
    destdir: Path,
    ext: Optional[str],
    subcmd: int = 0
) -> list:
    if not ext:  # fallback
        ext = '*'
    progs = ext_to_extractor[ext]
    for p in progs:
        cmd = []
        cmd_list = extractors.get(p, [])
        if not cmd_list:
            log.debug(f"Extractor program {p} is disabled because not found.")
            continue
        if isinstance(cmd_list[0], list):  # nested lists
            if subcmd > len(cmd_list) - 1:
                # We don't have such subcommand, pass it to the next guy
                continue
            cmd.extend(cmd_list[subcmd])
        elif subcmd > 0:
            # no subcommand available for only extractors
            continue
        else:  # it's a str
            cmd.extend(cmd_list)
        log.debug(f"Template command: {cmd}")

        for item in cmd:
            if "##DESTDIR##" in item:
                # item = str(destdir)
                # item = item.replace('##DESTDIR##', str(destdir))
                cmd[cmd.index(item)] = item.replace('##DESTDIR##', str(destdir))
            elif "##TARGET##" in item:
                # item = str(filepath)
                # item = item.replace('##TARGET##', str(filepath))
                cmd[cmd.index(item)] = item.replace('##TARGET##', str(filepath))
        yield cmd


def get_file_ext(filepath: Path) -> Optional[str]:
    _ext = None
    mimetype = guess_type(filepath)
    if mimetype[0]:
        _ext = guess_extension(mimetype[0])
    return _ext


def run_subproc(cmd: list) -> None:
    proc = run(
        cmd,
        check=True,
        capture_output=True,
        # stdin=PIPE, stdout=PIPE, stderr=STDOUT,
        text=True
    )
    log.debug(f"stderr: {proc.stderr}")
    log.debug(f"stdout: {proc.stdout}")


def get_dest_dir(filepath: Path) -> Path:
    """Return the directory where the archive should be expanded into."""
    candidate = Path(dirname(filepath.absolute())) / filepath.name.split('.')[0]
    if candidate.exists() and candidate.is_file():
        log.warning(
            f"{candidate} already existed and is a file, not a directory! "
            f"Skipping creation, will extract in \"{Path.cwd()}\" instead.")
        return Path.cwd()
    log.debug(f"Candidate destination dir: {candidate}")
    return candidate


def play_sound(snd_path: Union[Path, str] ) -> None:
    if isinstance(snd_path, str):
        snd_path = Path(snd_path)
        if not snd_path.exists():
            return
    log.debug(f"Playing sound {snd_path}")
    run(['paplay', str(snd_path)])
    # if "242503__gabrielaraujo__failure" in str(snd_path):
    #     raise Exception("BOOOOH")


def log_to_file(logpath: Path, message: str) -> None:
    with open(logpath, 'a') as f:
        f.write(message)


def parse_text_output(text_buffer: str) -> set:
    # This might only work with unrar's output.
    cached_line = ""
    problematic = set()
    for line in text_buffer.split("\n"):
        if "Cannot create" in line:
            filename = line.split(sep)[-1]
            log.warning(f"Failed to create filename {filename}")
            problematic.add(filename)
        if "File name too long" in line:
            log.debug(f"Previous line has file name too long: {cached_line}")
            if "Cannot create" in cached_line:
                filename = cached_line.split(sep)[-1]
                problematic.add(filename)
        cached_line = line
    return problematic


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


def sanitized(filename: str) -> str:
    """Remove characters in name that are illegal in some file systems, and
    make sure it is not too long, including the extension."""
    extension = ""
    ext_idx = filename.rfind(".")
    if ext_idx > -1:
        extension = filename[ext_idx:]
        if not extension.isascii():
            # There is a risk that we failed to detect an actual extension.
            # Only preserve extension if it is valid ASCII, otherwise ignore it.
            extension = ""

    if extension:
        filename = filename[:-len(extension)]

    print(f"filename {filename}, extension {extension}")
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


def extract_file_to_stdout(cmd: list, dest_fname: Path) -> bool:
    with open(dest_fname, "wb") as outfile:
        proc = run(
            cmd,
            check=True,
            text=True,
            stdout=outfile,
        )
        log.debug(f"TO STDOUT: {cmd} stderr: {proc.stderr}")
    if dest_fname.exists():
        return True
    return False

def main() -> None:
    firstp = Path(argv[1]).absolute()
    log_path = Path().cwd()
    parent_dir = Path(dirname(firstp))
    if parent_dir.exists():
        log_path = parent_dir
    log_path = log_path / "extraction.log"
    setup_logger(log_path)

    # Update list of available extractors on this system
    progs = (p for p in extractors.keys())
    missing = set()
    for p in progs:
        log.debug(f"Checking if {p} is available...")
        proc = run(
            ['which', p], check=False,
            capture_output=False, stdout=DEVNULL, stderr=DEVNULL
        )
        if not proc.returncode == 0:
            log.debug(f"`which {p}` returned exit code {proc.returncode}")
            missing.add(p)
    for miss in missing:
        extractors.pop(miss)
    log.info(f"Available extractors: {extractors.keys()}")


    extractor = None
    # Process archives passed as arguments
    archive_files = (Path(f) for f in argv[1:])
    for filepath in archive_files:
        log.debug(f"Processing {filepath}")
        extractor = None
        used_unreliable_prog = False

        if not filepath.exists():
            log.warning(f"File {filepath} does not exists. Skipping.")
            continue

        destdir = get_dest_dir(filepath)
        _ext = get_file_ext(filepath)
        # if not _ext:
        #     # We failed to detect mime type.
        #     # FIXME for now we skip, but we could fallback to ark/unp.
        #     continue
        makedirs(destdir, exist_ok=True)
        gen = cmd_generator(filepath, destdir, _ext)
        for cmd in gen:
            extractor = cmd[0]
            if extractor == "ark":
                used_unreliable_prog = True
            log.debug(f"Calling extractor cmd: {cmd}")
            try:
                run_subproc(cmd)
                # pass
            except CalledProcessError as e:
                play_sound(WARNING_SOUND)
                log.info(f"{e.cmd} returned exit code: {e.returncode}")
                log.info(f"{e.cmd} stderr: {e.stderr}")
                if e.returncode == 9 and extractor == "unrar":
                    try:
                        handle_problematic_filenames(
                            e.stderr, filepath, destdir, _ext
                        )
                    except Exception as e:
                        log.exception(
                            f"Failed to extract problematic filenames: {e}")
                        play_sound(FAIL_SOUND)
                        continue
                    play_sound(SUCCESS_SOUND)
                    break
                continue
            except Exception as e:
                log.warning(f"Unhandled subprocess error running {cmd}: {e}")
                play_sound(FAIL_SOUND)
                continue
            # TODO make a resolved or "phew" sfx
            play_sound(SUCCESS_SOUND)
            # No need to use other candidate extractors
            break

        if used_unreliable_prog:
            diff, miss = check_extracted_files(filepath, destdir, _ext)
            if diff != 0:
                missing_fmt = '\n'.join('"' + f + '"' for f in miss)
                log.warning(
                    f"There is a count difference of {diff} with the number "
                    f"of files in the archive \"{filepath}\"! "
                    f"Missing files:\n{missing_fmt}"
                )
    if extractor is None:
        log.warning("No extractor was used! Install one at least!")
        play_sound(FAIL_SOUND)
        return


def handle_problematic_filenames(unrar_stderr, filepath, destdir, ext):
    problematic_filenames = parse_text_output(unrar_stderr)
    log.warning(f"Will retry extraction of {problematic_filenames}...")
    tcmds = []
    gen = cmd_generator(filepath, destdir, ext, subcmd=2)
    for cmd in gen:
        log.debug(f"Got {cmd[0]} template to inflate to stdout... {cmd}")
        tcmds.append(cmd)
    
    for fname in problematic_filenames:
        dest_fname = destdir / Path(sanitized(fname))
        for cmd in tcmds:
            cmd_copy = cmd[:]
            if cmd_copy[0] == "unrar":
                for item in cmd_copy:
                    if item == "##PROBFILE##":
                        cmd_copy[cmd_copy.index(item)] = item.replace(
                            '##PROBFILE##', fname
                        )
            log.debug(f"Using inflate stdout cmd: {cmd_copy} -> {dest_fname}")
            try:
                if extract_file_to_stdout(cmd_copy, dest_fname):
                    break
            except Exception as e:
                log.warning(
                    f"Error inflating to stdout with {cmd_copy}: {e}.\n"
                    "Trying next extractor..."
                )
                continue
            raise Exception(
                f"Failed to extract problematic file \"{fname}\" from {filepath}")


def check_extracted_files(
    filepath: Path, destdir: Path, ext: Optional[str]) -> Tuple[int, list]:
    """Compare extracted files to files listed by extractor.
    Return the count difference and the missing files."""
    ar_file_listing = list_files_from_archive(filepath, destdir, ext)

    out_file_listing = []
    for _root, _dirs, _files in walk(destdir):
        for f in _files:
            # FIXME might need to prepend the parent directory in case it was
            # perserved during extraction
            out_file_listing.append(f)
    log.debug(f"Files on disk: {out_file_listing}")

    diff_count = len(ar_file_listing) - len(out_file_listing)
    missing_files = []
    if diff_count != 0:
        missing_files = \
            [f for f in ar_file_listing if f not in out_file_listing]

    return diff_count, missing_files


def list_files_from_archive(
    filepath: Path, destdir: Path, ext: Optional[str]) -> list:
    """Call the listing subcommand on available extractors and return the
    file list."""
    gen = cmd_generator(filepath, destdir, ext, subcmd=1)
    ar_file_listing = []
    used_prog = None
    for p in gen:
        log.debug(f"Calling extractor subcommand: {p}")
        try:
            proc = run(
                p,
                check=True,
                capture_output=True,
                # stdin=PIPE, stdout=PIPE, stderr=STDOUT,
                text=True
            )
        except Exception as e:
            log.debug(f"Unhandled error running extractor subcommand {p}: {e}")
            continue
        used_prog = p[0]
        # FIXME depends on the program used
        if used_prog == "unrar":
            for line in proc.stdout.split("\n"):
                stripped = line.strip()
                if stripped:
                    ar_file_listing.append(stripped)
        break

    if len(ar_file_listing) == 0:
        log.warning(
            f"{used_prog} returned a file listing of archive \"{filepath}\" "
            "which is empty!")
    return ar_file_listing


def setup_logger(output_filepath: Path) -> None:
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )

    logfile = logging.FileHandler(
        filename=output_filepath, delay=True
    )
    logfile.setLevel(logging.WARNING)
    logfile.setFormatter(formatter)
    log.addHandler(logfile)

    # Console stdout handler, not added if not a tty
    if stdout.isatty():
        conhandler = logging.StreamHandler()
        conhandler.setLevel(logging.DEBUG)
        conhandler.setFormatter(formatter)
        log.addHandler(conhandler)


if __name__ == "__main__":
    main()
