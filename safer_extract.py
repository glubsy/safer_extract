#!/bin/env python3
from sys import argv, stdout
from os import walk
from subprocess import DEVNULL, run, DEVNULL
from mimetypes import guess_extension, guess_type
from pathlib import Path
from typing import Optional, Tuple
from os.path import dirname
import logging

from safer_extract.handlers import *
from safer_extract.file import *
from safer_extract.notification import *

log = logging.getLogger()
log.setLevel(logging.DEBUG)


available_extractors = {
    UnrarHandler, UnzipHandler, SevenZHandler, ArkHandler, UnpHandler
}

def main() -> None:
    # Setup logger file destination
    # FIXME dynamically update logfile path depending on file being processed?
    firstp = Path(argv[1]).absolute()
    log_path = Path().cwd()
    parent_dir = Path(dirname(firstp))
    if parent_dir.exists():
        log_path = parent_dir
    log_path = log_path / "safer_extract.log"
    setup_logger(log_path)

    # Update list of available extractors on this system
    missing = set()
    for p in available_extractors:
        log.debug(f"Checking if {p} is available...")
        # Use the hardcoded commands to identify the program actually used
        proc = run(
            ['which', p.ecmd[0]], check=False,
            capture_output=False, stdout=DEVNULL, stderr=DEVNULL
        )
        if not proc.returncode == 0:
            log.debug(f"`which {p}` returned exit code {proc.returncode}")
            missing.add(p)
    for miss in missing:
        available_extractors.remove(miss)
    log.info(f"Available extractors: {available_extractors}")

    # TODO let user specify where to extract, 
    # by default should be the same directory as each archive
    # and make sure it is a "valid" path
    all_dest_dir = None
    # TODO let user decide to create directory named from archive base name
    create_subdir = True
    force_verification = True
    # DEBUG 
    # exclude = ["*.txt"]
    exclude = []

    archive_files = (File(f) for f in argv[1:])
    for arfile in archive_files:
        log.debug(f"Processing {arfile}")

        if not arfile.exists():
            log.warning(f"File {arfile} does not exists. Skipping.")
            continue

        try:
            arfile.extract_files(
                dest_dir=all_dest_dir, 
                create_subdir=create_subdir,
                exclude=exclude
            )
            play_sound("SUCCESS")
        except StopIteration:
            log.warning(f"Exhausted all handlers for {arfile}. Skipping it.")
            play_sound("FAILED")
            continue

        if arfile._used_unreliable or force_verification:
            # Compare extracted files to files listed by extractor
            if arfile.dest_dir is None \
            or arfile.dest_dir == arfile.path.absolute().parent:
                log.debug(f"{arfile} had no specified destination directory. "
                           "Skipping verification of extracted files.")
                continue

            log.debug("Checking number of entries in archive...")
            log.debug(f"arfile {arfile} has password: {arfile.password}")
            arentries = arfile.list_files(arfile.password)
            log.debug(f"Number of entries found {len(arentries)}: {arentries}")
            
            log.debug("Checking number of entries in output directory...")    
            dest_dir = arfile.dest_dir
            fsentries = enumerate_extracted_files(dest_dir)
            diff_count = len(arentries) - len(fsentries)
            if diff_count != 0:
                fs_missing_files = \
                    [f for f in arentries if f not in fsentries]
                log.warning(
                    f"{diff_count.__abs__()} files might be missing from disk "
                    "after extraction, or they had to be renamed slightly: "
                    f"{fs_missing_files}"
                )

def enumerate_extracted_files( 
    destdir: Path,
    ) -> list[ArchiveEntry]:
    """Return a list of paths to files relative to destdir."""
    if not destdir.is_dir():
        raise Exception(f"{destdir} is not a valid directory.")

    out_file_listing = []
    for _root, _, _files in walk(destdir):
        for f in _files:
            out_file_listing.append(ArchiveEntry(f, [_root]))
    log.debug(f"Files on disk: {out_file_listing}")
    return out_file_listing

    #     destdir = get_dest_dir(filepath)
    #     _ext = get_file_ext(filepath)
    #     # if not _ext:
    #     #     # We failed to detect mime type.
    #     #     # FIXME for now we skip, but we could fallback to ark/unp.
    #     #     continue
    #     # FIXME NEW: only create later if needed, for now only point
    #     makedirs(destdir, exist_ok=True)
    #     gen = cmd_generator(filepath, destdir, _ext)
    #     for cmd in gen:
    #         extractor = cmd[0]
    #         if extractor == "ark":
    #             used_unreliable_prog = True
    #         log.debug(f"Calling extractor cmd: {cmd}")
    #         try:
    #             run_subproc(cmd)
    #         # except CalledProcessError as e:
    #         except pexpect.ExceptionPexpect as e:
    #             play_sound("WARNING")
    #             log.info(f"{e.cmd} returned exit code: {e.returncode}")
    #             log.info(f"{e.cmd} stderr: {e.stderr}")
    #             if e.returncode == 9 and extractor == "unrar":
    #                 try:
    #                     handle_problematic_filenames(
    #                         e.stderr, filepath, destdir, _ext
    #                     )
    #                 except Exception as e:
    #                     log.exception(
    #                         f"Failed to extract problematic filenames: {e}")
    #                     play_sound("FAILED")
    #                     continue
    #                 play_sound("SUCCESS")
    #                 break
    #             continue
    #         except CanceledPasswordPrompt:
    #             log.warning(f"Canceled password for archive \"{filepath}\"")
    #             play_sound("FAILED")
    #             continue
    #         except Exception as e:
    #             log.warning(f"Unhandled subprocess error running {cmd}: {e}")
    #             play_sound("FAILED")
    #             continue
    #         # TODO make a "resolved" sfx
    #         play_sound("SUCCESS")
    #         # No need to use other candidate extractors
    #         break

    #     if used_unreliable_prog:
    #         diff = 0
    #         try:
    #             diff, miss = check_extracted_files(filepath, destdir, _ext)
    #         except Exception as e:
    #             log.warning("Failed to compare files exracted to files in archives!")
    #         if diff != 0:
    #             missing_fmt = '\n'.join('"' + f + '"' for f in miss)
    #             log.warning(
    #                 f"There is a count difference of {diff} with the number "
    #                 f"of files in the archive \"{filepath}\"! "
    #                 f"Missing files:\n{missing_fmt}"
    #             )
    # if extractor is None:
    #     log.warning("No extractor was used! Install one at least!")
    #     play_sound("SUCCESS")
    #     return

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
