#!/bin/env python3
from sys import argv, stdout
from pathlib import Path
from os.path import dirname
import logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)
print(f"Main logger: {log}")

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
    else:
        print("Not a tty, console log output disabled.")

# Setup logger file destination
# FIXME dynamically update logfile path depending on file being processed?
firstp = Path(argv[1]).absolute()
log_path = Path().cwd()
parent_dir = Path(dirname(firstp))
if parent_dir.exists():
    log_path = parent_dir
log_path = log_path / "safer_extract.log"
setup_logger(log_path)

import safer_extract.handlers
import safer_extract.file
import safer_extract.notification

def main() -> None:
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

    archive_files = (
        safer_extract.file.File(f, verify=force_verification) for f in argv[1:]
    )
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
            safer_extract.notification.play_sound("SUCCESS")
        except safer_extract.handlers.CanceledPasswordPrompt:
            continue
        except StopIteration:
            log.warning(f"Exhausted all handlers for \"{arfile}\". Skipping it.")
            safer_extract.notification.play_sound("FAILED")
            continue


if __name__ == "__main__":
    main()
