from os import makedirs, sep
from sys import stdout
from pathlib import Path
from enum import Enum
from typing import Any, Optional, Union
from subprocess import run, CalledProcessError, Popen, PIPE
import logging
import io
import re

import pexpect
from pexpect import fdpexpect

from safer_extract.notification import play_sound
from .util import get_dest_dir, sanitized


log = logging.getLogger()


def run_zenity() -> Optional[str]:
    # TODO display archive name in dialog
    cmd = [
        "zenity", "--password", "--title",
        "Safe Extract password prompt"
    ]
    data = None
    try:
        proc = run(cmd, check=True, capture_output=True, text=True)
        data = proc.stdout
    except CalledProcessError as e:
        if e.returncode == 1: # clicked cancel
            data = None
        else:
            raise
    except Exception as e:
        print(f"zenity exc: {e}")

    print(f"zenity reutrned {data}")
    return data


class ArchiveEntry():
    """Describes a generic archive entry."""

    __slots__ = ["name", "path", "error", "password"]

    def __init__(
        self, 
        name: str, 
        path_parts: Optional[list] = None
    ) -> None:
        # log.debug(f"ArchiveEntry({name}, {path_parts})")
        self.name: str = name
        self.path: Optional[str] = "/".join(path_parts) \
                    if path_parts is not None and len(path_parts) > 0 \
                    else None
        self.error: Optional[str] = None
        self.password: Optional[str] = None

    def __hash__(self) -> int:
        if self.path is not None:
            return hash(self.path + "/" + self.name)
        return hash(self.name)
    
    def __repr__(self) -> str:
        if self.path is not None:
            return self.path + "/" + self.name
        return self.name
    
    def __eq__(self, other):
        return (isinstance(other, type(self))
                and hash(other) == hash(self))


def parse_unrar_text_output(text_buffer: io.StringIO, 
                            destdir: Path) -> set[ArchiveEntry]:
    """
    :param text_buffer: stderr output from unrar
    :param destdir: path to parent directory of archive
    """
    cached_line = ""
    num_err = 0
    problematic: set[ArchiveEntry] = set()
    destdirname = destdir.name

    def get_file_path(line: str) -> list:
        """Return list of ['maybe/inner/path', 'filename']."""
        # Assuming path separators are always "/", which they should be.
        # It's bad new if it's a "\", we will have the path inside the filename. 
        splits = line.split("/")
        # log.debug(f"splits for \"{line}\": {splits}")
        filename = splits[-1]
        # Isolate the path part, leave out the absolute FS path and the filename
        innerpath = splits[splits.index(destdirname)+1:-1]
        innerpath.extend([filename])
        return innerpath

    # Iterate over buffered output and gather reported problematic filenames
    # and their path inside the rar archive if any
    for line in text_buffer:
        line = line.strip("\r\n")  # thanks pexpect!
        if UnrarErrorCode.NOT_A_DIR.value in line:
            if "Cannot create" in cached_line:
                fpaths_parts = get_file_path(cached_line)
                log.debug(f"fpath_parts again {fpaths_parts}")
                entry = ArchiveEntry(fpaths_parts[-1], fpaths_parts[:-1])
                log.debug(f"Filename that failed to create (again): \"{entry}\"")
                if entry in problematic:
                    # Update error reason
                    entry.error = UnrarErrorCode.NOT_A_DIR.value
                else:
                    problematic.add(entry)

        if "Cannot create" in line:
            fpaths_parts = get_file_path(line)
            log.debug(f"fpath_parts {fpaths_parts}")
            entry = ArchiveEntry(fpaths_parts[-1], fpaths_parts[:-1])
            log.warning(f"Filename that failed to create: \"{entry}\"")
            problematic.add(entry)

        if UnrarErrorCode.TOO_LONG.value in line:
            log.debug(f"Failed to create filename because too long: \"{line}\"")
            log.debug(f"Previous line was: {cached_line}")
            # FIXME get the filepath from the previous line (this seems redudant)
            if "Cannot create" in cached_line:
                fpaths_parts = get_file_path(cached_line)
                log.debug(f"fpath_parts again {fpaths_parts}")
                entry = ArchiveEntry(fpaths_parts[-1], fpaths_parts[:-1])
                log.debug(f"Filename that failed to create (again): \"{entry}\"")
                if entry in problematic:
                    # Update error reason
                    entry.error = UnrarErrorCode.TOO_LONG.value
                else:
                    problematic.add(entry)
                                
        if "Total errors:" in line:
            if match := re.match(r".*Total errors: (\d*).*", line):
                num_err = int(match.group(1))
            log.debug(f"Unrar reported {num_err} errors.")
        
        cached_line = line

    if num_err != len(problematic):
        log.warning(
            f"Number of reported errors ({num_err}) does not match "
            f"the number of problematic files recorded ({len(problematic)})")
    
    return problematic


def replace_cmd(template: list, *replacements: tuple[str, Any]) -> list:
    """Return a copy of template with placeholders replaced by args specified
    in each *args tuple. If the value is the tuple is None, the placeholder is 
    simply removed."""
    cmd = template[:]
    to_remove = set()
    for item in cmd:
        for replace in replacements:
            if replace[0] in item:
                if replace[1] is None:
                    log.debug(f"{item} will be removed.")
                    to_remove.add(item)
                    continue
                idx = cmd.index(item)
                # elif isinstance(replace[1], Path) \
                # or isinstance(replace[1], ArchiveEntry):
                cmd[idx] = item.replace(replace[0], str(replace[1]))
    for item in to_remove:
        cmd.remove(item)
    log.debug(f"Replaced command {cmd}")
    return cmd


class Handler():
    """ABC defining the common interface for archive decompressors."""
    @classmethod
    def extract_files(
        cls,
        target: Path, 
        dest_dir: Union[Path, None] = None,
        create_subdir: bool = True,
        exclude: list[str] = None
    ) -> tuple[Path, Union[str, None]]:
        """Extract files from archive.
        :param target: archive file from which to extract
        :param dest_dir: destination directory where to extract files
        :param create_subdir: whether or not to create a subdirectory to extract
        :return (path, password): path of destination directory if successfully 
        created, and the last used valid password if any.
        """
        raise NotImplementedError

    @classmethod
    def list_files(
        cls, 
        target: Path, 
        password: Optional[str] = None,
        exclude: list[str] = None
    ) -> list[ArchiveEntry]:
        raise NotImplementedError

    @classmethod
    def print_file(
        cls, 
        target: Path, 
        probfile: ArchiveEntry, 
        dest_path: Path,
        password: Optional[str] = None,
        exclude: list[str] = None
    ) -> None:
        raise NotImplementedError


class UnrarExitCode(Enum):
    RARX_SUCCESS   =   0  # Successful operation.
    RARX_WARNING   =   1  # Non fatal error(s) occurred.
    RARX_FATAL     =   2  # A fatal error occurred.
    RARX_CRC       =   3  # Invalid checksum. Data is damaged.
    RARX_LOCK      =   4  # Attempt to modify an archive locked by 'k' command.
    RARX_WRITE     =   5  # Write error.
    RARX_OPEN      =   6  # File open error.
    RARX_USERERROR =   7  # Wrong command line option.
    RARX_MEMORY    =   8  # Not enough memory.
    RARX_CREATE    =   9  # File create error
    RARX_NOFILES   =  10  # No files matching the specified mask and options were found.
    RARX_BADPWD    =  11  # Wrong password.
    RARX_READ      =  12  # Read error.
    RARX_USERBREAK = 255  # User stopped the process.


class UnrarErrorCode(Enum):
    TOO_LONG = "File name too long"
    NOT_A_DIR = "Not a directory"


class UnrarHandler(Handler):
    ecmd = [
            "unrar", "x",
            #"-or",  # rename files if name already taken
            # "-ad", # prepend archive name to output directory
            "-o-",  # DEBUG don't overwrite
            # "-kb", # keep broken files
            "-c-", # don't display comment
            # "-p-", # don't prompt for password
            # "-ierr", # send all messages to stderr
            # "-x'*.txt'", # exclude xt files
            "--",
            "##TARGET##", "##DESTDIR##"
        ]
    lcmd = [
            "unrar", "la", "-c-", "-p##PASSWORD##", "##TARGET##"
        ]
    pcmd = [
            "unrar", "p", "-inul", "-p##PASSWORD##", "##TARGET##", "##PROBFILE##"
        ]

    @classmethod
    def extract_files(
        cls, 
        target: Path, 
        dest_dir: Union[Path, None] = None,
        create_subdir: bool = True,
        exclude: list[str] = None
    )-> tuple[Path, Union[str, None]]:

        cmd = replace_cmd(
            cls.ecmd, 
            ("##TARGET##", target), 
            ("##DESTDIR##", dest_dir)
        )

        if exclude:
            for ex in exclude:
                cmd.insert(2, f"-x'{ex}'")

        log.debug(f"Command after replace: {cmd}")
        
        # If destdir is None, use -ad flag (##DESTDIR## is removed). In practice
        # we don't use it since we always specify a dest dir in File class,
        # as this is also prone to raise "Not a directory" errors, but just in case...
        unrar_dest_dir = target.absolute().parent / target.stem
        if dest_dir is None or "##DESTDIR##" not in cmd:
            # unrar will use this path, and fail if that's a file, so we fall 
            # back to our own manual solution of creating a unique subdir
            if unrar_dest_dir.is_file():
                log.debug("Destination is a file, unrar will not like...")
                dest_dir = get_dest_dir(target, None, create_subdir)
                log.debug(f"Will output to \"{dest_dir}\" instead.")
                unrar_dest_dir = dest_dir
                cmd.append(str(dest_dir))
            else:
                cmd.insert(3, "-ad")

        if dest_dir is not None:
            makedirs(dest_dir, exist_ok=True)
        elif dest_dir is None:
            dest_dir = unrar_dest_dir
            
        exitcode = -1
        output: Optional[io.StringIO] = None
        last_pw = None
        try:
            output, exitcode, last_pw = cls.run_subproc(cmd)
        # except CalledProcessError as e:
        except pexpect.ExceptionPexpect as e:
            log.exception(f"Pexcept exception: {e}")

        play_sound("WARNING")

        if exitcode >= 9:
            log.debug(f"Looking for problematic filenames in {cmd[0]} output...")
            problematic_filenames = []
            if output is not None:
                output.seek(0)
                problematic_filenames = parse_unrar_text_output(
                    output,  # or output.getvalue()
                    dest_dir
                )
                output.close()
                # Adding the password for each file, assuming only one password per archive
                for pfile in problematic_filenames:
                    pfile.password = last_pw

            raise FileCreationError(
                "Some file names failed to extract.",
                problematic_filenames,
                dest_dir = dest_dir,
                password = last_pw
            )

        elif exitcode != 0:
            log.warning(
                f"{cmd[0]} returned exit code {exitcode}: "
                f"{UnrarExitCode(exitcode).name}"
            )
            # TODO make custom exception, handle other errors better
            raise Exception
        
        return dest_dir, last_pw

    @classmethod
    def list_files(
        cls, 
        target: Path, 
        password: Optional[str] = None,
        exclude: list[str] = None
    ) -> list[ArchiveEntry]:
        cmd = replace_cmd(
            cls.lcmd, 
            ("##TARGET##", target),
            ('##PASSWORD##', password)
        )
        if exclude:
            for ex in exclude:
                cmd.insert(2, f"-x'{ex}'")
        while True:
            try:
                proc = run(
                    cmd,
                    check=True,
                    capture_output=True,
                    # stdin=PIPE, stdout=PIPE, stderr=STDOUT,
                    text=True,
                )
                return cls.parse_list_output(proc.stdout)
            except Exception as e:
                log.debug(f"Unhandled error running extractor subcommand {cmd}: {e}")
                raise e

    @staticmethod
    def parse_list_output(buffer: str) -> list[ArchiveEntry]:
        """Return list of entry files, but filter out the directory files."""
        files_parts = []
        for line in buffer.split("\n"):
            stripped = line.rstrip()
            if stripped.startswith((" ", "*")): 
                # "*   ..A....      1220  2021-08-05 21:15  dir/file.ext"
                # "    ...D...         0  2021-08-05 21:15  dir"
                if match := re.match(r"\*?\s*(\S{7})\s*\d*\s{2}.*\s{2}(.*)", line):
                    attrs = match.group(1)
                    entryname = match.group(2)
                    log.debug(f"attrs: {attrs} fname {entryname}")
                    if "D" not in attrs:
                        splits = entryname.split("/")
                        filename = splits[-1]
                        innerpath = splits[:-1]
                        innerpath.extend([filename])
                        files_parts.append(innerpath)
        return [ArchiveEntry(parts[-1], parts[:-1]) for parts in files_parts]

    @classmethod
    def print_file(
        cls, 
        target: Path, 
        probfile: ArchiveEntry, 
        dest_path: Path,
        password: Optional[str] = None,
        exclude: list[str] = None
    ) -> None:
        log.debug(f"print_file(): probfile: {probfile}, password {password}")
        cmd = replace_cmd(
            cls.pcmd, 
            ("##TARGET##", target), 
            ("##PROBFILE##", probfile),
            ('##PASSWORD##', password)
        )
        if exclude:
            for ex in exclude:
                cmd.insert(2, f"-x'{ex}'")
        try:
            cls.run_subproc2(
                cmd, 
                probfile=probfile, 
                dest_dir=dest_path
            )
        except Exception as e:
            log.exception(e)
            raise

    @staticmethod
    def run_subproc(cmd: list) -> tuple[io.StringIO, int, Optional[str]]:
        log.debug(f"Running command: {cmd}")
        child = pexpect.spawn(cmd[0], args=cmd[1:], encoding='utf-8')
        log.debug(f"pexpect spawned: {child.command} {child.args}")
        child.logfile = stdout
        _outputbuff = io.StringIO()
        child.logfile_read = _outputbuff
        last_pw = None
        while True:
            match = child.expect(
                [
                    "Enter password.*for (.*)",
                    "The specified password is incorrect",
                    ".*use current password ?.*", # [Y]es, [N]o, [A]ll
                    pexpect.EOF
                ]
            )
            if match == 0:
                log.debug(
                    f"Password prompt detected for file {child.match}, enter pw!")
                pw = run_zenity()
                log.debug(f"Got pw from zenity: {pw}")
                if pw is None:  # clicked cancel
                    child.close()
                    raise CanceledPasswordPrompt
                else:
                    stripped = pw.strip()
                    if stripped == "":
                        last_pw = None
                        # Sending a bogus password to force asking user again
                        child.sendline("---")
                        continue
                    log.debug(f"Sending \"{stripped}\" to subproc...")
                    last_pw = stripped
                    child.sendline(stripped)
                    continue
            elif match == 1:
                play_sound("WARNING")
                continue
            elif match == 2:
                # TODO we could send Yes instead and record valid password for each 
                # entry, which means we need to instanciate an appropriate
                # ArchiveEntry for every entry needing a password
                log.debug("Detected prompt to resend... Sending 'All'.")
                child.sendline("A\n")
                continue
            elif match == 3:
                child.close()
                log.debug(
                    f"Exit status: {child.exitstatus} signal: {child.signalstatus}"
                )
                break
            else:
                log.debug("No expect match...")
                continue
        return _outputbuff, child.exitstatus, last_pw

    @staticmethod
    def run_subproc2(
        cmd: list, 
        probfile: ArchiveEntry, 
        dest_dir: Path
    ) -> None:
        newname = sanitized(probfile.name, isfile=True)
        log.critical(f"Renamed problematic file to {newname}")

        if probfile.path is not None:
            final_path = dest_dir / (probfile.path + sep + newname)
        else:
            final_path = dest_dir / newname
        
        if final_path.is_file():
            log.warning(f"File {final_path} already exists.")
            return
            # TODO if filename is 255 bytes long, overwrite with number
            # otherwise simply append to it.
            # num = 1
            # while final_path.exists():
            #     add = f" {str(num)}"
            #     final_path = final_path.with_name(
            #         final_path.stem[:-len(add)] + add + final_path.suffix)
            #     num += 1
            # log.warning(f"Will attempt to extract as {final_path}.")

        with open(final_path, "wb") as outfile:
            command = Popen(
                cmd, 
                stdout=outfile,
                stdin=PIPE, 
                stderr=PIPE
            )
            # FIXME we don't need all this
            childin = fdpexpect.fdspawn(command.stdin)
            childerr = fdpexpect.fdspawn(command.stderr)
            while True:
                match = childerr.expect(
                    [
                        "Enter password.*",
                        "The specified password is incorrect",
                        pexpect.EOF
                    ]
                )
                if match == 0:
                    # has_password = True
                    log.debug("Password prompt detected, enter pw!")
                if match == 2:
                    log.debug("EOFFFFFFFFFFFFFFFFFFFFFFFF"
                    )
                    break


class SevenZHandler(Handler):
    ecmd = [
        "7z", "x", "##TARGET##",
        # "-w", "##DESTDIR##", # change cwd
        "-o*", # automatic create output directory
        # "-o##DESTDIR##", # manual output directory
        "-x!*.txt",  # exclude txt files
    ]

    @classmethod
    def extract_files(cls, target: Path, destdir: Optional[Path] = None) -> None:
        # TODO if no destdir, use -ad flag and remove ##DESTDIR##
        cmd = replace_cmd(
            cls.ecmd,
            ("##TARGET##", target), 
            ("##DESTDIR##", destdir)
        )


class UnzipHandler(Handler):
    ecmd = ["unzip", "-d", "##DESTDIR##", "##TARGET##"]


class ArkHandler(Handler):
    ecmd = ["ark", "--batch", "-o", "##DESTDIR##", "##TARGET##"]


class UnpHandler(Handler):
    ecmd = ["unp", "##TARGET##", "-u", "##DESTDIR##"]


class CanceledPasswordPrompt(Exception):
    pass


class FileCreationError(Exception):
    def __init__(
        self, 
        args: object, 
        filelist: Union[list, set],
        dest_dir: Optional[Path] = None,
        password: Optional[str] = None
    ) -> None:
        """dest_dir is the directory created by the extractor"""
        super().__init__(args)
        self.problematic_filenames: Union[list, set] = filelist
        self.dest_dir = dest_dir
        self.password = password
