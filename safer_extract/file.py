from typing import Generator, Optional
from pathlib import Path
from os import walk
import logging
log = logging.getLogger()
from subprocess import DEVNULL, run
from mimetypes import guess_extension, guess_type

HAS_MAGIC = False
try:
    # This is either python-magic or file-magic (deprecated)
    import magic
    HAS_MAGIC = True
except ImportError as e:
    log.warning(e)

from .handlers import (
    ArchiveEntry, UnrarHandler, SevenZHandler, UnzipHandler, ArkHandler, 
    UnpHandler, FileCreationError, CanceledPasswordPrompt, Handler, 
    RarLibHandler, PatoolHandler
)
from .notification import play_sound
from .util import get_dest_dir
from .handlers import UnrarErrorCode


# The order matter for ranking
ext_to_extractor = {
    ".rar": [UnrarHandler, RarLibHandler, SevenZHandler, ArkHandler, UnpHandler],
    ".zip": [SevenZHandler, UnzipHandler, PatoolHandler, ArkHandler, UnpHandler],
    "*": [PatoolHandler, UnpHandler, ArkHandler]
}

def update_available_tools():
    """
    Keep track of processes and libraries available on this system.
    """
    available_extractors = set()
    for h_list in ext_to_extractor.values():
        for h in h_list:
            available_extractors.add(h)

    log.debug(f"Initial extractors list {available_extractors}")

    # Update list of available extractors on this system
    missing = set()
    for p in available_extractors:
        if hasattr(p, "ecmd"):
            log.debug(f"Checking if {p.ecmd[0]} is available...")
            # Use the hardcoded commands to identify the program actually used
            proc = run(
                ['which', p.ecmd[0]], check=False,
                capture_output=False, stdout=DEVNULL, stderr=DEVNULL
            )
            if not proc.returncode == 0:
                log.debug(f"`which {p}` returned exit code {proc.returncode}")
                missing.add(p)
        elif hasattr(p, "available"):  # handler is a library wrapper
            if not p.available:
                missing.add(p)
        else:
            missing.add(p)

    for miss in missing:
        available_extractors.remove(miss)
    log.info(f"Available extractors: {available_extractors}")

    # update according to available
    for key in ext_to_extractor.keys():
        ext_to_extractor[key] = [
            h for h in ext_to_extractor[key] if h in available_extractors
        ]

    log.debug(f"Extractors per extension {ext_to_extractor}")

update_available_tools()

ext_to_mime = {
    ".rar": ["application/x-rar", "application/vnd.rar"],
    ".zip": ["application/zip", "application/gzip", "application/vnd.comicbook+zip"],
    ".7z": ["application/x-7z-compressed"],
}


def get_ext(_mime: Optional[str]) -> Optional[str]:
    if _mime is None:
        return None
    for key, values in ext_to_mime.items():
        for value in values:
            if _mime == value:
                return key


def get_mimetype(fpath: Path) -> tuple[Optional[str], Optional[str]]:
    if not HAS_MAGIC:
        return None, None
    if hasattr(magic, "from_file"):  # We use "python-magic" package
        m = magic.from_file(fpath, mime=True, uncompess=False, extension=True)
        mime = m.mime
        ext = "." + m.extension
        log.debug(f"Using python-magic: {mime}, {ext}")
        return mime, ext  # 'application/x-rar'
    else:  # We use "file-magic" package (upstream, but deprecated)
        # strict will raise if file is a symlink and can't be resolved
        detected = magic.detect_from_filename(str(fpath.resolve(strict=True)))
        # mime_type='application/x-rar'
        log.debug(
            f"file-magic detected mime_type: \"{detected.mime_type}\" "
            f"name: \"{detected.name}\""
            )
        mime = detected.mime_type
        log.debug(f"Using file-magic: {mime}, None")
        return mime, None


class File():
    def __init__(self,
                filepath: str,
                verify: bool = False) -> None:
        """
        Describe an archive file.
        :param filepath: path to archive
        :param dest_dir: path to output directory if desired
        :param create_subdir: whether or not to create directory named
        from the archive name, without extension
        """
        self.path: Path = Path(filepath)
        self._mimetype: Optional[str] = None
        self._ext: Optional[str] = None
        self._handlers: Optional[list] = None
        self._used_unreliable: bool = False
        self.dest_dir: Optional[Path] = None
        self._gen_handler: Generator 
        # This may raise StopIteration if the handler list is empty!
        self.handler: Handler = next(self.handlers)()
        self.password: Optional[str] = None
        self.force_verification: bool = verify

    def exists(self) -> bool:
        return self.path.exists()

    def __repr__(self) -> str:
        return str(self.path)

    @property
    def handlers(self) -> Generator:
        """Return a generator from the start on each call."""
        if self._handlers is None:
            _ext = self.extension
            log.debug(f"Extension for {self} is {_ext}")
            if _ext is not None:
                self._handlers = ext_to_extractor[_ext]
            else:
                if self._mimetype is not None \
                and "inode/directory" in self._mimetype:
                    raise Exception("Not a valid archive file.")
                self._handlers = ext_to_extractor['*']
            # self._handlers.append(None)
            self._gen_handler = (h for h in self._handlers)
        return self._gen_handler

    @property
    def mimetype(self) -> Optional[str]:
        if self._mimetype is None:
            mime = guess_type(self.path)
            log.debug(f"Guessed type: {mime}")
            if mime[0] is None:
                mime, _ext = get_mimetype(self.path)
                log.debug(f"get_mimetype()-> {mime}, {_ext}")
                self._mimetype = mime
                if _ext is None:
                    _ext = get_ext(mime)
                self._ext = _ext
            else:
                self._mimetype = mime[0]
                self._ext = guess_extension(mime[0])
                if self._ext is None:
                    self._ext = get_ext(self._mimetype)
        return self._mimetype
        # #
        # if self._type is not None:
        #     return self._type
        # mime = guess_type(self.path)
        # self._type = mime[0]
        # return self._type

    @property
    def extension(self) -> Optional[str]:
        if self._ext is not None:
            return self._ext
        mime = self.mimetype
        log.debug(f"Mimetype for {self} is {mime}")
        return self._ext

    def extract_files(
        self,
        dest_dir: Optional[Path],
        create_subdir: bool = True,
        exclude: list[str] = None
    ) -> None:

        self.dest_dir = get_dest_dir(self.path, dest_dir, create_subdir)

        while True:
            if self.handler is ArkHandler:
                self._used_unreliable = True
            log.debug(f"Calling extractor: {self.handler}")
            try:
                self.password = self.handler.extract_files(
                    target=self.path,
                    dest_dir=self.dest_dir,
                    create_subdir=create_subdir,
                    exclude=exclude
                )
                break
            except FileCreationError as e:
                # if not e.problematic_filenames:
                # TODO get bad filenames by other means (-test flag) if empty
                log.debug(
                    f"Problematic filenames found: "
                    f"{len(e.problematic_filenames)}. "
                    f"{e.problematic_filenames}"
                )
                self.password = e.password
                for pfile in e.problematic_filenames:
                    if pfile.error == UnrarErrorCode.NOT_A_DIR.value:
                        play_sound("FAILED")
                        log.critical(
                            f"Trying to extract from {self} to a file that is "
                            "not a directory! Skipping."
                        )
                    self.print_file(
                        pfile,
                        dest_dir=e.dest_dir,
                        create_subdir=create_subdir,  # not really used
                        password=pfile.password
                    )
                break
            except CanceledPasswordPrompt:
                log.warning(f"We have skipped password prompt for file {self.path}")
                raise
            except Exception as e:
                play_sound("WARNING")
                log.exception(e)
                log.debug(f"Trying next handler for {self}...")
                self.handler = next(self.handlers)()

        if self._used_unreliable or self.force_verification:
        # Compare extracted files to files listed by extractor
            if self.dest_dir is None \
            or self.dest_dir == self.path.absolute().parent:
                log.debug(f"{self} had no specified destination directory. "
                            "Skipping verification of extracted files.")
                return

            log.debug("Checking number of entries in archive...")
            log.debug(f"arfile {self} has password: {self.password}")
            arentries = self.list_files(self.password)
            log.debug(f"Number of entries found {len(arentries)}: {arentries}")

            log.debug("Checking number of entries in output directory...")
            fsentries = enumerate_extracted_files(self.dest_dir)
            diff_count = len(arentries) - len(fsentries)
            if diff_count != 0:
                fs_missing_files = \
                    [f for f in arentries if f not in fsentries]
                log.warning(
                    f"{diff_count.__abs__()} files might be missing from disk "
                    "after extraction, or they had to be renamed slightly: "
                    f"{fs_missing_files}"
                )
            else:
                log.debug(
                    "Number of files on disk matches number of files "
                    f"reported in archive by extractor {self.handler.__class__}")


    def list_files(self, password: Optional[str] = None) -> list:
        files = []
        while True:
            print("Listing files...")
            try:
                files = self.handler.list_files(
                    target=self.path,
                    password=password
                )
                return files
            except:
                self.handler = next(self.handlers)()

    def print_file(self,
                   filename: ArchiveEntry,
                   dest_dir: Optional[Path] = None,
                   create_subdir: bool = True,
                   password: Optional[str] = None) -> None:
        if dest_dir is None:
            dest_dir = get_dest_dir(self.path, dest_dir, create_subdir)

        while True:
            try:
                self.handler.print_file(
                    target=self.path,
                    probfile=filename,
                    dest_path=dest_dir,
                    password=password
                )
                return
            except:
                self.handler = next(self.handlers)()


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
