from typing import Generator, Optional, Any
from pathlib import Path
import logging
from mimetypes import guess_extension, guess_type

HAS_MAGIC = False
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    pass

from .handlers import (
    ArchiveEntry, UnrarHandler, SevenZHandler, UnzipHandler, ArkHandler, UnpHandler,
    FileCreationError, CanceledPasswordPrompt, Handler
)
from .notification import play_sound
from .util import get_dest_dir
from .handlers import UnrarErrorCode

log = logging.getLogger()

# The order matter for ranking
ext_to_extractor = {
    ".rar": [UnrarHandler, SevenZHandler, ArkHandler, UnpHandler],
    ".zip": [SevenZHandler, UnzipHandler, ArkHandler, UnpHandler],
    "*": [UnpHandler, ArkHandler]
}

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
    if hasattr(magic, "from_file"):
        # We use "python-magic" package
        m = magic.from_file(mime=True, uncompess=False, extension=True)
        mime = m.mime
        ext = "." + m.extension
        return mime, ext
        # 'application/x-rar'
    else:
        # We use "file-magic" package (upstream, but deprecated)
        detected = magic.detect_from_filename(str(fpath))
        # mime_type='application/x-rar'
        log.debug(
            f"file-magic detected mime_type: \"{detected.mime_type}\" "
            f"name: \"{detected.name}\""
            )
        mime = detected.mime_type
        return mime, None


class File():
    def __init__(self,
                filepath: str) -> None:
        """
        Describe an archive file.
        :param filepath: path to archive
        :param dest_dir: path to output directory if desired
        :param create_subdir: whether or not to create directory named
        from the archive name, without extension
        """
        self.path = Path(filepath)
        self._mimetype: Optional[str] = None
        self._ext: Optional[str] = None
        self._handlers: Optional[list] = None
        self._used_unreliable: bool = False
        self.dest_dir: Optional[Path] = None
        self.handler: Handler = next(self.handlers)
        self.password: Optional[str] = None

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
        return (h() for h in self._handlers)

    @property
    def mimetype(self) -> Optional[str]:
        if self._mimetype is None:
            mime = guess_type(self.path)
            if mime[0] is None:
                mime, _ext = get_mimetype(self.path)
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
                return
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
                return
            except CanceledPasswordPrompt:
                log.warning(f"We have skipped password prompt for file {self.path}")
                return
            except Exception as e:
                play_sound("WARNING")
                log.exception(e)
                log.debug(f"Trying next handler for {self}...")
                self.handler = next(self.handlers)

    def list_files(self, password: Optional[str] = None) -> list:
        files = []
        while True:
            try:
                files = self.handler.list_files(
                    target=self.path,
                    password=password
                )
                return files
            except:
                self.handler = next(self.handlers)

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
                self.handler = next(self.handlers)
