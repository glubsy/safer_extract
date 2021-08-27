# run with python -m pytest -v -s --maxfail=2 tests.main_test.py
from os import sep, symlink
# from shutil import copy, move, rmtree
from pathlib import Path
import logging
# from itertools import product
import pytest
from typing import Optional, Union
# from unittest import MagicMock

from safer_extract.file import (
    File, enumerate_extracted_files, ext_to_extractor
)
import safer_extract.file
import safer_extract.handlers
from safer_extract.handlers import UnrarHandler, RarLibHandler
import safer_extract.notification

log = logging.getLogger()
log.setLevel(logging.DEBUG)

TESTDIRFILES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def no_zenity(monkeypatch):
    monkeypatch.setattr(
        safer_extract.handlers, "run_zenity", lambda: "passpass"
    )


@pytest.fixture(autouse=True)
def no_notification(monkeypatch):
    monkeypatch.setattr(
        safer_extract.notification, "SFX", dict()
    )


dest_dir_choices = [None, "custom"]
create_subdir_choices = [True, False]
RarExtractors = [UnrarHandler]


@pytest.fixture()
def setup_test_arfile(request, tmp_path):
    # monkeypatch.chdir(tmp_path)
    symlink(
        sep.join((str(TESTDIRFILES), request.node.cls.filename)),
        tmp_path / request.node.cls.filename
    )
    print(f"Symlinking to file {request.node.cls.filename}")

    if hasattr(request.node.cls, "extras"):
        print("Symlinking extras...")
        for extra in request.node.cls.extras:
            symlink(
                sep.join((str(TESTDIRFILES), extra)),
                tmp_path / extra
            )
    yield tmp_path / request.node.cls.filename
    # rmtree(tmp_path)


@pytest.fixture()
def force_extractor(monkeypatch, request):
    monkeypatch.setitem(
        ext_to_extractor, request.node.cls.ext, request.node.cls.extractors
    )
    print(f"force_extractor: {ext_to_extractor}")


def test_no_handler(monkeypatch, tmp_path):
    fake_file = tmp_path / "test.rar"
    with monkeypatch.context() as m:
        # m.setattr(safer_extract.file, "ext_to_extractor", ext_to_extractor)
        m.setitem(
            safer_extract.file.ext_to_extractor, ".rar", []
        )
        with pytest.raises(StopIteration):
            _ = File(fake_file)


def test_depleted_handler(monkeypatch, tmp_path):
    fake_file = tmp_path / sep.join((str(TESTDIRFILES), "long_filenames_pw"))

    with monkeypatch.context() as m:
        m.setitem(
            safer_extract.file.ext_to_extractor, ".rar", [UnrarHandler]
        )
        _file = File(fake_file)
        print(f"_file {_file}")
        assert type(_file.handler) is UnrarHandler
        assert _file._handlers is not None
        assert UnrarHandler in _file._handlers
        # assert _file._handlers[-1] is None
        print(f"handler: {_file._handlers}")

        with pytest.raises(StopIteration):
            print(f"HANDLER: {next(_file.handlers)}")
        # print(f"HANDLERRR: {next(_file.handlers, None)}")
        # assert next(_file.handlers, None) is None


# @pytest.fixture(scope="class")
# def my_filepath(self, tempfile):
#     tmpdir = tempfile.mkdtemp()
#     subdir = os.path.join(tmpdir, "sub")
#     os.mkdir(subdir)
#     yield os.path.join(subdir, "testCurrentTicketCount.txt")
#     shutil.rmtree(tmpdir)

# @pytest.fixture(scope="class")
# def class_setup(tmp_path_factory):
#     print(f"Class setup {tmp_path_factory}")
#     assert 0


class TestUnrar():
    filename: str = "normal_from_unix.rar"
    ext: str = ".rar"
    mimetypes = ["application/x-rar", "application/vnd.rar"]
    # extractors: list = [UnrarHandler]
    nentries: int = 4
    password: Optional[str] = None
    file: Optional[File] = None

    def assert_number_of_entries(
        self,
        arfile: File,
        expected_number: int,
        password: Optional[str]
    ) -> None:
        entries = arfile.list_files(password)
        print(f"entries: {entries}")
        assert len(entries) == expected_number

    def assert_same_number_of_files(
        self, dest_dir_choice: Union[Path, str], updated_path: bool
    ) -> None:
        extra_len = len(getattr(self, "extras", []))

        if updated_path:
            assert len(enumerate_extracted_files(Path(dest_dir_choice))) \
                == self.nentries
        else:
            # Extracted in the same directory, so we add the archive file itself
            # plus any extra file already present
            assert len(enumerate_extracted_files(Path(dest_dir_choice))) \
                == self.nentries + 1 + extra_len

    def test_mime_detected(self, class_setup):
        if not self.file:
            self.file = File(sep.join((str(TESTDIRFILES), self.filename)))
        print(f"Mimetype: {self.file.mimetype}")
        assert self.file.mimetype in self.mimetypes

    @pytest.mark.parametrize("subdir_choice", create_subdir_choices)
    @pytest.mark.parametrize("dest_dir_choice", dest_dir_choices)
    @pytest.mark.parametrize("extractor", RarExtractors)
    def test_extract(
        self,
        tmp_path,
        monkeypatch,
        extractor,
        setup_test_arfile,
        dest_dir_choice,
        subdir_choice
    ):
        monkeypatch.setitem(ext_to_extractor, self.ext, [extractor])

        if not self.file:
            self.file = File(setup_test_arfile)

        assert self.file.exists()

        print(f"Handlers {self.file._handlers}, current {self.file.handler}")

        self.assert_number_of_entries(
            arfile=self.file, expected_number=self.nentries, password=self.password
        )

        updated_path = False
        if isinstance(dest_dir_choice, str):
            dest_dir_choice = Path(tmp_path / dest_dir_choice).absolute()
            updated_path = True

        self.file.extract_files(
            dest_dir=dest_dir_choice,
            create_subdir=subdir_choice
        )

        self.post_extract_tests(tmp_path, dest_dir_choice, subdir_choice)

        if dest_dir_choice is None:
            dest_dir_choice = self.file.path.parent.absolute()
            print(f"No custom dest dir. Updated to parent of archive {dest_dir_choice}")

        self.assert_same_number_of_files(dest_dir_choice, updated_path)

    def post_extract_tests(self, tmp_path, dest_dir_choice, subdir_choice):
        pass


class TestRarLongNames(TestUnrar):
    filename = "long_filenames.rar"
    nentries = 3


class TestRarLongNamesPassword(TestUnrar):
    filename = "long_filenames_pw.rar"
    nentries = 3


class TestRarLongNamesPasswordNoExt(TestUnrar):
    filename = "long_filenames_pw"
    nentries = 3

    @pytest.mark.parametrize("subdir_choice", create_subdir_choices)
    @pytest.mark.parametrize("dest_dir_choice", dest_dir_choices)
    @pytest.mark.parametrize("extractor", RarExtractors)
    def test_extract(
        self, tmp_path, monkeypatch, extractor, setup_test_arfile, 
        dest_dir_choice, subdir_choice
    ):
        return super().test_extract(
            tmp_path, monkeypatch, extractor, setup_test_arfile, 
            dest_dir_choice, subdir_choice
        )

    def post_extract_tests(self, tmp_path, dest_dir_choice, subdir_choice):
        # test if directory created with ".d"
        if subdir_choice and not dest_dir_choice:
            tgt = tmp_path / (self.filename + ".d")
            assert tgt.is_dir()


class TestRarLongNamesPasswordNoExtAlreadyExist(TestUnrar):
    filename = "long_filenames_pw"
    # Test if a file with directory name already exists
    extras = ["long_filenames_pw.d"]
    nentries = 3

    def post_extract_tests(self, tmp_path, dest_dir_choice, subdir_choice):
        # Directory has to be renamed
        if subdir_choice and not dest_dir_choice:
            tgt = tmp_path / (self.filename + "_1.d")
            assert tgt.is_dir()


class TestRarPassword(TestUnrar):
    filename = "password_no_crypted_fnames.rar"
    nentries = 4


class TestRarPasswordCryptedEntryNames(TestUnrar):
    filename = "password_crypted_fnames.rar"
    nentries = 4
    # use password to list files
    password = "passpass"




if __name__ == '__main__':
    pytest.main()
