from asyncio.tasks import current_task
from os import rmdir, sep, symlink, walk, mkdir, makedirs
from shutil import copy, move, rmtree
from pathlib import Path
from safer_extract.file import File, enumerate_extracted_files
import safer_extract.handlers
import unittest
import unittest.mock
from itertools import product
import logging

log = logging.getLogger()

# run with python -m unittest -v tests.main_test
# WARNING this is just an obsolete draft, it is broken. 
# Use the pytest version instead.

TESTDIRFILES = Path(__file__).parent / "fixtures"
BASETESTDIR = Path("/tmp/safer_extract_tests")

def setup_test_files():
    """Make symlinks to our test files into /tmp."""
    makedirs(BASETESTDIR, exist_ok=True)
    for root, _, files in walk(TESTDIRFILES):
        for f in files:
            symlink(sep.join((root, f)), BASETESTDIR / f)

setup_test_files()

current_sub_cases = []

class TestRar(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # cls.dest_dir_choices = [None, TESTDIR / cls.__name__]
        cls.create_subdir_choices = [True, False]
        cls.verification_choices = [True, False]
        cls.filename = "normal_from_unix.rar"
        cls.nentries = 4
        return super().setUpClass()

    def setUp(self) -> None:
        # self.testdir = BASETESTDIR / self.__class__.__name__
        self.testdir = BASETESTDIR / self.id()
        makedirs(self.testdir, exist_ok=True)
        # copy file to its own subdir
        _file = copy(
            BASETESTDIR / self.filename, self.testdir, follow_symlinks=False
        )
        self.dest_dir_choices = [None, self.testdir]
        # Build the combinations of user defined options
        self.sub_cases = product(
            self.dest_dir_choices,
            self.create_subdir_choices, 
        )
        global current_sub_cases
        current_sub_cases = list(self.sub_cases)
        self.file = File(str(_file))
        print(f"file {self.file} cases {current_sub_cases}")
        return super().setUp()

    def tearDown(self) -> None:
        # for _d in self.dest_dir_choices:
        #     rmtree(_d)
        return super().tearDown()

    def check_list_files(self, expected_number):
        self.entries = self.file.list_files()
        print(f"entries: {self.entries}")
        self.assertEqual(len(self.entries), expected_number)

    @unittest.mock.patch("safer_extract.handlers.run_zenity")
    def test_extract(self, mock_zenity):
        if not self.file.exists():
            print(f"File {self.file} does not exist.")
            return

        def test_extract_sub(dest_dir_choice, subdir_choice):
            with self.subTest(dest_dir=dest_dir_choice):
                # self.file.force_verification = verif_choice
                self.file.extract_files(
                    dest_dir=dest_dir_choice, 
                    create_subdir=subdir_choice    
                )
                
                files_on_disk = enumerate_extracted_files(
                    Path(dest_dir_choice)
                    if dest_dir_choice is not None else self.testdir
                )
                if self.testdir is not None:
                    self.assertEqual(len(files_on_disk), self.nentries)
                else:
                    # extracted files + the archive itself, in the same dir
                    self.assertEqual(len(files_on_disk) + 1, self.nentries)

        self.check_list_files(expected_number=self.nentries)
        for case in self.sub_cases:
            dest_dir_choice = case[0]
            subdir_choice = case[1]
            try:
                test_extract_sub(dest_dir_choice, subdir_choice)
            finally:
                # rmtree(dest_dir_choice)
                pass


        # for dest_dir_choice in self.dest_dir_choices:
        #     for subdir_choice in self.create_subdir_choices:
        #         for verif_choice in self.verification_choices:
        #             with self.subTest(dest_dir=dest_dir_choice):
        #                 self.file.force_verification = verif_choice
        #                 self.file.extract_files(
        #                     dest_dir=dest_dir_choice, 
        #                     create_subdir=subdir_choice    
        #                 )
        #                 self.assertEqual(
        #                     len(enumerate_extracted_files(Path(dest_dir_choice) \
        #                     if dest_dir_choice is not None else self.testdir)), 
        #                     3
        #                 )

class TestRarLongNames(TestRar):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        # cls.dest_dir_choices = [None, TESTDIR / cls.__name__]
        cls.filename = "long_filenames.rar"

    # def tearDown(self) -> None:
    #     return super().tearDown()

    # def test_extract(self):
    #     return super().test_extract()


class TestRarPassword(TestRar):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        # cls.dest_dir_choices = [None, TESTDIR / cls.__name__]
        cls.filename = "password_no_crypted_fnames.rar"
        cls.nentries = 3

    @unittest.mock.patch("safer_extract.handlers.run_zenity")
    def test_extract(self, mock_zenity):
        mock = unittest.mock.MagicMock(return_value="passpass")
        with unittest.mock.patch('safer_extract.handlers.run_zenity', mock):
            print(f"mockjed: {safer_extract.handlers.run_zenity()}")
            return super().test_extract(mock_zenity)
        # mock_zenity()

    # def tearDown(self) -> None:
    #     return super().tearDown()


if __name__ == '__main__':
    unittest.main(verbosity=2, failfast=True)
