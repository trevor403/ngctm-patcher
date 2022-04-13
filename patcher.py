#! /usr/bin/env python3

# Credits to leogx9r for patching logic

import pefile
import logging
from sys import exit
from pathlib import Path


class SpecialFormatter(logging.Formatter):
    FORMATS = {
        logging.ERROR: "[!] %(message)s",
        logging.INFO: "[+] %(message)s",
        logging.DEBUG: "[=] %(message)s",
        logging.WARNING: "[-] %(message)s",
        "DEFAULT": "%(levelname)s: %(message)s",
    }

    def format(self, record):
        orig_fmt = self._fmt
        orig_style = self._style

        self._fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        self._style = logging.PercentStyle(self._fmt)
        result = super().format(record)

        self._fmt = orig_fmt
        self._style = orig_style

        return result


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
c_handler = logging.StreamHandler()
c_handler.setLevel(logging.DEBUG)
c_handler.setFormatter(SpecialFormatter())
logger.addHandler(c_handler)


class PrettyBytes:
    def __init__(self, _bytes):
        self.bytes = _bytes

    def __str__(self):
        return ''.join('\\x{:02x}'.format(b) for b in self.bytes)


class Patch:
    """
    Replaces bytes
    """

    CALL_LEN = 5  # E8 | xx xx xx xx
    LEA_LEN = 7  # LEA: 48 8D xx | xx xx xx xx

    patch_types = {
        "nop": "90" * CALL_LEN,
        "ret": "C3",  # ret
        "ret0": "48 31 C0 C3",  # xor rax, rax; ret
        "ret1": "48 31 C0 48 FF C0 C3",  # xor rax, rax; inc rax; ret
    }

    patch_types.update((k, bytes.fromhex(v)) for k, v in patch_types.items())

    def __init__(self, offset: int, patch_type: str, file=None):
        self.file = file
        self.offset = offset

        if patch_type not in Patch.patch_types:
            raise ValueError("Unsupported patch type {}".format(patch_type))

        self.patch_type = patch_type
        self.new_bytes = Patch.patch_types[self.patch_type]

    def apply(self, file=None):
        if not hasattr(self, 'file') and not file:
            raise ValueError("No file provided")
        end_offset = self.offset + len(self.new_bytes)
        logger.debug(
            "Offset {:<8}: patching {} with {}".format(hex(self.offset),
                                                       PrettyBytes(self.file.data[self.offset:end_offset]),
                                                       PrettyBytes(self.new_bytes))
        )
        self.file.data[self.offset:end_offset] = self.new_bytes


class File:
    """
    Loads file data
    """

    ngctm_EXE_NAME = "ngctm.exe"
    NULL = b"\x00"

    def __init__(self, filepath: str):
        self.filepath = filepath or self.ngctm_EXE_NAME
        self.path = self.check_path()
        self.pe = self.parse_pe()
        self.sections = {s.Name.strip(self.NULL).decode(): s for s in self.pe.sections}
        self.pe.close()

        try:
            self.data = bytearray(self.path.read_bytes())
        except IOError:
            raise IOError("{} is not a valid file".format(self.path))
        else:
            self.patches = []

    def create_patch(self, patch: Patch):
        patch.__init__(patch.offset, patch.patch_type, self)
        self.patches.append(patch)

    def save(self):
        backup_path = self.path.with_suffix(self.path.suffix+".bak")
        logger.info("Backing up original file at {}".format(backup_path))

        try:
            self.path.replace(backup_path)
        except PermissionError as e:
            raise PermissionError("Permission denied renaming file to {}. Try running as Administrator".format(backup_path))
        except IOError as e:
            raise IOError("Error renaming file to {}".format(backup_path))

        try:
            self.path.write_bytes(self.data)
        except PermissionError as e:
            raise PermissionError("Permission denied writing to new file {}. Try running as Administrator.".format(self.path))
        except IOError:
            raise IOError("Error writing to new file {}".format(self.path))
        else:
            logger.info("Patched file written at {}".format(self.path))

    def apply_all(self):
        logger.info("Applying all patches...")
        for patch in self.patches:
            patch.apply()
        logger.info("All patches applied!")

    def check_path(self):
        path = Path(self.filepath)
        if not path.exists():
            raise FileNotFoundError("File {} does not exist".format(self.filepath))
        if not path.is_file():
            logger.warning("{} is a directory, not a file".format(self.filepath))
            path = path / self.ngctm_EXE_NAME
            logger.warning("Proceeding with assumed file path {}".format(path))
            if not path.exists():
                raise FileNotFoundError("File {} does not exist".format(path))
            if not path.is_file():
                raise FileNotFoundError("{} is a directory, not a file".format(path))
        return path

    def parse_pe(self):
        try:
            pe = pefile.PE(self.path, fast_load=True)
        except pefile.PEFormatError:
            raise pefile.PEFormatError("Not a valid Windows application")

        if pe.NT_HEADERS.Signature != 0x4550:
            raise pefile.PEFormatError("Not a valid PE")

        if pe.FILE_HEADER.Machine != 0x14c:
            raise pefile.PEFormatError("64 bit ngctm not supported")
        return pe

    def __str__(self):
        return self.path


def main():
    print("-" * 64)
    print("ngctm patcher")
    print("-" * 64)

    ngctm_file_path = None
    ngctm = None

    try:
        ngctm = File(ngctm_file_path)
    except (FileNotFoundError, pefile.PEFormatError, IOError) as e:
        logger.error(e)
        exit(1)

    """
    0040ed18 e8 c3 27 ff ff        CALL       FUN_004014e0                                     uint FUN_004014e0(void)
    """

    virtual = 0x0040ed18
    section = ".text"
    offset = virtual - ngctm.sections[section].VirtualAddress + ngctm.sections[section].PointerToRawData - ngctm.pe.OPTIONAL_HEADER.ImageBase
    
    # b = ngctm.data[offset:offset+5]
    # print("orig", [hex(o)[2:] for o in b])

    print("Patching...")

    patch = Patch(offset, 'nop')
    ngctm.create_patch(patch)

    ngctm.apply_all()

    try:
        ngctm.save()
    except (IOError, PermissionError) as e:
        logger.error(e)
        exit(1)

    print("Enjoy! :)")
    print("-" * 64)

if __name__ == "__main__":
    main()
