"""Basic tests for the scanner module."""

import pytest
from driverscope.scanner import (
    PRIMITIVE_CLASSES,
    _IMPORT_TO_CLASSES,
    sha256_bytes,
)


def test_primitive_classes_populated():
    assert len(PRIMITIVE_CLASSES) >= 15
    assert "PhysMem-Map" in PRIMITIVE_CLASSES
    assert "MmMapIoSpace" in PRIMITIVE_CLASSES["PhysMem-Map"]


def test_import_to_classes_index():
    assert "MmMapIoSpace" in _IMPORT_TO_CLASSES
    assert "PhysMem-Map" in _IMPORT_TO_CLASSES["MmMapIoSpace"]


def test_sha256_bytes():
    h = sha256_bytes(b"test data")
    assert len(h) == 64
    assert h == "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"


def test_ctl_code_decoding():
    from driverscope.ioctl import CTLCode
    code = CTLCode(0x22200C)
    assert code.device_type == 0x22
    assert code.device_type_name == "FILE_DEVICE_UNKNOWN"
    assert code.method_name == "METHOD_BUFFERED"
