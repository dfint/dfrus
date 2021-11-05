from ctypes import sizeof

from dfrus.peclasses import ImageDosHeader, ImageFileHeader, ImageDataDirectory, DataDirectory, ImageOptionalHeader


def test_sizes():
    assert sizeof(ImageDosHeader) == 64
    assert sizeof(ImageFileHeader) == 20
    assert sizeof(DataDirectory) == 8
    assert sizeof(ImageDataDirectory) == 8 * 16
    assert sizeof(ImageOptionalHeader) == 224
