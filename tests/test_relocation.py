import io

from dfrus.peclasses import RelocationTable


def test_relocation():
    relocs = [0x123456, 0xdeadbeef]
    table = RelocationTable.build(relocs)
    print(table._table)
    # Test __iter__ method
    assert list(table) == relocs
    
    file = io.BytesIO()
    table.to_file(file)
    assert len(file.getbuffer()) == table.size
    
    # Test if the table written to a file is the same as before
    file.seek(0)
    table = RelocationTable.from_file(file, len(file.getbuffer()))
    
    assert list(table) == relocs
