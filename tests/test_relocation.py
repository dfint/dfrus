import io

from dfrus.peclasses import RelocationTable


def test_relocation():
    relocs = [0x123456, 0xdeadbeef]
    table = RelocationTable.build(relocs)
    
    # Test __iter__ method
    assert list(table) == relocs
    
    file = io.BytesIO()
    table.to_file(file)
    
    # Check if size of the table written to the file corresponds with the calculated size
    assert len(file.getbuffer()) == table.size
    
    # Reread table and compare result to the original data
    file.seek(0)
    table = RelocationTable.from_file(file, len(file.getbuffer()))
    
    assert list(table) == relocs
