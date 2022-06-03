# DFRUS

[![Python package](https://github.com/dfint/dfrus/workflows/Python%20package/badge.svg)](https://github.com/dfint/dfrus/actions?query=workflow%3A"Python+package")
[![codecov](https://codecov.io/gh/dfint/dfrus/branch/develop/graph/badge.svg?token=PKw7KdAswK)](https://codecov.io/gh/dfint/dfrus)
![Warning: Legacy!](https://img.shields.io/badge/Warning-Legacy!-red)

A patcher for a text hard-coded into an executable of the Dwarf Fortress game.

What it does:

- Extracts all hard-coded strings using information from a relocation table of the executable file (`extract_strings.py` module)
- Finds all cross-references to all strings using information from the relocation table (`cross_references.py`)
- Patches short strings in place, places long translations to a new section and fixes references to the string (`patchdf.py`)
- Tries to fix hard-coded string size value (`analyze_and_provide_fix.py`)
- For cases when a string is copied with a series of `mov` commands and tries to replace such code with a more simple code (specifically, with `rep movsd` command)  (`moves_series.py`)
- Patches charmap table to make it possible to show translated text correctly (`search_charmap.py`, `patch_charmap.py`)

Includes:

- <s>Custom parser of the Portable Executable format (see `peclasses.py` module). I tried to migrate to the [pefile](https://github.com/erocarrera/pefile) module, but it turned out that our implementation is faster and easier to use (e.g., IDE shows field names of PE Structures as you type code)</s>  
  Migrated to a separate repository: https://github.com/dfint/peclasses
- Command-line relocation table editor (see `edit_relocs.py`)
- Custom disassembler engine (see `disasm.py` module). It is planned to replace it with some fully functional engine (e.g., [zydis-py](https://github.com/zyantific/zydis-py)), because it needs too much effort to develop.
- Machine code builder class and some simple assembly DSL implementation (only a few assembly commands are implemented yet). See `machine_code_builder.py`, `machine_code_assembler.py`, and `machine_code_utils.py` as a demonstration.
- A metaclass that makes possible to create ctypes structures in a dataclass style. See implementation in `ctypes_annotated_structure.py` module and usage examples in `peclasses.py`.
