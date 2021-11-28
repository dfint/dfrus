import io
import sys
from collections import defaultdict, OrderedDict
from operator import itemgetter
from typing import Tuple, Set, Mapping, MutableMapping, List

from .analyze_and_provide_fix import analyze_reference_code
from .binio import fpoke4, fpoke, to_dword
from .cross_references import get_cross_references
from .disasm import align
from .extract_strings import extract_strings
from .logger import get_logger
from .machine_code_assembler import asm
from .machine_code_utils import mach_strlen
from .metadata_objects import Metadata, Fix
from .new_section import add_new_section, add_to_new_section, create_section_blueprint
from .opcodes import *
from .patch_charmap import patch_unicode_table, get_encoder
from .peclasses import Section, RelocationTable, PortableExecutable
from .pretty_printing import myrepr, format_hex_list
from .search_charmap import search_charmap
from .trace_machine_code import FunctionInformation

# from warnings import warn

code_section, rdata_section, data_section = range(3)


def fix_df_exe(file, pe, codepage, original_codepage, trans_table: Mapping[str, str], debug=False):
    log = get_logger()

    log.info("Finding cross-references...")

    image_base = pe.image_optional_header.image_base
    sections = pe.section_table

    # Getting addresses of all relocatable entries
    relocatable_items: Set[int] = set(pe.relocation_table)

    # Getting cross-references:
    xref_table = get_cross_references(file, relocatable_items, sections, image_base)

    if codepage:
        fix_unicode_table(codepage, file, sections, xref_table)

    if debug:
        log.info("Preparing additional data section...")

    last_section = sections[-1]

    if last_section.name == b".new":
        log.error("There is '.new' section in the file already.")
        return

    # New section prototype
    new_section = create_section_blueprint(
        b".new",
        align(last_section.virtual_address + last_section.virtual_size,
              pe.image_optional_header.section_alignment),
        align(last_section.pointer_to_raw_data + last_section.size_of_raw_data,
              pe.image_optional_header.file_alignment),
    )

    new_section_offset = new_section.pointer_to_raw_data

    # --------------------------------------------------------
    log.info("Translating...")

    strings = list(extract_strings(file, xref_table, encoding=original_codepage, arrays=True))

    if debug:
        log.info("{} strings extracted.".format(len(strings)))

        log.info("Leaving only strings, which have translations.")
        strings = [x for x in strings if x[1] in trans_table]
        log.info("{} strings remaining.".format(len(strings)))
        if 0 < len(strings) <= 16:
            log.info("All remaining strings:")
            for offset, string, *_ in strings:
                log.info("0x{:x} : {!r}".format(offset, string))

    encoding = codepage if codepage else "cp437"

    encoder_function = get_encoder(encoding)

    fixes, metadata, new_section_offset, relocs_to_add, relocs_to_remove = process_strings(
        encoder_function, encoding, file, image_base, new_section, new_section_offset,
        sections, strings, trans_table, xref_table
    )

    functions = extract_function_information(image_base, metadata, sections)

    if debug:
        log.debug("\nGuessed function parameters:")
        for address, meta in sorted(functions.items(), key=itemgetter(0)):
            log.debug("sub_{:x}: {!r}".format(sections[code_section].offset_to_rva(address) + image_base, meta))

    not_fixed, status_unknown = add_strlens(fixes, functions, metadata)
    if debug:
        for ref, (string, meta) in sorted(not_fixed.items(), key=lambda x: x[0]):
            log.debug("Length not fixed: {} (reference from 0x{:x})".format(myrepr(string), ref), meta)

        for ref, (string, meta) in sorted(status_unknown.items(), key=lambda x: x[0]):
            log.debug("Status unknown: {} (reference from 0x{:x})".format(myrepr(string), ref), meta)

    new_section_offset = apply_delayed_fixes(fixes, file, new_section, new_section_offset, relocs_to_add, sections)

    # Write relocation table to the executable
    if relocs_to_add or relocs_to_remove:
        if relocs_to_remove - relocatable_items:
            log.warning("Trying to remove some relocations which weren't in the original list: " +
                        format_hex_list(item + image_base for item in (relocs_to_remove - relocatable_items)))

        if debug:
            log.debug("\nRemoved relocations:")
            log.debug(format_hex_list(relocs_to_remove, wrap_at=80))
            log.debug("\nAdded relocations:")
            log.debug(format_hex_list(relocs_to_add, wrap_at=80))

        relocatable_items -= relocs_to_remove
        relocatable_items |= relocs_to_add

        new_section_offset, relocation_table = update_relocation_table(pe, new_section, new_section_offset,
                                                                       relocatable_items)

        relocatable_items = set(relocation_table)

    # Add new section to the executable
    if new_section_offset > new_section.pointer_to_raw_data:
        log.info("Adding new data section...")
        add_new_section(pe, new_section, new_section_offset)

    # Check if the patched file is not broken
    log.info("Final check...")
    pe.reread()
    assert set(pe.relocation_table) == relocatable_items, "Error: relocation table is broken"

    log.info("Done.")


def fix_unicode_table(codepage, fn, sections, xref_table):
    log = get_logger()
    log.info("Searching for charmap table...")
    needle = search_charmap(fn, sections, xref_table)
    if needle is None:
        log.warning("Warning: charmap table not found. Skipping.")
    else:
        log.info("Charmap table found at offset 0x{:X}".format(needle))

        try:
            log.info("Patching charmap table to {}...".format(codepage))
            patch_unicode_table(fn, needle, codepage)
        except KeyError:
            log.warning("Warning: codepage {} not implemented. Skipping.".format(codepage))
        else:
            log.info("Done.")


def process_strings(encoder_function, encoding, fn, image_base, new_section, new_section_offset, sections,
                    strings, trans_table, xref_table) -> \
        Tuple[MutableMapping[int, Fix], MutableMapping[Tuple[str, int], Fix], int, Set[int], Set[int]]:
    # return fixes, metadata, new_section_offset, relocs_to_add, relocs_to_remove

    log = get_logger()

    relocs_to_add: Set[int] = set()
    relocs_to_remove: Set[int] = set()
    fixes: MutableMapping[int, Fix] = defaultdict(Fix)
    metadata: MutableMapping[Tuple[str, int], Fix] = OrderedDict()
    delayed_pokes = dict()
    for off, string, cap_len in strings:
        if string in trans_table:
            translation = trans_table[string]

            if string == translation:
                continue

            if off in xref_table:
                # Find the earliest reference to the string (even if it is a reference to the middle of the string)
                refs = find_earliest_midrefs(off, xref_table, len(string))
            else:
                refs = []

            is_long = cap_len < len(translation) + 1
            original_string_address = sections.offset_to_rva(off) + image_base

            try:
                encoded_translation = encoder_function(translation)[0] + b"\0"
            except UnicodeEncodeError:
                encoded_translation = encoder_function(translation, errors="replace")[0] + b"\0"
                log.warning("Warning: some of characters in a translation strings can't be represented in {}, "
                            "they will be replaced with ? marks.".format(encoding))
                log.warning("{!r}: {!r}".format(string, encoded_translation))

            if not is_long or off not in xref_table:
                # Overwrite the string with the translation in-place
                fpoke(fn, off, encoded_translation.ljust(cap_len, b"\0"))
                string_address = original_string_address
            else:
                # Add the translation to the separate section
                str_off = new_section_offset
                string_address = new_section.offset_to_rva(str_off) + image_base
                new_section_offset = add_to_new_section(fn, new_section_offset, encoded_translation)

            # Fix string length for each reference
            for ref in refs:
                ref_rva = sections.offset_to_rva(ref)
                if 0 <= (ref - sections[code_section].pointer_to_raw_data) < sections[code_section].size_of_raw_data:
                    try:
                        fix = analyze_reference_code(fn, offset=ref, old_len=len(string), new_len=len(translation),
                                                     string_address=string_address,
                                                     original_string_address=original_string_address)
                    except Exception:
                        log.exception("Caught {} exception on a string {!r} (translation {!r}) at reference 0x{:x}"
                                      .format(sys.exc_info()[0], string, translation, ref_rva + image_base))
                        raise
                else:
                    fix = Fix(meta=Metadata(fixed="not needed"))

                meta = fix.meta
                assert meta is not None
                if "cmp reg" in meta.string:
                    # This is probably a bound of an array, not a string reference
                    continue
                elif fix.new_code:
                    src_off = fix.src_off
                    assert src_off is not None
                    fixes[src_off].add_fix(fix)
                else:
                    if fix.added_relocs:
                        # Add relocations of new references of moved items
                        relocs_to_add.update(item + ref_rva for item in fix.added_relocs)

                    if fix.pokes:
                        delayed_pokes.update({off + ref: val for off, val in fix.pokes.items()})

                # Remove relocations of the overwritten references
                if fix.deleted_relocs:
                    relocs_to_remove.update(item + ref_rva for item in fix.deleted_relocs)
                elif is_long and string_address:
                    fpoke4(fn, ref, string_address)

                metadata[(string, ref_rva + image_base)] = fix

    for offset, b in delayed_pokes.items():
        fpoke(fn, offset, b)

    return fixes, metadata, new_section_offset, relocs_to_add, relocs_to_remove


def add_strlens(fixes, functions, metadata):
    """
    Add strlen before call of functions for strings which length was not fixed
    """

    status_unknown = dict()
    not_fixed = dict()

    for string, fix in metadata.items():
        meta: Metadata = fix.meta
        if (meta.fixed is None or meta.fixed == "no") and fix.new_code is None:
            assert meta.func is not None
            func: FunctionInformation = meta.func
            if func is not None and func.info == "call near":
                if functions[func.address].length is not None:
                    src_off = func.address
                    dest_off = func.operand
                    assert src_off is not None
                    src_off += 1
                    code_chunk = None
                    if functions[dest_off].length == "push":
                        # mov [esp+8], ecx
                        code_chunk = asm().byte(mov_rm_reg | 1).modrm(1, Reg.ecx, 4).sib(0, 4, Reg.esp).byte(8)
                    elif functions[dest_off].length == "edi":
                        # mov edi, ecx
                        code_chunk = asm().byte(mov_reg_rm | 1).modrm(3, Reg.edi, Reg.ecx)

                    if code_chunk:
                        new_code = mach_strlen(code_chunk)
                        assert isinstance(dest_off, int)
                        fix = Fix(src_off=src_off, new_code=new_code, dest_off=dest_off)
                        fixes[src_off].add_fix(fix)
                        meta.fixed = "yes"
                    else:
                        meta.fixed = "no"
                else:
                    meta.fixed = "not needed"

            if meta.fixed is None:
                status_unknown[string[1]] = (string[0], meta)
            elif meta.fixed == "no":
                not_fixed[string[1]] = (string[0], meta)

    return not_fixed, status_unknown


def update_relocation_table(pe: PortableExecutable, new_section, new_section_offset, relocation_table) \
        -> Tuple[int, RelocationTable]:
    file = pe.file
    sections = pe.section_table
    reloc_table = RelocationTable.build(relocation_table)
    new_size = reloc_table.size
    data_directory = pe.image_data_directory
    relocation_table_offset = sections.rva_to_offset(data_directory.basereloc.virtual_address)
    relocation_table_size = data_directory.basereloc.size
    relocation_section = sections[sections.which_section(offset=relocation_table_offset)]
    if new_size <= relocation_section.size_of_raw_data:
        file.seek(relocation_table_offset)
        reloc_table.to_file(file)

        if new_size < relocation_table_size:
            # Clear empty bytes after the relocation table
            file.seek(relocation_table_offset + new_size)
            file.write(bytes(relocation_table_size - new_size))

        # Update data directory table
        data_directory.basereloc.size = new_size
        pe.rewrite_data_directory()
    else:
        # Write relocation table to the new section
        with io.BytesIO() as buffer:
            reloc_table.to_file(buffer)

            data_directory.basereloc.size = new_size
            data_directory.basereloc.virtual_address = new_section.offset_to_rva(new_section_offset)
            pe.rewrite_data_directory()
            new_section_offset = add_to_new_section(file, new_section_offset, buffer.getvalue())
    return new_section_offset, relocation_table


def apply_delayed_fixes(fixes, fn, new_section, new_section_offset, relocs_to_add, sections):
    # Delayed fix
    for fix in fixes.values():
        src_off = fix.src_off
        assert src_off is not None
        mach = fix.new_code
        assert mach is not None

        hook_rva = new_section.offset_to_rva(new_section_offset)

        dest_off = dict(mach.get_values()).get("dest", None) or fix.dest_off

        for field_name, value in mach.get_values():
            if value is not None:
                mach.set_value(field_name, sections[code_section].offset_to_rva(value))

        mach.origin_address = hook_rva

        if dest_off is not None:
            dest_rva = sections[code_section].offset_to_rva(dest_off)
            mach.origin_address = hook_rva
            if "dest" in mach.get_values():
                mach.set_values(dest=dest_rva)
            else:
                # Add jump from the hook
                mach.byte(jmp_near).relative_reference(dest_rva, size=4)

        assert mach is not None
        # Write the hook to the new section
        new_section_offset = add_to_new_section(fn, new_section_offset, mach.build(), padding_byte=int3)

        # If there are absolute references in the code, add them to relocation table
        if fix.added_relocs or list(mach.absolute_references):
            new_refs = set(mach.absolute_references)

            if fix.added_relocs:
                new_refs.update(fix.added_relocs)

            relocs_to_add.add_items(hook_rva + item for item in new_refs)

        if fix.pokes:
            for off, b in fix.pokes.items():
                fpoke(fn, off, b)

        src_rva = sections[code_section].offset_to_rva(src_off)
        disp = hook_rva - (src_rva + 4)  # 4 is a size of a displacement itself
        fpoke(fn, src_off, to_dword(disp, signed=True))
    return new_section_offset


def extract_function_information(image_base: int,
                                 metadata: Mapping[Tuple[str, int], Fix],
                                 sections: List[Section]) -> Mapping[int, Metadata]:
    """
    Extract information of functions parameters
    """
    log = get_logger()

    functions: MutableMapping[int, Metadata] = defaultdict(Metadata)
    for fix in metadata.values():
        meta = fix.meta
        assert meta is not None
        if meta.func and meta.func.info == "call near":
            offset = meta.func.address
            assert offset is not None
            address = sections[code_section].offset_to_rva(offset) + image_base
            if meta.string:
                str_param = meta.string
                if not functions[offset].string:
                    functions[offset].string.update(str_param)
                elif str_param not in functions[offset].string:
                    log.warning(
                        "Warning: possible function parameter recognition collision for sub_{:x}: {!r} not in {!r}"
                        .format(address, str_param, functions[offset].string)
                    )
                    functions[offset].string.update(str_param)

            if meta.length is not None:
                len_param = meta.length
                if functions[offset].length is None:
                    functions[offset].length = len_param
                elif functions[offset].length != len_param:
                    raise ValueError("Function parameter recognition collision for sub_{:x}: {!r} != {!r}"
                                     .format(address, functions[offset].length, len_param))

    return functions


def find_earliest_midrefs(offset, xref_table, length):
    increment = 4
    k = increment
    references = xref_table[offset]
    while k < length + 1:
        if offset + k in xref_table:
            for j, ref in enumerate(references):
                mid_refs = xref_table[offset + k]
                for mid_ref in sorted(mid_refs, reverse=True):
                    if mid_ref < ref and ref - mid_ref < 70:  # Empirically picked number
                        references[j] = mid_ref
                        break

        while k + increment >= length + 1 and increment > 1:
            increment //= 2

        k += increment
    return references
