import argparse
import codecs
import io
import os.path
import sys
import textwrap
import warnings
from collections import defaultdict, OrderedDict
from shutil import copy

from . import patchdf as pd
from .binio import to_dword, fpoke4, fpoke
from .disasm import align, join_byte
from .extract_strings import extract_strings
from .machinecode import MachineCode
from .opcodes import *
from .patch_charmap import search_charmap, patch_unicode_table, get_codepages, get_encoder
from .patchdf import code, Fix, Metadata
from .peclasses import PortableExecutable, Section, RelocationTable


def init_argparser():
    parser = argparse.ArgumentParser(
            add_help=True,
            description='A patcher for the hardcoded strings of the Dwarf Fortress')
    parser.add_argument('-p', '--dfpath', dest='path',
                        default='Dwarf Fortress.exe',
                        help='path to the DF directory or to the Dwarf Fortress.exe itself, '
                             'default="Dwarf Fortress.exe"')
    parser.add_argument('-n', '--destname', dest='dest',
                        default='Dwarf Fortress Patched.exe',
                        help='name of the patched DF executable, default="Dwarf Fortress Patched.exe"')
    parser.add_argument('-d', '--dict', default='dict.txt', dest='dictionary',
                        help='path to the dictionary file, default=dict.txt')
    parser.add_argument('--debug', action='store_true', help='enable debugging mode')
    parser.add_argument('-c', '--codepage', help='enable given codepage by name')
    parser.add_argument('-oc', '--original_codepage', default='cp437',
                        help='specify original codepage of strings in the executable')
    parser.add_argument('-s', '--slice', help='slice the original dictionary, eg. 0:100',
                        type=lambda s: tuple(int(x) for x in s.split(':')))

    return parser


def myrepr(s):
    text = repr(s)
    if sys.stdout:
        b = text.encode(sys.stdout.encoding, 'backslashreplace')
        text = b.decode(sys.stdout.encoding, 'strict')
    return text


def find_earliest_midrefs(offset, xref_table, length):
    increment = 4
    k = increment
    references = xref_table[offset]
    while k < length + 1:
        if offset + k in xref_table:
            for j, ref in enumerate(references):
                mid_refs = xref_table[offset + k]
                for mid_ref in reversed(sorted(mid_refs)):
                    if mid_ref < ref and ref - mid_ref < 70:  # Empyrically picked number
                        references[j] = mid_ref
                        break
        
        while k + increment >= length + 1 and increment > 1:
            increment /= 2
        
        k += increment
    return references


def int_list_to_hex_str(s):
    return ', '.join(hex(x) for x in sorted(s))


def fix_df_exe(fn, pe, codepage, original_codepage, trans_table, debug=False):
    print("Finding cross-references...")
    
    image_base = pe.optional_header.image_base
    sections = pe.section_table

    # Getting addresses of all relocatable entries
    relocs = set(pe.relocation_table)
    relocs_to_add = set()
    relocs_to_remove = set()

    # Getting cross-references:
    xref_table = pd.get_cross_references(fn, relocs, sections, image_base)

    # --------------------------------------------------------
    if codepage:
        print("Searching for charmap table...")
        needle = search_charmap(fn, sections, xref_table)
        
        if needle is None:
            print("Warning: charmap table not found. Skipping.")
        else:
            print("Charmap table found at offset 0x%X" % needle)

            try:
                print("Patching charmap table to %s..." % codepage)
                patch_unicode_table(fn, needle, codepage)
            except KeyError:
                print("Warning: codepage %s not implemented. Skipping." % codepage)
            else:
                print("Done.")

    # --------------------------------------------------------
    if debug:
        print("Preparing additional data section...")

    last_section = sections[-1]

    if last_section.name == b'.new':
        print("There is '.new' section in the file already.")
        return

    file_alignment = pe.optional_header.file_alignment
    section_alignment = pe.optional_header.section_alignment

    # New section prototype
    new_section = Section(
        name=b'.new',
        virtual_size=0,  # for now
        rva=align(last_section.rva + last_section.virtual_size,
                  section_alignment),
        physical_size=0xFFFFFFFF,  # for now
        physical_offset=align(last_section.physical_offset +
                              last_section.physical_size, file_alignment),
        flags=Section.IMAGE_SCN_CNT_INITIALIZED_DATA | Section.IMAGE_SCN_MEM_READ | Section.IMAGE_SCN_MEM_EXECUTE
    )

    new_section_offset = new_section.physical_offset

    # --------------------------------------------------------
    print("Translating...")

    strings = list(extract_strings(fn, xref_table, encoding=original_codepage, arrays=True))

    if debug:
        print("%d strings extracted." % len(strings))

        print("Leaving only strings, which have translations.")
        strings = [x for x in strings if x[1] in trans_table]
        print("%d strings remaining." % len(strings))
        if 0 < len(strings) <= 16:
            print('All remaining strings:')
            for meta in strings:
                print("0x{:x} : {!r}".format(*meta[:2]))

    fixes = defaultdict(Fix)
    metadata = OrderedDict()  # type: {tuple: Fix}
    delayed_pokes = dict()
    
    encoding = codepage if codepage else 'cp437'

    try:
        encoder_function = codecs.getencoder(encoding)
    except LookupError as ex:
        if encoding in get_codepages():
            encoder_function = get_encoder(encoding)
        else:
            raise ex
    
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
                encoded_translation = encoder_function(translation) + b'\0'
            except UnicodeEncodeError:
                encoded_translation = encoder_function(translation, errors='replace') + b'\0'
                print("Warning: some of characters in a translation strings can't be represented in {}, "
                      "they will be replaced with ? marks.".format(encoding))
                print("{!r}: {!r}".format(string, encoded_translation))
            
            if not is_long or off not in xref_table:
                # Overwrite the string with the translation in-place
                fpoke(fn, off, encoded_translation.ljust(cap_len, b'\0'))
                string_address = original_string_address
            else:
                # Add the translation to the separate section
                str_off = new_section_offset
                string_address = new_section.offset_to_rva(str_off) + image_base
                new_section_offset = pd.add_to_new_section(fn, new_section_offset, encoded_translation)

            # Fix string length for each reference
            for ref in refs:
                ref_rva = sections.offset_to_rva(ref)
                if 0 <= (ref - sections[code].physical_offset) < sections[code].physical_size:
                    try:
                        fix = pd.fix_len(fn, offset=ref, oldlen=len(string), newlen=len(translation),
                                         string_address=string_address,
                                         original_string_address=original_string_address)
                    except Exception:
                        print('Catched %s exception on string %r at reference 0x%x' %
                              (sys.exc_info()[0], string, ref_rva + image_base))
                        raise
                else:
                    fix = Fix(meta=Metadata(fixed='not needed'))

                meta = fix.meta
                if meta.str == 'cmp reg':
                    # This is probably a bound of an array, not a string reference
                    continue
                elif 'new_code' in fix:
                    new_code = fix['new_code']
                    assert isinstance(new_code, (bytes, bytearray, MachineCode))
                    src_off = fix['src_off']

                    fixes[src_off].add_fix(fix)
                else:
                    if 'added_relocs' in fix:
                        # Add relocations of new references of moved items
                        relocs_to_add.update(item + ref_rva for item in fix['added_relocs'])

                    if 'pokes' in fix:
                        delayed_pokes.update(fix['pokes'])

                # Remove relocations of the overwritten references
                if 'deleted_relocs' in fix and fix['deleted_relocs']:
                    relocs_to_remove.update(item + ref_rva for item in fix['deleted_relocs'])
                elif is_long and string_address:
                    fpoke4(fn, ref, string_address)

                metadata[(string, ref_rva+image_base)] = fix

    for offset, b in delayed_pokes.items():
        fpoke(fn, offset, b)

    # Extract information of functions parameters
    functions = defaultdict(Metadata)
    for fix in metadata.values():
        meta = fix.meta
        assert isinstance(meta, Metadata)
        if meta.func and meta.func[0] == 'call near':
            offset = meta.func[2]
            address = sections[code].offset_to_rva(offset) + image_base
            if meta.str:
                str_param = meta.str
                if functions[offset].str is None:
                    functions[offset].str = {str_param}
                elif str_param not in functions[offset].str:
                    print('Warning: possible function parameter recognition collision for sub_%x: %r not in %r' %
                          (address, str_param, functions[offset].str))
                    functions[offset].str.add(str_param)

            if meta.len is not None:
                len_param = meta.len
                if functions[offset].len is None:
                    functions[offset].len = len_param
                elif functions[offset].len != len_param:
                    raise ValueError('Function parameter recognition collision for sub_%x: %r != %r' %
                                     (address, functions[offset].len, len_param))
    
    if debug:
        print('\nGuessed function parameters:')
        for func in sorted(functions):
            value = functions[func]
            print('sub_%x: %r' % (sections[code].offset_to_rva(func)+image_base, value))
        print()
    
    status_unknown = dict()
    not_fixed = dict()
    
    # Add strlen before call of functions for strings which length was not fixed
    for string, fix in metadata.items():
        meta = fix.meta
        if (meta.fixed is None or meta.fixed == 'no') and fix.new_code is None:
            func = meta.func
            if func is not None and func[0] == 'call near':
                if functions[func[2]].len is not None:
                    _, src_off, dest_off = func
                    src_off += 1
                    code_chunk = None
                    if functions[dest_off]['len'] == 'push':
                        # mov [esp+8], ecx
                        code_chunk = (mov_rm_reg | 1, join_byte(1, Reg.ecx, 4), join_byte(0, 4, Reg.esp), 8)
                    elif functions[dest_off]['len'] == 'edi':
                        code_chunk = (mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))  # mov edi, ecx
                    
                    if code_chunk:
                        new_code = pd.mach_strlen(code_chunk)
                        fix = Fix(src_off=src_off, new_code=new_code, dest_off=dest_off)
                        fixes[src_off].add_fix(fix)
                        meta.fixed = 'yes'
                    else:
                        meta.fixed = 'no'
                else:
                    meta.fixed = 'not needed'
            
            if debug:
                if meta.fixed is None:
                    status_unknown[string[1]] = (string[0], meta)
                elif meta.fixed == 'no':
                    not_fixed[string[1]] = (string[0], meta)
    
    if debug:
        for ref, (string, meta) in sorted(not_fixed.items(), key=lambda x: x[0]):
            print('Length not fixed: %s (reference from 0x%x)' % (myrepr(string), ref), meta)
        
        print()
        
        for ref, (string, meta) in sorted(status_unknown.items(), key=lambda x: x[0]):
            print('Status unknown: %s (reference from 0x%x)' % (myrepr(string), ref), meta)

    hook_off = None

    # Delayed fix
    for fix in fixes.values():
        src_off = fix['src_off']
        mach = fix['new_code']

        hook_off = new_section_offset
        hook_rva = new_section.offset_to_rva(hook_off)

        dest_off = mach.fields.get('dest', None) if isinstance(mach, MachineCode) else fix.get('dest_off', None)
        
        if isinstance(mach, MachineCode):
            for field, value in mach.fields.items():
                if value is not None:
                    mach.fields[field] = sections[code].offset_to_rva(value)
            mach.origin_address = hook_rva
        
        if dest_off is not None:
            dest_rva = sections[code].offset_to_rva(dest_off)
            if isinstance(mach, MachineCode):
                mach.fields['dest'] = dest_rva
            else:
                disp = dest_rva - (hook_rva + len(mach) + 5)  # 5 is a size of jmp near + displacement
                # Add jump from the hook
                mach += bytes((jmp_near,)) + to_dword(disp, signed=True)

        # Write the hook to the new section
        new_section_offset = pd.add_to_new_section(fn, hook_off, bytes(mach), padding_byte=int3)

        # If there are absolute references in the code, add them to relocation table
        if 'added_relocs' in fix or isinstance(mach, MachineCode) and list(mach.absolute_references):
            new_refs = set(mach.absolute_references) if isinstance(mach, MachineCode) else set()

            if 'added_relocs' in fix:
                new_refs.update(fix['added_relocs'])

            relocs_to_add.update(hook_rva + item for item in new_refs)
        
        if 'pokes' in fix:
            for off, b in fix['pokes'].items():
                fpoke(fn, off, b)
        
        src_rva = sections[code].offset_to_rva(src_off)
        disp = hook_rva - (src_rva + 4)  # 4 is a size of a displacement itself
        fpoke(fn, src_off, to_dword(disp, signed=True))

    # Write relocation table to the executable
    if relocs_to_add or relocs_to_remove:
        if relocs_to_remove - relocs:
            warnings.warn("Trying to remove some relocations which weren't in the original list: " +
                          int_list_to_hex_str(item + image_base for item in (relocs_to_remove - relocs)))

        relocs -= relocs_to_remove
        relocs |= relocs_to_add
        if debug:
            print("\nRemoved relocations:")
            print("[%s]" % '\n'.join(textwrap.wrap(int_list_to_hex_str(relocs_to_remove), 80)))
            print("\nAdded relocations:")
            print("[%s]" % '\n'.join(textwrap.wrap(int_list_to_hex_str(relocs_to_add), 80)))
        
        reloc_table = RelocationTable.build(relocs)
        new_size = reloc_table.size
        data_directory = pe.data_directory
        reloc_off = sections.rva_to_offset(data_directory.basereloc.virtual_address)
        reloc_size = data_directory.basereloc.size
        reloc_section = sections[sections.which_section(offset=reloc_off)]
        
        if new_size <= reloc_section.physical_size:
            fn.seek(reloc_off)
            reloc_table.to_file(fn)
            
            if new_size < reloc_size:
                # Clear empty bytes after the relocation table
                fn.seek(reloc_off + new_size)
                fn.write(bytes(reloc_size - new_size))
            
            data_directory.basereloc.size = new_size
            data_directory.rewrite()
        else:
            # Write relocation table to the new section
            with io.BytesIO() as buffer:
                reloc_table.to_file(buffer)
                
                data_directory.basereloc.size = new_size
                data_directory.basereloc.virtual_address = new_section.offset_to_rva(new_section_offset)
                data_directory.rewrite()
                
                new_section_offset = pd.add_to_new_section(fn, hook_off, buffer.getvalue())
        
        pe.reread()
        assert set(pe.relocation_table) == relocs

    # Add new section to the executable
    if new_section_offset > new_section.physical_offset:
        file_size = align(new_section_offset, file_alignment)
        new_section.physical_size = file_size - new_section.physical_offset

        print("Adding new data section...")

        # Align file size
        if file_size > new_section_offset:
            fn.seek(file_size - 1)
            fn.write(b'\0')

        # Set the new section virtual size
        new_section.virtual_size = new_section_offset - new_section.physical_offset

        # Write the new section info
        fn.seek(pe.nt_headers.offset + pe.nt_headers.sizeof() + len(sections) * Section.sizeof())
        new_section.write(fn)

        # Fix number of sections
        pe.file_header.number_of_sections = len(sections) + 1
        # Fix ImageSize field of the PE header
        pe.optional_header.size_of_image = align(new_section.rva + new_section.virtual_size, section_alignment)

        pe.file_header.rewrite()
        pe.optional_header.rewrite()

    print('Done.')


def slice_translation(trans_table, bounds):
    if isinstance(trans_table, dict):
        trans_table = list(trans_table.items())
    else:
        trans_table = list(trans_table)
    
    print('%d translation pairs loaded.' % len(trans_table))

    if not bounds:
        pass
    elif len(bounds) == 1:
        i = bounds[0]
        if 0 <= i < len(trans_table):
            trans_table = [trans_table[i]]
        else:
            print('Warning: Translation index is too high or too low. Using all the translations.')

    elif len(bounds) > 1:
        start_index = bounds[0]
        end_index = bounds[1]

        if not 0 <= start_index <= end_index < len(trans_table):
            print('Warning: Translation indices are too high or too low. Using all the translations.')
        else:
            print('Slicing translations (low, mid, high): %d:%d:%d' %
                  (start_index, (start_index + end_index) // 2, end_index))
            trans_table = trans_table[start_index:end_index + 1]
            print('Leaving %d translations.' % len(trans_table))

    return dict(trans_table)


def run(path: str, dest: str, trans_table: iter, codepage, original_codepage='cp437',
        dict_slice=None, debug=False, stdout=None):
    if not debug:
        warnings.simplefilter('ignore')
    
    if stdout is not None:
        sys.stdout = stdout

    if not path or not os.path.exists(path):
        if debug:
            print("Path was not given or doesn't exist. Using defaults.")
        df1 = "Dwarf Fortress.exe"
    elif os.path.isdir(path):
        df1 = os.path.join(path, "Dwarf Fortress.exe")
    else:
        df1 = path
        path = os.path.dirname(path)

    if dest:
        dest_path, dest_name = os.path.split(dest)
        if not dest_path:
            dest_path = path
    else:
        dest_path = path
        dest_name = 'Dwarf Fortress Patched.exe'

    df2 = os.path.join(dest_path, dest_name)

    if not debug:
        trans_table = dict(trans_table)
    else:
        trans_table = slice_translation(trans_table, dict_slice)

    # --------------------------------------------------------
    print("Copying '%s'\nTo '%s'..." % (df1, df2))

    try:
        copy(df1, df2)
    except IOError:
        print("Failed.")
        return
    else:
        print("Success.")

    # --------------------------------------------------------
    try:
        fn = open(df2, "r+b")
        try:
            pe = PortableExecutable(fn)
        except ValueError:
            print("Failed. '%s' is not an executable file." % df2)
            fn.close()
            os.remove(df2)
            return
        
        fix_df_exe(fn, pe, codepage, original_codepage, trans_table, debug)
        
        fn.close()
        
    except OSError:
        print("Failed to open '%s'" % df2)


def _main():
    parser = init_argparser()
    args = parser.parse_args(sys.argv[1:])

    print("Loading translation file...")

    try:
        with open(args.dictionary, encoding='utf-8') as trans:
            trans_table = list(pd.load_trans_file(trans))
    except FileNotFoundError:
        print('Error: "%s" file not found.' % args.dictionary)
    else:
        run(args.path, args.dest, trans_table, args.codepage, args.original_codepage, args.slice, args.debug)


if __name__ == "__main__":
    _main()
