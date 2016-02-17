import os.path
import argparse
import sys

from shutil import copy
from collections import defaultdict

from extract_strings import extract_strings
from binio import write_string, to_dword, fpeek, fpoke4, fpoke
from peclasses import PortableExecutable, Section, RelocationTable
import patchdf as pd
from patchdf import code, data
from opcodes import *
from machinecode import MachineCode
from disasm import align, join_byte


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
    parser.add_argument('--codepage', help='enable given codepage by name')
    parser.add_argument('-s', '--slice', help='slice the original dictionary, eg. 0:100',
                        type=lambda s: tuple(int(x) for x in s.split(':')))

    return parser


def add_fix(fixes, offset, fix):
    new_code = fix['new_code']
    if offset in fixes:
        old_fix = fixes[offset]
        old_code = old_fix['new_code']
        if bytes(new_code) not in bytes(old_code):
            if isinstance(old_code, MachineCode):
                assert not isinstance(new_code, MachineCode)
                new_code = new_code + old_code
                if 'poke' in old_fix and 'poke' not in fix:
                    fix['poke'] = old_fix['poke']
            else:
                new_code = old_code + new_code
            fix['new_code'] = new_code
            fixes[offset] = fix
        else:
            pass  # Fix is already added, do nothing
    else:
        fixes[offset] = fix

    return fixes


def _main():
    parser = init_argparser()

    args = parser.parse_args(sys.argv[1:])

    debug = args.debug

    path = args.path

    if len(path) == 0 or not os.path.exists(path):
        if debug:
            print("Path was not given or doesn't exist. Using defaults.")
        df1 = "Dwarf Fortress.exe"
    elif os.path.isdir(path):
        df1 = os.path.join(path, "Dwarf Fortress.exe")
    else:
        df1 = path
        path = os.path.dirname(path)

    if args.dest:
        dest_path, dest_name = os.path.split(args.dest)
        if not dest_path:
            dest_path = path
    else:
        dest_path = path
        dest_name = 'Dwarf Fortress Patched.exe'

    df2 = os.path.join(dest_path, dest_name)

    # --------------------------------------------------------
    try:
        with open(df1, "rb"):
            pass
            # TODO: Add necessary check (timedate etc.)
    except OSError:
        print("Unable to open '%s'" % df1)
        sys.exit()

    # --------------------------------------------------------
    print("Loading translation file...")

    encoding = args.codepage if args.codepage else 'cp437'
    try:
        with open(args.dictionary, encoding=encoding) as trans:
            trans_table = pd.load_trans_file(trans)

            if not debug:
                trans_table = dict(trans_table)
            else:
                trans_table = list(trans_table)
                print('%d translation pairs loaded.' % len(trans_table))

                if not args.slice:
                    pass
                elif len(args.slice) == 1:
                    i = args.slice[0]
                    if 0 <= i < len(trans_table):
                        trans_table = [trans_table[i]]
                    else:
                        print('Warning: Translation index is too high or too low. Using all the translations.')

                elif len(args.slice) > 1:
                    start_index = args.slice[0]
                    end_index = args.slice[1]

                    if not 0 <= start_index <= end_index < len(trans_table):
                        print('Warning: Translation indices are too high or too low. Using all the translations.')
                    else:
                        print('Slicing translations (low, mid, high): %d:%d:%d' %
                              (start_index, (start_index + end_index) // 2, end_index))
                        trans_table = trans_table[start_index:end_index + 1]
                        print('Leaving %d translations.' % len(trans_table))

                trans_table = dict(trans_table)
    except FileNotFoundError:
        print('Error: "%s" file not found.' % args.dictionary)
        sys.exit()
    except LookupError as err:
        if str(err).startswith('unknown encoding'):
            print('Error: unknown codepage %r' % encoding)
            sys.exit()
        else:
            raise

    # --------------------------------------------------------
    print("Copying '%s'\nTo '%s'..." % (df1, df2))

    try:
        copy(df1, df2)
    except IOError:
        print("Failed.")
        sys.exit()
    else:
        print("Success.")

    # --------------------------------------------------------
    print("Finding cross-references...")

    try:
        fn = open(df2, "r+b")
    except OSError:
        print("Failed to open '%s'" % df2)
        sys.exit()

    try:
        pe = PortableExecutable(fn)
    except ValueError:
        print("Failed. '%s' is not an executable file." % df2)
        fn.close()
        os.remove(df2)
        sys.exit()

    image_base = pe.optional_header.image_base
    sections = pe.section_table

    # Getting addresses of all relocatable entries
    relocs = set(pe.relocation_table)
    relocs_modified = False

    # Getting cross-references:
    xref_table = pd.get_cross_references(fn, relocs, sections, image_base)

    # --------------------------------------------------------
    if args.codepage and False:
        print("Searching for charmap table...")
        unicode_table_start = b''.join(
            to_dword(item) for item in [0x20, 0x263A, 0x263B, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022]
        )
        
        physical_offset = sections[data].physical_offset
        physical_size = sections[data].physical_size
        data_section = fpeek(fn, physical_offset, physical_size)
        needle = None
        for obj_off in xref_table:
            off = obj_off - physical_offset
            if off >= 0 and off < physical_size:
                buf = data_section[off:off+len(unicode_table_start)]
                if buf == unicode_table_start:
                    needle = obj_off
                    break

        if needle is None:
            fn.close()
            print("Charmap table not found.")
            sys.exit()
        else:
            print("Charmap table found at offset 0x%X" % needle)

        try:
            print("Patching charmap table to %s..." % args.codepage)
            pd.patch_unicode_table(fn, needle, args.codepage)
        except KeyError:
            print("Codepage %s not implemented. Skipping." % args.codepage)
        else:
            print("Done.")

    # --------------------------------------------------------
    if debug:
        print("Preparing additional data section...")

    last_section = sections[-1]

    if last_section.name == b'.new':
        fn.close()
        print("There is '.new' section in the file already.")
        sys.exit()

    file_alignment = pe.optional_header.file_alignment
    section_alignment = pe.optional_header.section_alignment

    # New section prototype
    new_section = Section(
        name=b'.new',
        virtual_size=0,  # for now
        rva=align(last_section.rva + last_section.virtual_size,
                  section_alignment),
        physical_size=0,  # for now
        physical_offset=align(last_section.physical_offset +
                              last_section.physical_size, file_alignment),
        flags=Section.IMAGE_SCN_CNT_INITIALIZED_DATA | Section.IMAGE_SCN_MEM_READ | Section.IMAGE_SCN_MEM_EXECUTE
    )

    new_section_offset = new_section.physical_offset

    # --------------------------------------------------------
    print("Translating...")

    strings = list(extract_strings(fn, xref_table, encoding='cp1252'))

    if debug:
        print("%d strings extracted." % len(strings))

        print("Leaving only strings, which have translations.")
        strings = [x for x in strings if x[1] in trans_table]
        print("%d strings remaining." % len(strings))
        if 0 < len(strings) <= 16:
            print('All remaining strings:')
            for item in strings:
                print("0x%x : %r" % item)

    fixes = dict()
    metadata = dict()

    for off, string in strings:
        if string in trans_table:
            translation = trans_table[string]

            if string == translation:
                continue
            
            if off in refs:
                refs = xref_table[off]

                # Find the earliest reference to the string (even if it is a reference to the middle of the string)
                k = 4
                while off + k in xref_table and k < len(string) + 1:
                    for j, ref in enumerate(refs):
                        mid_refs = xref_table[off + k]
                        delta = ref - mid_refs[0]
                        if len(mid_refs) == 1 and 0 < delta <= 6:  # 6 is the length of mov reg, [imm32]
                            refs[j] = mid_refs[0]
                    k += 4

            aligned_len = align(len(string) + 1)
            is_long = aligned_len < len(translation) + 1
            if not is_long or off not in refs:
                # Overwrite the string with the translation in-place
                write_string(fn, translation,
                             off=off, encoding=encoding,
                             new_len=aligned_len)
                new_str_rva = None
            else:
                # Add the translation to the separate section
                str_off = new_section_offset
                new_str_rva = new_section.offset_to_rva(str_off) + image_base
                new_section_offset = pd.add_to_new_section(fn, new_section_offset,
                                                           bytes(translation + '\0', encoding=encoding))

            # Fix string length for each reference
            for ref in refs:
                ref_rva = sections[code].offset_to_rva(ref)
                try:
                    fix = pd.fix_len(fn, offset=ref, oldlen=len(string), newlen=len(translation),
                                     new_str_rva=new_str_rva)
                except Exception:
                    print('Catched %s exception on string %r at reference 0x%x' % (sys.exc_info()[0], string, ref_rva+image_base))
                    raise

                assert isinstance(fix, dict)
                if 'new_code' in fix:
                    new_code = fix['new_code']
                    assert isinstance(new_code, (bytes, bytearray, MachineCode))
                    src_off = fix['src_off']

                    if 'new_ref' in fix:
                        new_ref = fix['new_ref']
                    elif isinstance(new_code, MachineCode) and list(new_code.absolute_references):
                        new_ref = next(new_code.absolute_references)
                    else:
                        new_ref = None

                    if new_ref is not None:
                        if bytes(new_code)[new_ref:new_ref+4] != to_dword(new_str_rva):
                            raise ValueError('new_ref in fix code is broken for string %r, reference from offset 0x%x' %
                                             (string, ref))

                    add_fix(fixes, src_off, fix)
                elif 'new_ref' in fix:
                    if fpeek(fn, ref + fix['new_ref'], 4) != to_dword(new_str_rva):
                        raise ValueError('new_ref broken for string %r, reference from offset 0x%x' % (string, ref))
                    # Add relocation for the new reference
                    relocs.add(ref_rva + fix['new_ref'])
                    relocs_modified = True

                # Remove relocations of the overwritten references
                if 'deleted_relocs' in fix and fix['deleted_relocs']:
                    for item in fix['deleted_relocs']:
                        relocs.remove(ref_rva + item)
                    relocs_modified = True
                elif is_long:
                    fpoke4(fn, ref, new_str_rva)

                metadata[(string, ref)] = fix

    # Extract information of functions parameters
    functions = defaultdict(dict)
    for item in metadata.values():
        if 'func' in item and item['func'][0] == 'call near':
            offset = item['func'][2]
            address = sections[code].offset_to_rva(offset) + image_base
            if 'str' in item:
                str_param = item['str']
                if 'str' not in functions[offset]:
                    functions[offset]['str'] = str_param
                elif functions[offset]['str'] != str_param:
                    raise ValueError('Function parameter recognition collision for sub_%x: %r != %r' %
                                     (address, functions[offset]['str'], str_param))

            if 'len' in item:
                len_param = item['len']
                if 'len' not in functions[offset]:
                    functions[offset]['len'] = len_param
                elif functions[offset]['len'] != len_param:
                    raise ValueError('Function parameter recognition collision for sub_%x: %r != %r' %
                                     (address, functions[offset]['len'], len_param))
    
    if debug:
        print('\nGuessed function parameters:')
        for func in sorted(functions):
            value = functions[func]
            print('sub_%x: %r' % (sections[code].offset_to_rva(func)+image_base, value))
        print()
    
    # Add strlen before call of functions for strings which length was not fixed
    for string, info in metadata.items():
        if ('fixed' not in info or info['fixed'] == 'no') and 'new_code' not in info:
            func = info.get('func', None)
            if func is not None and func[0] == 'call near':
                if 'len' in functions[func[2]]:
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
                        fix = dict(src_off=src_off, new_code=new_code, dest_off=dest_off)
                        add_fix(fixes, src_off, fix)
            elif debug:
                if 'fixed' in info and info['fixed'] == 'no':
                    print('Length not fixed: %r (reference from 0x%x)' % string, info)
                else:
                    print('Status unknown: %r (reference from 0x%x)' % string, info)

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
        if 'new_ref' in fix or isinstance(mach, MachineCode) and list(mach.absolute_references):
            new_refs = list(mach.absolute_references) if isinstance(mach, MachineCode) else []

            if 'new_ref' in fix:
                new_refs.append(fix['new_ref'])

            relocs.update({hook_rva+item for item in new_refs})
            relocs_modified = True
        
        if 'poke' in fix:
            fpoke(fn, fix['poke'][0], fix['poke'][1])
        
        src_rva = sections[code].offset_to_rva(src_off)
        disp = hook_rva - (src_rva + 4)  # 4 is a size of a displacement itself
        fpoke(fn, src_off, to_dword(disp, signed=True))

    # Write relocation table to the executable
    if relocs_modified:
        reloc_table = RelocationTable.build(relocs)
        new_size = reloc_table.size
        data_directory = pe.data_directory
        reloc_off = sections.rva_to_offset(data_directory.basereloc.virtual_address)
        reloc_size = data_directory.basereloc.size
        fn.seek(reloc_off)
        reloc_table.to_file(fn)
        assert new_size <= reloc_size
        if new_size < reloc_size:
            fn.seek(reloc_off + new_size)
            fn.write(bytes(reloc_size - new_size))
        data_directory.basereloc.size = new_size
        data_directory.rewrite()

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

    fn.close()
    print('Done.')

_main()
