import sys
import os.path
import argparse

from shutil import copy
from collections import defaultdict, Sequence

from disasm import align
from extract_strings import extract_strings
from binio import fpeek4u, write_string
from peclasses import PortableExecutable, Section, RelocationTable
from patchdf import *
from opcodes import *

parser = argparse.ArgumentParser(add_help=True, description='A patcher for the hardcoded strings of the Dwarf Fortress')
parser.add_argument('-p', '--dfpath', dest='path',
                    default='Dwarf Fortress.exe',
                    help='path to the DF directory or to the Dwarf Fortress.exe itself, default="Dwarf Fortress.exe"')
parser.add_argument('-n', '--destname', dest='dest',
                    default='Dwarf Fortress Patched.exe',
                    help='name of the patched DF executable, default="Dwarf Fortress Patched.exe"')
parser.add_argument('-d', '--dict', default='dict.txt', dest='dictionary',
                    help='path to the dictionary file, default=dict.txt')
parser.add_argument('--debug', action='store_true', help='enable debugging mode')
parser.add_argument('--cyr', action='store_true', help='enable cyrillic cp1251 codepage')
parser.add_argument('-s', '--slice', help='slice the original dictionary, eg. 0:100',
                    type=lambda s: tuple(int(x) for x in s.split(':')))

args = parser.parse_args(sys.argv[1:])

debug = args.debug

make_call_hooks = False

path = args.path
df1 = None

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
    with open(df1, "rb") as fn:
        pass
        # TODO: Add necessary check (timedate etc.)
except OSError:
    print("Unable to open '%s'" % df1)
    sys.exit()

# --------------------------------------------------------
print("Loading translation file...")

encoding = 'cp1251' if args.cyr else 'cp437'
try:
    with open(args.dictionary, encoding=encoding) as trans:
        trans_table = load_trans_file(trans)

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
xref_table = get_cross_references(fn, relocs, sections, image_base)

# --------------------------------------------------------
if args.cyr:
    print("Enabling the cyrillic alphabet...")

    unicode_table_start = [0x20, 0x263A, 0x263B, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022]

    needle = None
    for obj_off in xref_table:
        buf = fpeek4u(fn, obj_off, len(unicode_table_start))
        if buf == unicode_table_start:
            needle = obj_off
            break

    if needle is None:
        fn.close()
        print("Unicode table not found.")
        sys.exit()

    patch_unicode_table(fn, needle)

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

strings = list(extract_strings(fn, xref_table))

if debug:
    print("%d strings extracted." % len(strings))

    print("Leaving only strings, which have translations.")
    strings = [x for x in strings if x[1] in trans_table]
    print("%d strings remaining." % len(strings))
    if 0 < len(strings) <= 16:
        print('All remaining strings:')
        for item in strings:
            print("0x%x : %r" % item)

funcs = defaultdict(lambda: defaultdict(list))
fixes = dict()

for off, string in strings:
    if string in trans_table:
        translation = trans_table[string]

        if string == translation:
            continue

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
        if not is_long:
            # Overwrite the string with the translation in-place
            write_string(fn, translation,
                         off=off, encoding=encoding,
                         new_len=aligned_len)
            str_off = None
        else:
            # Add the translation to the separate section
            str_off = new_section_offset
            new_section_offset = add_to_new_section(fn, new_section_offset,
                                                    bytes(translation + '\0', encoding=encoding))

        # Fix string length for each reference
        for ref in refs:
            fix = fix_len(fn, offset=ref, oldlen=len(string), newlen=len(translation))
            if isinstance(fix, Sequence):
                # fix_len() failed to fix length
                if len(fix) < 4:
                    if debug:
                        print('Unable to add jump/call hook at 0x%x for |%s|%s| (jump or call to address 0x%x)' %
                              (sections[code].offset_to_rva(fix[0]) + image_base,
                               string, translation, sections[code].offset_to_rva(fix[2]) + image_base))
                else:
                    src_off, new_code, dest_off, op = fix
                    new_code = bytes(new_code)
                    if op == call_near and make_call_hooks:
                        funcs[dest_off][new_code].append(sections[code].offset_to_rva(src_off))
                    else:
                        if src_off in fixes:
                            old_fix = fixes[src_off]
                            old_code = old_fix[1]
                            if new_code not in old_code:
                                new_code = old_code + new_code
                        fixes[src_off] = src_off, new_code, dest_off, op
                fix = -1

            if fix != 0:
                if fix == -2 and debug:
                    print('|%s|%s| <- %x (%x)' %
                          (string, translation, ref, sections[code].offset_to_rva(ref) + image_base))
                    print('SUSPICIOUS: Failed to fix length. Probably the code is broken.')

                if is_long:
                    fpoke4(fn, ref, new_section.offset_to_rva(str_off) + image_base)
            elif is_long:
                pre = fpeek(fn, ref - 3, 3)
                start = ref - get_start(pre)
                x = get_length(fpeek(fn, start, 100), len(string) + 1)
                src = new_section.offset_to_rva(str_off) + image_base
                mach, new_ref_off = mach_memcpy(src, x['dest'], len(translation) + 1)
                if x['lea'] is not None:
                    mach += mach_lea(**x['lea'])

                start_rva = sections[code].offset_to_rva(start)

                if len(mach) > x['length']:
                    # if memcpy code is to long, try to write it into the new section and make call to it
                    mach.append(ret_near)
                    proc = mach
                    dest_off = new_section_offset
                    dest_rva = new_section.offset_to_rva(dest_off)
                    disp = dest_rva - (start_rva + 5)
                    mach = bytearray((call_near,)) + disp.to_bytes(4, byteorder='little')
                    if len(mach) > x['length']:
                        if debug:
                            print('|%s|%s| <- %x (%x)' %
                                  (string, translation, ref, sections[code].offset_to_rva(ref) + image_base))
                            print('Replacement machine code is too long (%d against %d).' % (len(mach), x['length']))
                        continue
                    new_sect_off = add_to_new_section(fn, dest_off, proc)
                    new_ref = dest_rva + new_ref_off
                else:
                    new_ref = start_rva + new_ref_off

                # Fix relocations
                # Remove relocations of the overwritten references
                deleted_relocs = x['deleted']
                for i, item in enumerate(deleted_relocs):
                    relocs.remove(item + start_rva)

                # Add relocation for the new reference
                relocs.add(new_ref)

                relocs_modified = True

                # Write replacement code
                mach = pad_tail(mach, x['length'], nop)
                fpoke(fn, start, mach)


# Delayed fix
for fix in fixes:
    src_off, mach, dest, _ = fixes[fix]
    hook_off = new_section_offset
    hook_rva = new_section.offset_to_rva(hook_off)
    dest_rva = sections[code].offset_to_rva(dest)
    disp = dest_rva - (hook_rva + len(mach) + 5)  # displacement for jump from the hook
    # Add jump from the hook
    mach += bytearray((jmp_near,)) + disp.to_bytes(4, byteorder='little', signed=True)
    # Write the hook to the new section
    new_section_offset = add_to_new_section(fn, hook_off, mach)

    src_rva = sections[code].offset_to_rva(src_off)
    disp = hook_rva - (src_rva + 5)  # displacement for jump to the hook
    fpoke(fn, src_off + 1, disp.to_bytes(4, byteorder='little', signed=True))


def add_call_hook(dest, val):
    global new_section_offset
    mach = sum(val.keys(), bytearray())  # Flatten and convert to bytearray()
    hook_off = new_section_offset
    hook_rva = new_section.offset_to_rva(hook_off)
    dest_rva = sections[code].offset_to_rva(dest)

    # Save the beginning of the function (at least 5 bytes for jump)
    func_start = fpeek(fn, dest, 0x10)
    n = None
    for line in disasm(func_start):
        assert (line.mnemonic != 'db')
        if line.address >= 5:
            n = line.address
            break

    func_start = func_start[:n]
    mach += func_start
    disp = dest_rva + len(func_start) - (hook_rva + len(mach) + 5)

    # Jump back to the function
    mach.append(jmp_near)
    mach += disp.to_bytes(4, byteorder='little', signed=True)
    new_section_offset = add_to_new_section(fn, hook_off, mach)

    # Add jump from the function to the hook
    src_off = dest
    src_rva = sections[code].offset_to_rva(src_off)
    disp = hook_rva - (src_rva + 5)
    fpoke(fn, src_off, jmp_near)
    fpoke(fn, src_off + 1, disp.to_bytes(4, byteorder='little', signed=True))


# Adding call hooks
if make_call_hooks:
    for func in funcs:
        add_call_hook(func, funcs[func])


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
