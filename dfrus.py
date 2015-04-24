import sys

cmd = sys.argv

debug = 'debug' in cmd
if debug:
    cmd.remove('debug')

make_call_hooks = False

if len(cmd) > 1:
    path = cmd[1]
else:
    path = ""

import os.path


def abort():
    """

    :rtype : None
    """
    input("Press Enter...")
    sys.exit()

df1 = None

if len(path) == 0 or not os.path.exists(path):
    if debug:
        print("Path was not given or doesn't exist. Using defaults")
    df1 = "Dwarf Fortress.exe"
elif os.path.isdir(path):
    df1 = os.path.join(path, "Dwarf Fortress.exe")
else:
    df1 = path
    path = os.path.dirname(path)

df2 = os.path.join(path, "Dwarf Fortress Rus.exe")

# --------------------------------------------------------
from pe import *

try:
    with open(df1, "rb") as fn:
        pass
        # TODO: Add necessary check (timedate etc.)
except OSError:
    print("Unable to open '%s'" % df1)
    abort()

# --------------------------------------------------------
from patchdf import *
print("Loading translation file...")

trans_filename = "trans.txt"
with open(trans_filename, encoding="cp1251") as trans:
    trans_table = load_trans_file(trans)
    
# --------------------------------------------------------
from shutil import copy
print("Copying '%s'\nTo '%s'..." % (df1, df2))

try:
    copy(df1, df2)
except IOError:
    print("Failed.")
    abort()
else:
    print("Success.")

# --------------------------------------------------------
print("Finding cross-references...")

try:
    fn = open(df2, "r+b")
except OSError:
    print("Failed to open '%s'" % df2)
    abort()

pe_offset = check_pe(fn)

if pe_offset is None:
    print("Failed. '%s' is not an executable file." % df2)
    fn.close()
    os.remove(df2)
    abort()

# from binio import fpeek4u
from pe import *

image_base = fpeek4u(fn, pe_offset+PE_IMAGE_BASE)
sections = get_section_table(fn, pe_offset)

# Getting addresses of all relocatable entries
relocs = get_relocations(fn, sections)
relocs_modified = False

# Getting cross-references:
xref_table = get_cross_references(fn, relocs, sections, image_base)

# --------------------------------------------------------
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
    abort()

patch_unicode_table(fn, needle)

# --------------------------------------------------------
if debug:
    print("Preparing additional data section...")

last_section = sections[-1]

if last_section.name.startswith(b'.rus'):
    fn.close()
    print("There is '.rus' section in the file already.")
    abort()

file_alignment = fpeek4u(fn, pe_offset+PE_FILE_ALIGNMENT)
section_alignment = fpeek4u(fn, pe_offset+PE_SECTION_ALIGNMENT)

from disasm import align

# New section prototype

new_section = Section(
    name='.rus',
    virtual_size=0,  # for now
    rva=align(last_section.rva+last_section.virtual_size,
              section_alignment),
    physical_size=0,  # for now
    physical_offset=align(last_section.physical_offset +
                          last_section.physical_size, file_alignment),
    flags=IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE
)

new_section_offset = new_section.physical_offset

# --------------------------------------------------------
print("Translating...")

from extract_strings import extract_strings

strings = list(extract_strings(fn, xref_table))

if debug:
    print("%d strings extracted.\n" % len(strings))
    # TODO: add slicing of the string list for the debugging purposes

funcs = defaultdict(lambda: defaultdict(list))
fixes = dict()

for off, string in strings:
    if string in trans_table:
        translation = trans_table[string]
        
        if string == translation:
            continue
        
        refs = xref_table[off]
        
        # Find the earliest reference to the string
        k = 4
        while off+k in xref_table and k < len(string)+1:
            for j, ref in enumerate(refs):
                mid_refs = xref_table[off+k]
                delta = ref - mid_refs[0]
                if len(mid_refs) == 1 and 0 < delta <= 6:  # 6 is the length of mov reg, [imm32]
                    refs[j] = mid_refs[0]
            k += 4
        
        aligned_len = align(len(string)+1)
        is_long = aligned_len < len(translation)+1
        if not is_long:
            write_string(fn, translation,
                         off=off, encoding='cp1251',
                         new_len=aligned_len)
            str_off = None
        else:
            str_off = new_section_offset
            new_section_offset = add_to_new_section(fn, new_section_offset,
                                                    bytes(translation + '\0', encoding='cp1251'))

        # Fix string length for each reference
        for ref in refs:
            fix = fix_len(fn, offset=ref, oldlen=len(string), newlen=len(translation))
            if type(fix) is not int:
                # fix_len() failed to fix length
                if len(fix) < 4:
                    if debug:
                        print('Unable to add jump/call hook at 0x%x for |%s|%s| (jump or call to address 0x%x)' %
                              (off_to_rva_ex(fix[0], sections[code]) + image_base,
                               string, translation, off_to_rva_ex(fix[2], sections[code])+image_base))
                else:
                    src_off, newcode, dest_off, op = fix
                    newcode = bytes(newcode)
                    if op == call_near and make_call_hooks:
                        funcs[dest_off][newcode].append(off_to_rva_ex(src_off, sections[code]))
                    else:
                        if src_off in fixes:
                            oldfix = fixes[src_off]
                            oldcode = oldfix[1]
                            if newcode not in oldcode:
                                newcode = oldcode + newcode
                        fixes[src_off] = src_off, newcode, dest_off, op
                fix = -1

            if fix != 0:
                if fix == -2 and debug:
                    print('|%s|%s| <- %x (%x)' %
                          (string, translation, ref, off_to_rva_ex(ref, sections[code])+image_base))
                    print('SUSPICIOUS: Failed to fix length. Probably the code is broken.')

                if is_long:
                    fpoke4(fn, ref, off_to_rva_ex(str_off, new_section)+image_base)
            elif is_long:
                pre = fpeek(fn, ref-3, 3)
                start = ref-get_start(pre)
                x = get_length(fpeek(fn, start, 100), len(string)+1)

                src = off_to_rva_ex(str_off, new_section)+image_base
                mach, new_ref_off = mach_memcpy(src, x[2], len(translation)+1)
                if x['lea'] is not None:
                    mach += mach_lea(*x['lea'])

                start_rva = off_to_rva_ex(start, sections[code])

                if len(mach) > x['length']:
                    # if memcpy code is to long, try to write it into the new section and make call to it
                    mach.append(ret_near)
                    proc = mach
                    dest_off = new_section_offset
                    dest_rva = off_to_rva_ex(dest_off, new_section)
                    disp = dest_rva-(start_rva+5)
                    mach = bytearray((call_near,))+to_bytes(disp, 4)
                    if len(mach) > x['length']:
                        if debug:
                            print('|%s|%s| <- %x (%x)' %
                                  (string, translation, ref, off_to_rva_ex(ref, sections[code])+image_base))
                            print('Replacement machine code is too long (%d against %d).' % (len(mach), x['length']))
                        continue
                    new_sect_off = add_to_new_section(fn, dest_off, proc)
                    new_ref = dest_rva+new_ref_off
                else:
                    new_ref = start_rva+new_ref_off

                # Fix relocations
                # Remove relocations of the overwritten references
                deleted_relocs = x['deleted']
                for i, item in enumerate(deleted_relocs):
                    relocs.remove(item+start_rva)

                # Add relocation for the new reference
                relocs.add(new_ref)

                relocs_modified = True

                # Write replacement code
                mach = pad_tail(mach, x['length'], nop)
                fpoke(fn, start, mach)


def fix_it(_, fix):
    global new_section_offset
    src_off, mach, dest = fix
    hook_off = new_section_offset
    hook_rva = off_to_rva_ex(hook_off, new_section)
    dest_rva = off_to_rva_ex(dest, sections[code])
    disp = dest_rva-(hook_rva+len(mach)+5)  # displacement for jump from the hook
    # Add jump from the hook
    mach += bytearray((jmp_near,)) + to_bytes(disp, 4)
    # Write the hook to the new section
    new_section_offset = add_to_new_section(fn, hook_off, mach)

    src_rva = off_to_rva_ex(src_off, sections[code])
    disp = hook_rva-(src_rva+5)  # displacement for jump to the hook
    fpoke4(fn, src_off+1, disp)

# Delayed fix
for fix in fixes:
    fix_it(fix, fixes[fix])


def add_call_hook(dest, val):
    global new_section_offset
    mach = sum(val.keys(), bytearray())
    hook_off = new_section_offset
    hook_rva = off_to_rva_ex(hook_off, new_section)
    dest_rva = off_to_rva_ex(dest, sections[code])

    # Save the beginning of the function (at least 5 bytes for jump)
    funccode = fpeek(fn, dest, 0x10)
    n = None
    for line in disasm(funccode):
        assert(line.mnemonic != 'db')
        if line.address >= 5:
            n = line.address
            break

    saved_code = funccode[:n]
    mach += saved_code
    disp = dest_rva+len(saved_code)-(hook_rva+len(mach)+5)

    # Jump back to the function
    mach.append(jmp_near)
    mach += to_bytes(disp, 4)
    new_section_offset = add_to_new_section(fn, hook_off, mach)

    # Add jump from the function to the hook
    src_off = dest
    src_rva = off_to_rva_ex(src_off, sections[code])
    disp = hook_rva-(src_rva+5)
    fpoke(fn, src_off, jmp_near)
    fpoke4(fn, src_off+1, disp)

# Adding call hooks
if make_call_hooks:
    for func in funcs:
        add_call_hook(func, funcs[func])



# Write relocation table to the executable
if relocs_modified:
    new_size, reloc_table = relocs_to_table(relocs)
    dd = get_data_directory(fn)
    reloc_off = rva_to_off(dd[DD_BASERELOC][0], sections)

# Add new section to the executable
if new_section_offset > new_section.physical_offset:
    file_size = align(new_section_offset, file_alignment)
    new_section.physical_size = file_size - new_section.physical_offset

    print("Adding new data section...")

    # Align file size
    if file_size > new_section_offset:
        fn.seek(file_size-1)
        fn.write('\0')

    # Set the new section virtual size
    new_section.virtual_size = new_section_offset - new_section.physical_offset

    # Write the new section info
    put_section_info(fn,
                     pe_offset + SIZEOF_PE_HEADER + len(sections)*SIZEOF_IMAGE_SECTION_HEADER,
                     new_section)

    # Fix number of sections
    fpoke2(fn, pe_offset + PE_NUMBER_OF_SECTIONS, len(sections)+1)

    # Fix ImageSize field of the PE header
    fpoke4(fn, pe_offset + PE_SIZE_OF_IMAGE,
           align(new_section.rva + new_section.virtual_size, section_alignment))

fn.close()
print('Done.')