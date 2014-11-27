import sys

cmd = sys.argv

debug = 'debug' in cmd
if debug:
    cmd.remove('debug')

if len(cmd)>1:
    path = cmd[1]
else:
    path = ""

import os.path

def abort():
    input("Press Enter...")
    sys.exit()

df1 = None

if len(path)==0 or not os.path.exists(path):
    if debug:
        print("Path was not given or doesn't exist. Using defaults")
    df1 = "Dwarf Fortress.exe"
elif os.path.isdir(path):
    df1 = os.path.join(path, "Dwarf Fortress.exe")
else:
    df1 = path
    path = os.path.dirname(path)

df2 = os.path.join(path, "Dwarf Fortress Rus.exe")

#--------------------------------------------------------
from pe import *

try:
    with open(df1, "rb") as fn:
        pass
        # TODO: Add necessary check (timedate etc.)
except OSError:
    print("Unable to open '%s'" % df1)
    abort()

#--------------------------------------------------------
from patchdf import *
print("Loading translation file...")

trans_filename = "trans.txt"
with open(trans_filename, encoding="cp1251") as trans:
    trans_table = load_trans_file(trans)
    
#--------------------------------------------------------
from shutil import copy
print("Copying '%s'\nTo '%s'..." % (df1,df2))

try:
    copy(df1,df2)
except IOError:
    print("Failed.")
    abort()
else:
    print("Success.")

#--------------------------------------------------------
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

from binio import fpeek4u
from pe import *

image_base = fpeek4u(fn, pe_offset+PE_IMAGE_BASE)
sections = get_section_table(fn, pe_offset)

# Getting addreses of all relocatable entries
relocs = get_relocations(fn, sections)

# Getting cross-references:
xref_table = get_cross_references(fn, relocs, sections, image_base)

#--------------------------------------------------------
print("Enabling the cyrillic alphabet...")

unicode_table_start = [ 0x20, 0x263A, 0x263B, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022 ]

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

#--------------------------------------------------------
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
    name = '.rus',
    virtual_size = 0, # for now
    rva = align(last_section.rva+last_section.virtual_size,
                section_alignment),
    physical_size = 0, # for now
    physical_offset = align(last_section.physical_offset +
                            last_section.physical_size, file_alignment),
    flags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
            IMAGE_SCN_MEM_EXECUTE
)

#--------------------------------------------------------
print("Translating...")

from extract_strings import extract_strings

strings = list(extract_strings(fn, xref_table))

if debug:
    print("%d strings extracted.\n" % len(strings))
    # TODO: add slicing of the string list for the debugging purposes

funcs = dict()

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
                if len(mid_refs)==1 and delta>0 and delta<=6: # 6 is the length of mov reg, [imm32]
                    refs[j] = mid_refs[0]
            k += 4
        
        aligned_len = align(len(string)+1)
        is_long = aligned_len < len(translation)+1
        if not is_long:
            write_string(fn, translation,
                         off=off, encoding='cp1251',
                         new_len=aligned_len)
        else:
            pass
        
        pass


fn.close()
