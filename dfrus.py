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

print(hex(image_base))
for section in sections:
    print(section)

# Getting addreses of all relocatable entries
relocs = get_relocations(fn, sections)

# Getting cross-references:
xref_table = get_cross_references(fn, relocs, sections, image_base)

fn.close()
