#! python3
import sys
import argparse

from peclasses import *


def main():
    parser = argparse.ArgumentParser(add_help=True,
                                     description='A tool to get differences in two Portable Executable binaries.')
    parser.add_argument('unchanged')
    parser.add_argument('changed')

    args = parser.parse_args(sys.argv[1:])
    with open(args.unchanged, 'rb') as unchanged:
        pe1 = PortableExecutable(unchanged)
        with open(args.changed, 'rb') as changed:
            pe2 = PortableExecutable(changed)

            structures = ['dos_header', 'file_header', 'optional_header', 'data_directory']
            for structure in structures:
                print(structure)
                original = getattr(pe1, structure)
                changed = getattr(pe2, structure)
                changes = list(original.diff(changed))
                if not changes:
                    print(' No changes')
                else:
                    for field, formatter, change in changes:
                        print(' - %s=%s' % (field, formatter) % change[0])
                        print(' + %s=%s' % (field, formatter) % change[1])

if __name__ == "__main__":
    main()
