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

            print('IMAGE_DOS_HEADER:')
            changes = list(pe1.dos_header.diff(pe2.dos_header))
            if not changes:
                print('No changes')
            else:
                for field, formatter, change in changes:
                    print('%s: changed from %s to %s' % (field, formatter, formatter) % change)

            print('IMAGE_FILE_HEADER:')
            changes = list(pe1.file_header.diff(pe2.file_header))
            if not changes:
                print('No changes')
            else:
                for field, formatter, change in changes:
                    print('%s: changed from %s to %s' % (field, formatter, formatter) % change)

            print('IMAGE_OPTIONAL_HEADER:')
            changes = list(pe1.optional_header.diff(pe2.optional_header))
            if not changes:
                print('No changes')
            else:
                for field, formatter, change in changes:
                    print('%s: changed from %s to %s' % (field, formatter, formatter) % change)

            print("IMAGE_DATA_DIRECTORY'es:")
            changes = list(pe1.data_directory.diff(pe2.data_directory))
            if not changes:
                print('No changes')
            else:
                for field, formatter, change in changes:
                    print('%s: changed from %s to %s' % (field, formatter, formatter) % change)

if __name__ == "__main__":
    main()
