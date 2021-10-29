import argparse
import os.path
import sys
import warnings

from shutil import copy
from contextlib import contextmanager
from typing import Sequence

from .patchdf import fix_df_exe, load_trans_file
from .peclasses import PortableExecutable


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


@contextmanager
def destination_file_context(src, dest):
    print("Copying '{}'\nTo '{}'...".format(src, dest))
    try:
        copy(src, dest)
    except IOError as ex:
        print("Failed.")
        raise ex
    else:
        print("Success.")
    
    try:
        yield dest
    except Exception as ex:
        # print("Removing '{}'".format(dest))
        # os.remove(dest)
        raise ex


def run(path: str, dest: str, trans_table: Sequence, codepage, original_codepage='cp437',
        dict_slice=None, debug=False, stdout=None, stderr=None):
    if not debug:
        warnings.simplefilter('ignore')
    
    if stdout is not None:
        sys.stdout = stdout

    if stderr is not None:
        sys.stderr = stderr

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
    with destination_file_context(df1, df2):
        with open(df2, "r+b") as fn:
            try:
                pe = PortableExecutable(fn)
            except ValueError:
                raise ValueError("'{}' is broken".format(df2))
            
            if pe.file_header['machine'] != 0x014C:
                raise ValueError("Only 32-bit versions are supported.")
            
            fix_df_exe(fn, pe, codepage, original_codepage, trans_table, debug)


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
    parser.add_argument('-d', '--dict', default='dict.csv', dest='dictionary',
                        help='path to the dictionary file, default=dict.csv')
    parser.add_argument('--debug', action='store_true', help='enable debugging mode')
    parser.add_argument('-c', '--codepage', help='enable given codepage by name')
    parser.add_argument('-oc', '--original_codepage', default='cp437',
                        help='specify original codepage of strings in the executable')
    parser.add_argument('-s', '--slice', help='slice the original dictionary, eg. 0:100',
                        type=lambda s: tuple(int(x) for x in s.split(':')))

    return parser


def _main():
    parser = init_argparser()
    args = parser.parse_args(sys.argv[1:])

    print("Loading translation file...")

    try:
        with open(args.dictionary, encoding='utf-8') as trans:
            trans_table = list(load_trans_file(trans))
    except FileNotFoundError:
        print('Error: "%s" file not found.' % args.dictionary)
    else:
        run(args.path, args.dest, trans_table, args.codepage, args.original_codepage, args.slice, args.debug)


if __name__ == "__main__":
    _main()
