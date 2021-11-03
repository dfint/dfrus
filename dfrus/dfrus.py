import os.path
import sys
import warnings
from contextlib import contextmanager
from shutil import copy
from typing import Sequence, Tuple, Union, Dict, Iterable

import click

from .dictionary_loaders import load_trans_file
from .patchdf import fix_df_exe
from .peclasses import PortableExecutable


def slice_translation(trans_table: Union[Dict[str, str], Iterable[Tuple[str, str]]], bounds) -> Dict[str, str]:
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
        print(f"Failed: {ex}")
        sys.exit()
    else:
        print("Success.")
    
    try:
        yield dest
    except Exception as ex:
        # print("Removing '{}'".format(dest))
        # os.remove(dest)
        raise ex


def run(path: str, dest: str, trans_table: Sequence[Tuple[str, str]], codepage, original_codepage='cp437',
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
        trans_dict = dict(trans_table)
    else:
        trans_dict = slice_translation(trans_table, dict_slice)

    # --------------------------------------------------------
    with destination_file_context(df1, df2):
        with open(df2, "r+b") as fn:
            try:
                pe = PortableExecutable(fn)
            except ValueError:
                raise ValueError("'{}' is broken".format(df2))
            
            if pe.file_header['machine'] != 0x014C:
                raise ValueError("Only 32-bit versions are supported.")
            
            fix_df_exe(fn, pe, codepage, original_codepage, trans_dict, debug)


class SliceParam(click.ParamType):
    name = 'slice'

    def convert(self, value, param, ctx):
        try:
            return tuple(int(x) for x in value.split(':'))
        except ValueError:
            self.fail(f"{value!r} is not a valid slice", param, ctx)


SLICE_PARAM = SliceParam()


@click.command()
@click.option('-p', '--dfpath', 'path', default="Dwarf Fortress.exe",
              help='path to the DF directory or to the Dwarf Fortress.exe itself')
@click.option('-n', '--destname', 'dest', default='Dwarf Fortress Patched.exe',
              help='name of the patched DF executable')
@click.option('-d', '--dict', 'dictionary', default='dict.csv',
              help='path to the dictionary file, default=dict.csv')
@click.option('--debug', is_flag=True, help='enable debugging mode')
@click.option('-c', '--codepage', 'codepage', help='enable given codepage by name')
@click.option('-oc', '--original-codepage', 'original_codepage', default='cp437',
              help='specify original codepage of strings in the executable')
@click.option('-s', '--slice', 'dict_slice', help='slice the original dictionary, eg. 0:100', type=SLICE_PARAM)
def _main(path, dest, dictionary, debug, codepage, original_codepage, dict_slice):
    """A patcher for the hardcoded strings of the Dwarf Fortress"""

    print("Loading translation file...")

    try:
        with open(dictionary, encoding='utf-8') as trans:
            trans_table = list(load_trans_file(trans))
    except FileNotFoundError:
        print('Error: "%s" file not found.' % dictionary)
    else:
        run(path, dest, trans_table, codepage, original_codepage, dict_slice, debug)


if __name__ == "__main__":
    _main()
