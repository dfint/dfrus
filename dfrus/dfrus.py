import os.path
import sys
from contextlib import contextmanager
from shutil import copy
from typing import Sequence, Tuple, Union, Dict, Iterable

import click

from .dictionary_loaders import load_trans_file
from .logger import get_logger, init_logger
from .patchdf import fix_df_exe
from .peclasses import PortableExecutable


def slice_translation(trans_table: Union[Dict[str, str], Iterable[Tuple[str, str]]], bounds) -> Dict[str, str]:
    log = get_logger()
    if isinstance(trans_table, dict):
        trans_table = list(trans_table.items())
    else:
        trans_table = list(trans_table)
    
    log.info("{} translation pairs loaded.".format(len(trans_table)))

    if not bounds:
        pass
    elif len(bounds) == 1:
        i = bounds[0]
        if 0 <= i < len(trans_table):
            trans_table = [trans_table[i]]
        else:
            log.warning("Warning: Translation index is too high or too low. Using all the translations.")

    elif len(bounds) > 1:
        start_index = bounds[0]
        end_index = bounds[1]

        if not 0 <= start_index <= end_index < len(trans_table):
            log.warning("Warning: Translation indices are too high or too low. Using all the translations.")
        else:
            log.info("Slicing translations (low, mid, high): {}:{}:{}".format(
                start_index, (start_index + end_index) // 2, end_index)
            )
            trans_table = trans_table[start_index:end_index + 1]
            log.info("{} translations left.".format(len(trans_table)))

    return dict(trans_table)


@contextmanager
def destination_file_context(src, dest):
    log = get_logger()
    log.info("Copying '{}' To '{}'...".format(src, dest))
    try:
        copy(src, dest)
    except IOError as ex:
        log.error(f"Failed: {ex}")
        sys.exit()
    else:
        log.info("Success.")
    
    try:
        yield dest
    except Exception as ex:
        raise ex


def run(path: str, dest: str, trans_table: Sequence[Tuple[str, str]], codepage, original_codepage="cp437",
        dict_slice=None, debug=False, stdout=None, stderr=None):

    log = init_logger(stdout, stderr, debug)

    if not path or not os.path.exists(path):
        df1 = "Dwarf Fortress.exe"
        log.debug("Path was not given or doesn't exist. Using defaults: {}".format(df1))
    elif os.path.isdir(path):
        df1 = os.path.join(path, "Dwarf Fortress.exe")  # TODO: rewrite to pathlib.Path
    else:
        df1 = path
        path = os.path.dirname(path)

    if dest:
        dest_path, dest_name = os.path.split(dest)  # TODO: rewrite to pathlib.Path
        if not dest_path:
            dest_path = path
    else:
        dest_path = path
        dest_name = "Dwarf Fortress Patched.exe"

    df2 = os.path.join(dest_path, dest_name)

    if not debug:
        trans_dict = dict(trans_table)
    else:
        trans_dict = slice_translation(trans_table, dict_slice)

    # --------------------------------------------------------
    with destination_file_context(df1, df2):
        with open(df2, "rb+") as fn:
            try:
                pe = PortableExecutable(fn)
            except ValueError:
                raise ValueError("'{}' file is broken".format(df2))
            
            if pe.image_file_header.machine != 0x014C:
                raise ValueError("Only 32-bit versions are supported.")

            try:
                fix_df_exe(fn, pe, codepage, original_codepage, trans_dict)
            except Exception:
                log.exception("An exception occurred")
                raise


class SliceParam(click.ParamType):
    name = "slice"

    def convert(self, value, param, ctx):
        try:
            return tuple(int(x) for x in value.partition(":")[::2])
        except ValueError:
            self.fail(f"{value!r} is not a valid slice", param, ctx)


SLICE_PARAM = SliceParam()


@click.command()
@click.option("-p", "--dfpath", "path", default="Dwarf Fortress.exe", type=click.Path(exists=True, file_okay=True),
              help="path to the DF directory or to the Dwarf Fortress.exe itself")
@click.option("-n", "--destname", "dest", default="Dwarf Fortress Patched.exe",
              help="name of the patched DF executable")
@click.option("-d", "--dict", "dictionary", default="dict.csv", type=click.Path(exists=True, file_okay=True),
              help="path to the dictionary file, default=dict.csv")
@click.option("--debug", is_flag=True, help="enable debugging mode")
@click.option("-c", "--codepage", "codepage", help="enable given codepage by name")
@click.option("-oc", "--original-codepage", "original_codepage", default="cp437",
              help="specify original codepage of strings in the executable")
@click.option("-s", "--slice", "dict_slice", help="slice the original dictionary, eg. 0:100", type=SLICE_PARAM)
def _main(path, dest, dictionary, debug, codepage, original_codepage, dict_slice):
    """A patcher for the hardcoded strings of the Dwarf Fortress"""

    get_logger().info("Loading translation file...")

    with open(dictionary, encoding="utf-8") as trans:
        trans_table = list(load_trans_file(trans))

    run(path, dest, trans_table, codepage, original_codepage, dict_slice, debug)


if __name__ == "__main__":
    _main()
