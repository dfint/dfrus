import csv


def load_trans_file(fn):
    def unescape(x):
        return x.replace('\\r', '\r').replace('\\t', '\t')

    dialect = 'unix'

    fn.seek(0)
    reader = csv.reader(fn, dialect)
    for parts in reader:
        if not parts[0]:
            parts = parts[1:]
        assert len(parts) >= 2, parts
        yield unescape(parts[0]), unescape(parts[1])
