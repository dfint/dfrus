
def align(n, edge=4):
    return (n+edge-1) & (-edge)
