from scapy.all import rdpcap

def analyze(filename: str):
    print(filename)
    f = rdpcap(filename)
    found = {}
    for i, row in enumerate(f, start=1):
        rowb = bytes(row)
        starting_byte = rowb[0]
        if starting_byte == 192: # 0xc0
            source = int.from_bytes(rowb[10:16], 'big')
            found[i] = hex(source)
            # print(f"{i}: {hex(source)}")
    return found
