import gzip



def handle(str_chunks):
    html = b''
    # while str_chunks:
    #     lstr, str_chunks = str_chunks.split(b'\r\n', 1)
    #     l = int(lstr, 16)
    #     html += str_chunks[:l]
    #     str_chunks = str_chunks[l + 2:]
    # return html
    m = memoryview(str_chunks)
    right = 0
    left = 0
    while len(str_chunks) > right:
        index = str_chunks.index(b'\r\n',right)
        right = index
        l = int(m[left:right].tobytes(),16)
        html += m[right+2:right+2+l]
        right = right + 2 + l +2
        left = right

    return html
if __name__ == '__main__':
    pass

