#!/usr/bin/env python3
"""Writes the decoding tables of Sovite.Charset (lib/charset/tables/) from
Python's codecs. Run it again only to change the set of charsets:

    python3 scripts/charset_tables.py

Formats, all integers big-endian:

  single-byte  128 x u16: the code point of each byte 0x80..0xFF, 0 for none.
  double-byte  "D", u8 lead_min, u8 lead_max, u8 trail_min, u8 trail_max,
               128 x u16 for the single bytes 0x80..0xFF (0: a lead byte or
               invalid), then (lead_max-lead_min+1) x (trail_max-trail_min+1)
               x u16 for the two-byte sequences, 0 for none.
  gb18030      "R", u16 count, then count x (u32 first index, u32 first code
               point, u32 length): the four-byte sequences of the BMP, by the
               linear index of GB 18030 (the two-byte table is gbk-like).
"""
import codecs
import os
import struct

OUT = os.path.join(os.path.dirname(__file__), "..", "lib", "charset", "tables")

SINGLE = {
    "iso-8859-2": "iso8859_2", "iso-8859-3": "iso8859_3", "iso-8859-4": "iso8859_4",
    "iso-8859-5": "iso8859_5", "iso-8859-6": "iso8859_6", "iso-8859-7": "iso8859_7",
    "iso-8859-8": "iso8859_8", "iso-8859-10": "iso8859_10", "iso-8859-13": "iso8859_13",
    "iso-8859-14": "iso8859_14", "iso-8859-15": "iso8859_15", "iso-8859-16": "iso8859_16",
    "windows-874": "cp874", "windows-1250": "cp1250", "windows-1251": "cp1251",
    "windows-1252": "cp1252", "windows-1253": "cp1253", "windows-1254": "cp1254",
    "windows-1255": "cp1255", "windows-1256": "cp1256", "windows-1257": "cp1257",
    "windows-1258": "cp1258", "koi8-r": "koi8_r", "koi8-u": "koi8_u", "ibm866": "cp866",
    "macintosh": "mac_roman",
}

# (name, codec, lead range, trail range)
DOUBLE = {
    "gbk": ("gbk", (0x81, 0xFE), (0x40, 0xFE)),
    "gb18030": ("gb18030", (0x81, 0xFE), (0x40, 0xFE)),
    "big5": ("cp950", (0x81, 0xFE), (0x40, 0xFE)),
    "shift_jis": ("cp932", (0x81, 0xFC), (0x40, 0xFC)),
    "euc-kr": ("cp949", (0x81, 0xFE), (0x41, 0xFE)),
    # Two bytes: JIS X 0208, and 0x8E with a half-width katakana byte.
    "euc-jp": ("euc_jp", (0x8E, 0xFE), (0xA1, 0xFE)),
}


def decode(codec, data):
    try:
        text = data.decode(codec)
    except UnicodeDecodeError:
        return None
    return text if len(text) == 1 else None


def u16(cp):
    if cp is None:
        return b"\0\0"
    assert ord(cp) < 0x10000, cp
    return struct.pack(">H", ord(cp))


def single(name, codec):
    for b in range(0x80):
        assert decode(codec, bytes([b])) == chr(b), (name, b)
    return b"".join(u16(decode(codec, bytes([b]))) for b in range(0x80, 0x100))


def double(name, codec, lead, trail):
    singles = b"".join(u16(decode(codec, bytes([b]))) for b in range(0x80, 0x100))
    table = b"".join(
        u16(decode(codec, bytes([l, t])))
        for l in range(lead[0], lead[1] + 1)
        for t in range(trail[0], trail[1] + 1)
    )
    return b"D" + bytes([lead[0], lead[1], trail[0], trail[1]]) + singles + table


def jis0212():
    # EUC-JP's three-byte sequences: 0x8F and two bytes of JIS X 0212.
    return b"".join(
        u16(decode("euc_jp", bytes([0x8F, l, t]))) for l in range(0xA1, 0xFF) for t in range(0xA1, 0xFF)
    )


def gb18030_ranges():
    ranges = []
    for index in range(39420):
        b1, rest = divmod(index, 12600)
        b2, rest = divmod(rest, 1260)
        b3, b4 = divmod(rest, 10)
        cp = decode("gb18030", bytes([0x81 + b1, 0x30 + b2, 0x81 + b3, 0x30 + b4]))
        if cp is None:
            continue
        cp = ord(cp)
        if ranges and ranges[-1][0] + ranges[-1][2] == index and ranges[-1][1] + ranges[-1][2] == cp:
            ranges[-1][2] += 1
        else:
            ranges.append([index, cp, 1])
    return b"R" + struct.pack(">H", len(ranges)) + b"".join(struct.pack(">III", *r) for r in ranges)


def write(name, data):
    with open(os.path.join(OUT, name + ".bin"), "wb") as f:
        f.write(data)


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, codec in SINGLE.items():
        write(name, single(name, codec))
    for name, (codec, lead, trail) in DOUBLE.items():
        write(name, double(name, codec, lead, trail))
    write("jis-x-0212", jis0212())
    write("gb18030-ranges", gb18030_ranges())


if __name__ == "__main__":
    main()
