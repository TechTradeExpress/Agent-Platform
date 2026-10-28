"""Bounded ELF64 dependency metadata via a descriptor reader, never a loader."""

import re
import struct

from agent_platform.runtime_manifest import need, relative

FORBIDDEN = {15, 29, 0x6FFFFEFA, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF}
ALLOWED = set(range(39)) | {
    0x6FFFFEF5,
    0x6FFFFFF0,
    0x6FFFFFF9,
    0x6FFFFFFA,
    0x6FFFFFFB,
    0x6FFFFFFC,
    0x6FFFFFFD,
    0x6FFFFFFE,
    0x6FFFFFFF,
}


def inspect(read, size, *, executable=False):
    raw = read(0, 64)
    need(
        len(raw) == 64
        and raw[:7] == b"\x7fELF\x02\x01\x01"
        and raw[7] in (0, 3)
        and raw[8] == 0,
        "unsupported_elf",
    )
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    kind, machine, version, entry, offset, _, _, length, stride, count, *_ = header
    need(
        kind in (2, 3)
        and machine == 62
        and version == 1
        and length == 64
        and stride == 56
        and 0 < count <= 128
        and offset >= 64,
        "unsupported_elf",
    )
    table = read(offset, count * 56)
    loads, dynamic, interpreter = [], None, None
    for i in range(count):
        tag, flags, start, address, _, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", table, i * 56
        )
        need(start <= size and filesz <= size - start, "invalid_elf_range")
        if tag == 1:
            need(
                filesz <= memsz
                and address + memsz < 2**64
                and flags <= 7
                and flags & 3 != 3,
                "invalid_load",
            )
            need(
                align in (0, 1)
                or (
                    align <= 2**21
                    and align & (align - 1) == 0
                    and start % align == address % align
                ),
                "invalid_load",
            )
            need(
                all(
                    address + memsz <= a or a + m <= address for a, _, _, m, _ in loads
                ),
                "overlapping_load",
            )
            loads.append((address, start, filesz, memsz, flags))
        elif tag == 2:
            need(
                dynamic is None
                and 16 <= filesz <= 65536
                and filesz % 16 == 0
                and filesz <= memsz,
                "invalid_dynamic",
            )
            dynamic = (address, start, filesz)
        elif tag == 3:
            need(interpreter is None and 1 < filesz <= 256, "invalid_interpreter")
            value = read(start, filesz)
            need(value[-1:] == b"\0" and b"\0" not in value[:-1], "invalid_interpreter")
            try:
                interpreter = value[:-1].decode("ascii")
            except UnicodeError:
                need(False, "invalid_interpreter")
            need(
                interpreter.startswith("/") and relative(interpreter[1:]),
                "invalid_interpreter",
            )
        elif tag == 0x6474E551:
            need(not flags & 1, "executable_stack")
    need(loads, "missing_load")
    if executable:
        need(
            any(flags & 1 and a <= entry < a + n for a, _, n, _, flags in loads),
            "invalid_entrypoint",
        )
    if dynamic is None:
        return interpreter, [], None
    address, pos, length = dynamic
    need(
        sum(
            a <= address and address + length <= a + n and start + address - a == pos
            for a, start, n, _, _ in loads
        )
        == 1,
        "invalid_dynamic",
    )
    data = read(pos, length)
    entries = []
    ended = False
    for i in range(0, length, 16):
        tag, value = struct.unpack_from("<qQ", data, i)
        if tag == 0:
            ended = True
            break
        need(tag not in FORBIDDEN and tag in ALLOWED, "unsupported_dynamic")
        need(
            not (tag == 30 and value & 1) and not (tag == 0x6FFFFFFB and value & 0x80),
            "dynamic_search_path",
        )
        entries.append((tag, value))
    need(ended, "unterminated_dynamic")
    strings = [v for t, v in entries if t == 5]
    sizes = [v for t, v in entries if t == 10]
    needed = [v for t, v in entries if t == 1]
    sonames = [v for t, v in entries if t == 14]
    need(
        len(needed) <= 64 and len(set(needed)) == len(needed) and len(sonames) <= 1,
        "dependency_limit",
    )
    if not strings and not sizes:
        need(not needed and not sonames, "missing_strings")
        return interpreter, [], None
    need(
        len(strings) == len(sizes) == 1 and 0 < sizes[0] <= 1024 * 1024,
        "invalid_strings",
    )
    locations = [
        start + strings[0] - a
        for a, start, n, _, _ in loads
        if a <= strings[0] and strings[0] + sizes[0] <= a + n
    ]
    need(len(locations) == 1, "invalid_strings")

    def string(index):
        need(index < sizes[0], "invalid_strings")
        raw = read(locations[0] + index, min(129, sizes[0] - index))
        end = raw.find(b"\0")
        need(0 < end <= 128, "invalid_strings")
        try:
            result = raw[:end].decode("ascii")
        except UnicodeError:
            need(False, "invalid_strings")
        need(re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", result), "invalid_strings")
        return result

    return (
        interpreter,
        [string(n) for n in needed],
        string(sonames[0]) if sonames else None,
    )
