#!/usr/bin/env python3
"""Check the SOC 2 pack's identifiers against the publisher's PDF.

The trust services criteria are copyright AICPA, so the PDF is never in
this repository and this script copies nothing out of it. It reads the
criterion identifiers from a copy you hold, compares them with the pack,
and prints the count and any difference.

    pip install pypdf
    python3 tools/import/soc2/verify.py /path/to/Trust-services-criteria.pdf

Exit status 0 means the pack names exactly the criteria the PDF does.
"""
import hashlib
import pathlib
import re
import sys

PACK = pathlib.Path(__file__).resolve().parents[3] / "packs" / "soc2" / "2017-tsc-2022-pof.yaml"


def pdf_identifiers(path):
    import pypdf

    found = set()
    for page in pypdf.PdfReader(path).pages:
        for line in (page.extract_text() or "").splitlines():
            m = re.match(r"\s*((?:CC|PI|A|C|P)\d+\.\d+)\b", line)
            if m:
                found.add(m.group(1))
    return found


def pack_identifiers():
    text = PACK.read_text()
    sha = re.search(r"sha256: ([0-9a-f]{64})", text).group(1)
    ids, headings = set(), set()
    for block in re.split(r"\n  - id: ", text)[1:]:
        ident = block.split("\n", 1)[0].strip().strip('"')
        (headings if "heading: true" in block else ids).add(ident)
    return ids, headings, sha


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    pdf = sys.argv[1]
    ids, headings, sha = pack_identifiers()
    digest = hashlib.sha256(pathlib.Path(pdf).read_bytes()).hexdigest()
    if digest != sha:
        print(f"note: this PDF's SHA-256 is {digest}; the pack was written from {sha}")
    found = pdf_identifiers(pdf)
    # The PDF numbers its privacy sections P1.0 to P8.0; the pack has them as headings.
    criteria = found - headings
    print(f"PDF: {len(criteria)} criteria. Pack: {len(ids)} criteria, {len(headings)} headings.")
    missing, extra = sorted(criteria - ids), sorted(ids - criteria)
    if missing:
        print("in the PDF, not in the pack:", ", ".join(missing))
    if extra:
        print("in the pack, not in the PDF:", ", ".join(extra))
    sys.exit(1 if missing or extra else 0)


if __name__ == "__main__":
    main()
