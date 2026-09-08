#!/usr/bin/env python3
"""
Report the longest sentences in the manuscript body, so over-long sentences can be split.

Strips LaTeX preamble, comments, math, macros, floats and the biography block, then splits
on sentence-final punctuation while protecting common abbreviations. Prints every sentence
above the word threshold with its line number in main.tex.

Usage: sentence_scan.py [main.tex] [--min-words 45]
"""
import argparse
import re
import sys

SKIP_ENVS = ("table", "table*", "tabular", "equation", "figure", "figure*",
             "IEEEbiography", "IEEEbiographynophoto", "keywords")
ABBREV = ("e.g", "i.e", "cf", "vs", "Fig", "Eq", "Sec", "Ref", "Tab", "al", "approx",
          "Dr", "St", "No", "resp")


def load_body(path):
    """Return [(line_number, text)] for prose lines only."""
    out = []
    skip_depth = 0
    in_body = False
    for n, raw in enumerate(open(path), start=1):
        line = raw.rstrip("\n")
        if "\\begin{document}" in line:
            in_body = True
            continue
        if not in_body:
            continue
        if "\\bibliography{" in line or "\\begin{IEEEbiography" in line:
            break
        if re.match(r"\s*\\(title|author|address|markboth|corresp|tfootnote|history|doi|graphicspath)\b", line):
            out.append((n, ""))
            continue
        m = re.search(r"\\begin\{([A-Za-z*]+)\}", line)
        if m and m.group(1) in SKIP_ENVS:
            skip_depth += 1
        e = re.search(r"\\end\{([A-Za-z*]+)\}", line)
        if skip_depth and e and e.group(1) in SKIP_ENVS:
            skip_depth -= 1
            continue
        if skip_depth:
            continue
        line = re.sub(r"(?<!\\)%.*$", "", line)
        if not line.strip():
            out.append((n, ""))
            continue
        if line.lstrip().startswith("\\") and not re.match(r"\s*\\(emph|textit|textbf|IEEEPARstart)", line.lstrip()):
            # a bare command line (section heading, label, includegraphics...)
            if re.match(r"\s*\\(section|subsection|subsubsection|label|caption|item|includegraphics|centering|bibliographystyle|EOD|maketitle|titlepgskip)", line.lstrip()):
                out.append((n, ""))
                continue
        out.append((n, line))
    return out


def clean(text):
    text = re.sub(r"\$[^$]*\$", " NUM ", text)
    text = re.sub(r"\\cite\{[^}]*\}", " [ref] ", text)
    text = re.sub(r"\\ref\{[^}]*\}", " X ", text)
    text = re.sub(r"\\(emph|textit|textbf|texttt|uppercase)\{([^{}]*)\}", r"\2", text)
    text = re.sub(r"\\[A-Za-z]+\*?", " ", text)
    text = text.replace("~", " ").replace("{", " ").replace("}", " ")
    return re.sub(r"\s+", " ", text).strip()


def split_sentences(text):
    prot = text
    for a in ABBREV:
        prot = prot.replace(a + ".", a + "<DOT>")
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z(])", prot)
    return [p.replace("<DOT>", ".").strip() for p in parts if p.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tex", nargs="?", default="paper/main.tex")
    ap.add_argument("--min-words", type=int, default=45)
    args = ap.parse_args()

    body = load_body(args.tex)
    # regroup into paragraphs, remembering the first line number
    paras, cur, first = [], [], None
    for n, t in body:
        if t == "":
            if cur:
                paras.append((first, " ".join(cur)))
                cur, first = [], None
            continue
        if first is None:
            first = n
        cur.append(t)
    if cur:
        paras.append((first, " ".join(cur)))

    hits = []
    total = 0
    lengths = []
    for n, para in paras:
        for s in split_sentences(clean(para)):
            w = len(s.split())
            if w < 4:
                continue
            total += 1
            lengths.append(w)
            if w >= args.min_words:
                hits.append((w, n, s))
    lengths.sort()
    print("sentences=%d  median=%d  p90=%d  max=%d  over-%d=%d"
          % (total, lengths[len(lengths) // 2], lengths[int(0.9 * len(lengths))],
             lengths[-1], args.min_words, len(hits)))
    for w, n, s in sorted(hits, reverse=True):
        print("\n--- %d words, near line %d ---\n%s" % (w, n, s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
