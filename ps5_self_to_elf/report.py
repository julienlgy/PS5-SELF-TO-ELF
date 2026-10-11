"""Terminal output: banner, progress bar, results table and summary."""

import shutil
import sys

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
STYLES = {
    "OK": ("\033[92m", "✔"),
    "REPAIRED": ("\033[96m", "♻"),
    "READY": ("\033[94m", "➜"),
    "SKIP": ("\033[93m", "•"),
    "FAIL": ("\033[91m", "✘"),
}
CYAN = "\033[96m"
SELF_ART = [
    "███████╗███████╗██╗     ███████╗",
    "██╔════╝██╔════╝██║     ██╔════╝",
    "███████╗█████╗  ██║     █████╗  ",
    "╚════██║██╔══╝  ██║     ██╔══╝  ",
    "███████║███████╗███████╗███████╗",
    "╚══════╝╚══════╝╚══════╝╚══════╝",
]
ELF_ART = [
    "███████╗██╗     ███████╗",
    "██╔════╝██║     ██╔════╝",
    "█████╗  ██║     █████╗  ",
    "██╔══╝  ██║     ██╔══╝  ",
    "███████╗███████╗███████╗",
    "╚══════╝╚══════╝╚══════╝",
]


def human_size(size):
    if not size:
        return "-"
    for unit in ("B", "KiB", "MiB"):
        if size < 1024:
            return f"{size} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"


def clip(text, width):
    return text if len(text) <= width else text[:width - 1] + "…"


def paint(text, code, enabled):
    return f"{code}{text}{RESET}" if enabled else text


def print_banner(color):
    print()
    for i in range(len(SELF_ART)):
        arrow = "   ══▶   " if i == 2 else "         "
        line = SELF_ART[i] + arrow + ELF_ART[i]
        print(paint("  " + line, BOLD + CYAN, color))
    print(paint("  PS5 SELF/PRX → ELF converter", BOLD, color)
          + paint("  ·  no decryption, no decompression", DIM, color))
    print()


def print_progress(done, total, name):
    width = 30
    filled = int(width * done / total)
    columns = shutil.get_terminal_size((100, 20)).columns - 1
    line = f"  {'█' * filled}{'░' * (width - filled)} {done}/{total}  {name}"[:columns]
    sys.stdout.write("\r" + line.ljust(columns))
    sys.stdout.flush()


def clear_progress():
    columns = shutil.get_terminal_size((100, 20)).columns - 1
    sys.stdout.write("\r" + " " * columns + "\r")
    sys.stdout.flush()


def print_table(results, base, color):
    headers = ["#", "STATUS", "FILE", "SIZE", "NOTE"]
    files = [str(r.path.relative_to(base)) for r in results]
    notes = [r.note for r in results]
    file_width = min(max(len(headers[2]), *map(len, files)), 48)
    note_width = min(max(len(headers[4]), *map(len, notes)), 46)
    widths = [len(str(len(results))), 10, file_width, 10, note_width]

    def rule(left, middle, right):
        return "  " + left + middle.join("─" * (w + 2) for w in widths) + right

    def row(cells, styled=None):
        padded = [cell.ljust(width) for cell, width in zip(cells, widths)]
        if styled is not None:
            padded[1] = paint(padded[1], styled, color)
        return "  │ " + " │ ".join(padded) + " │"

    print(paint("  RESULTS", BOLD, color))
    print(rule("┌", "┬", "┐"))
    print(row(headers))
    print(rule("├", "┼", "┤"))
    for index, (result, name, note) in enumerate(zip(results, files, notes), 1):
        style, icon = STYLES[result.status]
        print(row([
            str(index),
            f"{icon} {result.status}",
            clip(name, file_width),
            human_size(result.size),
            clip(note, note_width),
        ], styled=style))
    print(rule("└", "┴", "┘"))


def print_summary(results, base, color, elapsed, verbose):
    print()
    print_table(results, base, color)
    print()
    counts = {status: sum(r.status == status for r in results) for status in STYLES}
    labels = {"OK": "converted", "REPAIRED": "repaired", "READY": "ready",
              "SKIP": "skipped", "FAIL": "failed"}
    totals = "   ".join(paint(f"{STYLES[s][1]} {counts[s]} {labels[s]}", STYLES[s][0], color)
                        for s in STYLES)
    print(paint("  TOTALS", BOLD, color) + f"   {totals}")
    print(paint(f"  Time: {elapsed:.2f} s", DIM, color))

    failures = [r for r in results if r.status == "FAIL"]
    if failures:
        print()
        print(paint(f"  FAILURES ({len(failures)})", BOLD + STYLES["FAIL"][0], color))
        for r in failures:
            print(f"    ✘ {r.path.relative_to(base)}: {r.note}")

    warnings = [(r, notice) for r in results for notice in r.notices]
    if warnings:
        print()
        print(paint(f"  WARNINGS ({len(warnings)})", BOLD + STYLES["SKIP"][0], color))
        if verbose:
            for r, notice in warnings:
                print(f"    ! {r.path.relative_to(base)}: {notice}")
        else:
            print(paint("    Run with -v to list them.", DIM, color))
    print()
