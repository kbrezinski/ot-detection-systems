"""Run gotham-network-packet-labeller feature cleaning, labelling and preparation.

Input: the tab-separated tshark feature CSVs already downloaded to ``data/``::

    data/benign/*.csv
    data/malicious/<event>/*.csv

Stages (outputs are written under ``--data-dir``):

    clean    feature cleaning   -> cleaning_report.json
    label    packet labelling   -> labelled/
    prepare  per-device dataset -> processed/<device>.csv

The library's own scripts are not run directly. At the pinned commit
``run_cleaning.py`` crashes (it iterates over a glob *string*) and writes nothing,
``run_labeling.py`` silently skips network scanning (it looks for a metadata file
that does not exist), and both it and ``data_preparation.py`` match devices by
filename prefix, so ``-1`` also swallows ``-10`` to ``-19``. This script reuses the
library's ``Labeller`` and ``FeatureCleaner`` and its metadata, and handles the file
layout, device grouping and chunked reading itself.

The benign CSVs in this dataset copy do not hold the traffic their file names claim:
each holds one other device's traffic. A benign file whose traffic does not involve
its named device but does involve exactly one other known device is therefore
assigned to that device (see ``benign_file_mapping.json``). Malicious files are
trusted as named.

Usage: uv run python scripts/run_gotham_pipeline.py [--stages clean label prepare]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import warnings
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
LIB_DIR = ROOT / "third_party" / "gotham-network-packet-labeller"
LIB_URL = "https://github.com/othmbela/gotham-network-packet-labeller.git"
LIB_COMMIT = "cad1575bc8fd65f9e30d5cc88b04d7ba137c980d"

SEED = 1337
CHUNK_ROWS = 200_000

# Library event name -> labelling rules file in the library's metadata/ folder.
EVENT_METADATA = {
    "coap-amplificator": "metadata-coap-amplificator.json",
    "network-scanning": "metadata-masscan.json",
    "merlin": "metadata-merlin.json",
    "mirai-dos": "metadata-mirai-dos.json",
    "mirai-infection": "metadata-mirai-infection.json",
}
# Folder names in data/malicious that differ from the library's event names.
FOLDER_ALIASES = {"coop-amplifactor": "coap-amplificator"}

# Same pattern the library uses to split "<device>-<n>_..." file names.
DEVICE_RE = re.compile(r"([a-zA-Z\-]+)-([0-9]+)")


@dataclass(frozen=True)
class Item:
    """One input CSV, the device its name claims and the device its traffic is."""

    event: str  # "benign" or a library event name
    path: Path
    named_device: str
    device: str

    @property
    def labelled_name(self) -> str:
        """File name in labelled/; starts with the true device id."""
        if self.device == self.named_device:
            return self.path.name
        return f"{self.device}__from_{self.path.name}"

    @property
    def folder(self) -> Path:
        return (
            Path("benign") if self.event == "benign" else Path("malicious", self.event)
        )


def ensure_library() -> None:
    """Clone the labeller at the pinned commit (once) and make it importable."""
    if not LIB_DIR.exists():
        LIB_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--quiet", LIB_URL, str(LIB_DIR)], check=True)
    subprocess.run(
        ["git", "-C", str(LIB_DIR), "checkout", "--quiet", LIB_COMMIT], check=True
    )
    sys.path.insert(0, str(LIB_DIR))


def load_metadata(name: str):
    return json.loads((LIB_DIR / "metadata" / name).read_text(encoding="utf-8"))


def device_id(path: Path) -> str:
    """Device instance a file belongs to, e.g. ``iotsim-cooler-motor-11``."""
    match = DEVICE_RE.match(path.name)
    if match is None:
        raise ValueError(f"Unexpected file name: {path.name}")
    return match.group(0)


def find_inputs(data_dir: Path) -> list[tuple[str, Path]]:
    """Return (event, csv path) pairs; event is "benign" or a library event name."""
    inputs = [("benign", p) for p in sorted((data_dir / "benign").glob("*.csv"))]
    malicious = data_dir / "malicious"
    folders = (
        sorted(p for p in malicious.iterdir() if p.is_dir())
        if malicious.is_dir()
        else []
    )
    for folder in folders:
        event = FOLDER_ALIASES.get(folder.name, folder.name)
        if event not in EVENT_METADATA:
            print(f"warning: skipping unknown folder {folder}")
            continue
        inputs += [(event, p) for p in sorted(folder.glob("*.csv"))]
    if not inputs:
        raise SystemExit(f"No CSV files found under {data_dir}")
    return inputs


def devices_in_traffic(path: Path, ip_to_device: dict[str, str]) -> set[str]:
    """Known devices whose IP address appears in the file's traffic."""
    seen: set[str] = set()
    chunks = pd.read_csv(
        path, sep="\t", usecols=["ip.src", "ip.dst"], dtype=str, chunksize=CHUNK_ROWS
    )
    for chunk in chunks:
        ips = pd.concat([chunk["ip.src"], chunk["ip.dst"]]).dropna().unique()
        seen.update(ip_to_device[ip] for ip in ips if ip in ip_to_device)
    return seen


def assign_devices(inputs: list[tuple[str, Path]], data_dir: Path) -> list[Item]:
    """Attach the true device to every file; benign files are checked by content."""
    benign_meta = load_metadata("metadata-benign.json")
    ip_to_device = {
        ip: f"{name}-{i + 1}"
        for name, info in benign_meta.items()
        for i, ip in enumerate(info["device_ip"])
    }
    items, mapping = [], {}
    for event, path in inputs:
        named = device_id(path)
        actual = named
        if event == "benign":
            seen = devices_in_traffic(path, ip_to_device)
            if named not in seen and len(seen) == 1:
                (actual,) = seen
            mapping[path.name] = {
                "named_device": named,
                "traffic_devices": sorted(seen),
                "assigned_device": actual,
            }
        items.append(Item(event, path, named, actual))

    if mapping:
        (data_dir / "benign_file_mapping.json").write_text(
            json.dumps(mapping, indent=2)
        )
        moved = sum(m["named_device"] != m["assigned_device"] for m in mapping.values())
        print(
            f"benign: {moved} of {len(mapping)} files hold another device's traffic "
            "and were reassigned (benign_file_mapping.json)"
        )
    return items


def group_by_device(items: list[Item]) -> dict[str, list[Item]]:
    by_device: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        by_device[item.device].append(item)
    return dict(sorted(by_device.items()))


def count_rows(path: Path) -> int:
    with path.open("rb") as fh:
        newlines = sum(
            block.count(b"\n") for block in iter(lambda: fh.read(1 << 22), b"")
        )
    return max(newlines - 1, 1)  # minus header


def read_sampled(path: Path, max_rows: int):
    """Yield chunks of ``path``, randomly thinned to roughly ``max_rows`` rows."""
    frac = min(1.0, max_rows / count_rows(path)) if max_rows else 1.0
    for chunk in pd.read_csv(path, sep="\t", low_memory=False, chunksize=CHUNK_ROWS):
        yield chunk if frac >= 1.0 else chunk.sample(frac=frac, random_state=SEED)


def run_cleaning(items: list[Item], data_dir: Path, max_rows: int) -> None:
    from src.helpers.feature_cleaner import FeatureCleaner
    from src.run_cleaning import federated_feature_consolidation

    feature_sets: list[set[str]] = []
    devices: dict[str, dict] = {}
    for device, files in group_by_device(items).items():
        try:
            df = pd.concat([c for f in files for c in read_sampled(f.path, max_rows)])
            cleaned = FeatureCleaner().clean_features(df)
        except ValueError as err:  # e.g. no column survives the variance filter
            print(f"  {device}: skipped ({err})")
            continue
        feature_sets.append(set(cleaned.columns))
        devices[device] = {
            "rows_analysed": len(df),
            "kept": sorted(cleaned.columns),
            "dropped": sorted(set(df.columns) - set(cleaned.columns)),
        }
        print(
            f"  {device}: {len(df):,} rows, kept {cleaned.shape[1]}/{df.shape[1]} columns"
        )

    global_features = sorted(federated_feature_consolidation(feature_sets))
    report = {"global_features": global_features, "devices": devices}
    (data_dir / "cleaning_report.json").write_text(json.dumps(report, indent=2))
    print(f"cleaning: {len(global_features)} global features -> cleaning_report.json")


def label_file(labeller, item: Item, out: Path) -> tuple[int, int]:
    """Label a file chunk by chunk into ``out``; returns (rows in, rows kept)."""
    tmp = out.with_name(out.name + ".part")
    rows_in = rows_kept = 0
    first = True
    reader = pd.read_csv(
        item.path,
        sep="\t",
        low_memory=False,
        chunksize=CHUNK_ROWS,
        dtype={"ip.src": str, "ip.dst": str},
    )
    for chunk in reader:
        # The labeller derives the device (and so its IP) from the file name.
        labelled = labeller.label_data(item.labelled_name, chunk)
        rows_in += len(chunk)
        rows_kept += len(labelled)
        labelled.to_csv(
            tmp, sep="\t", index=False, mode="w" if first else "a", header=first
        )
        first = False
    if not first:
        os.replace(tmp, out)
    return rows_in, rows_kept


def run_labelling(items: list[Item], data_dir: Path, force: bool) -> None:
    from src.helpers.labeller import Labeller

    benign_meta = load_metadata("metadata-benign.json")
    labellers = {"benign": Labeller(benign_meta, [])}
    for event, name in EVENT_METADATA.items():
        labellers[event] = Labeller(benign_meta, load_metadata(name))

    for item in items:
        out = data_dir / "labelled" / item.folder / item.labelled_name
        out.parent.mkdir(parents=True, exist_ok=True)
        shown = item.folder / item.labelled_name
        if out.exists() and not force:
            print(f"  {shown}: already labelled, skipping")
            continue
        start = time.perf_counter()
        rows_in, rows_kept = label_file(labellers[item.event], item, out)
        note = ""
        if rows_kept == 0:
            name, index = Labeller.extract_device_info(item.labelled_name)
            ip = benign_meta[name]["device_ip"][index]
            note = (
                f"  WARNING: no packets involve {ip}; file may belong to another device"
            )
        print(
            f"  {shown}: {rows_in:,} -> {rows_kept:,} rows "
            f"({time.perf_counter() - start:.0f}s){note}"
        )


def run_preparation(data_dir: Path, force: bool) -> None:
    labelled = data_dir / "labelled"
    processed = data_dir / "processed"
    processed.mkdir(exist_ok=True)

    # Group by exact device id (not filename prefix) so "-1" never absorbs "-10".
    by_device: dict[str, list[Path]] = defaultdict(list)
    for path in sorted(labelled.rglob("*.csv")):
        by_device[device_id(path)].append(path)

    for device, files in sorted(by_device.items()):
        out = processed / f"{device}.csv"
        if out.exists() and not force:
            print(f"  {device}: already prepared, skipping")
            continue
        tmp = out.with_name(out.name + ".part")
        columns, rows = None, 0
        for path in files:
            for chunk in pd.read_csv(
                path, sep="\t", low_memory=False, chunksize=CHUNK_ROWS
            ):
                if columns is None:
                    columns = list(chunk.columns)
                elif list(chunk.columns) != columns:
                    raise ValueError(f"Column mismatch in {path}")
                chunk.to_csv(
                    tmp, index=False, mode="w" if rows == 0 else "a", header=rows == 0
                )
                rows += len(chunk)
        if rows == 0:
            print(f"  {device}: no labelled rows, nothing written")
            continue
        os.replace(tmp, out)
        has_benign = any(p.parent.name == "benign" for p in files)
        print(
            f"  {device}: {rows:,} rows from {len(files)} files"
            + ("" if has_benign else " (no benign file)")
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    parser.add_argument(
        "--stages",
        nargs="+",
        choices=["clean", "label", "prepare"],
        default=["clean", "label", "prepare"],
    )
    parser.add_argument(
        "--clean-max-rows",
        type=int,
        default=200_000,
        help="cleaning: sample each file down to about this many rows (0 = all rows)",
    )
    parser.add_argument(
        "--force", action="store_true", help="redo outputs that already exist"
    )
    args = parser.parse_args()
    data_dir = args.data_dir.resolve()
    sys.stdout.reconfigure(line_buffering=True)  # live progress when piped

    # The library mutates DataFrame slices; the warning is noise here.
    warnings.filterwarnings("ignore", category=pd.errors.SettingWithCopyWarning)

    ensure_library()
    items = assign_devices(find_inputs(data_dir), data_dir)
    print(
        f"{len(items)} CSV files, {len({i.device for i in items})} devices in {data_dir}"
    )

    if "clean" in args.stages:
        print("== Feature cleaning")
        run_cleaning(items, data_dir, args.clean_max_rows)
    if "label" in args.stages:
        print("== Labelling")
        run_labelling(items, data_dir, args.force)
    if "prepare" in args.stages:
        print("== Data preparation")
        run_preparation(data_dir, args.force)


if __name__ == "__main__":
    main()
