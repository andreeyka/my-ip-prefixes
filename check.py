"""Проверяет, попадает ли IP-адрес в not-cis (не наш) или cis (наш) блоки."""

import argparse
import json
import subprocess
import sys
import tempfile
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path


def load_prefixes_from_srs(srs_path: Path) -> list[IPv4Network]:
    """Загружает IP-префиксы из .srs файла."""
    result = subprocess.run(
        ["sing-box", "rule-set", "decompile", "--output", "/dev/stdout", str(srs_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        subprocess.run(
            ["sing-box", "rule-set", "decompile", "--output", str(tmp_path), str(srs_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(tmp_path.read_text())
        tmp_path.unlink()
    else:
        data = json.loads(result.stdout)

    networks: list[IPv4Network] = []
    for rule in data.get("rules", []):
        for cidr in rule.get("ip_cidr", []):
            networks.append(IPv4Network(cidr, strict=False))
    return networks


def check_ip(ip: IPv4Address, networks: list[IPv4Network]) -> bool:
    """Проверяет, попадает ли IP в один из префиксов."""
    return any(ip in net for net in networks)


def load_networks(file_path: Path) -> list[IPv4Network]:
    """Загружает сети из .srs или .json файла."""
    if file_path.suffix == ".json":
        data = json.loads(file_path.read_text())
        return [
            IPv4Network(cidr, strict=False)
            for rule in data.get("rules", [])
            for cidr in rule.get("ip_cidr", [])
        ]
    return load_prefixes_from_srs(file_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Проверка IP-адреса по not-cis rule-set")
    parser.add_argument("ip", help="IP-адрес для проверки")
    parser.add_argument(
        "--dir", "-d", type=str, default=".",
        help="Директория с файлами not-cis-*.srs (по умолчанию: .)",
    )
    args = parser.parse_args()

    try:
        ip = IPv4Address(args.ip)
    except ValueError:
        print(f"Некорректный IP-адрес: {args.ip}", file=sys.stderr)
        sys.exit(1)

    srs_dir = Path(args.dir)
    files = sorted(srs_dir.glob("not-cis-*.srs"))
    if not files:
        print(f"Файлы not-cis-*.srs не найдены в {srs_dir}", file=sys.stderr)
        sys.exit(1)

    for f in files:
        name = f.stem.removeprefix("not-cis-")
        networks = load_networks(f)
        result = "not-cis" if check_ip(ip, networks) else "cis"
        print(f"{name:>8}: {result}")


if __name__ == "__main__":
    main()
