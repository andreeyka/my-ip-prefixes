import argparse
import array
import json
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network, collapse_addresses
from pathlib import Path

SRS_BASE_URL = (
    "https://raw.githubusercontent.com/"
    "you-oops-dev/ipranges-singbox/main/country"
)

DEFAULT_COUNTRIES = ["ru", "by", "kz", "uz", "kg", "tj", "tm", "am", "az"]
DEFAULT_LEVELS: list[tuple[int, int]] = [
    (16, 1),
    (20, 2),
    (23, 3),
    (26, 8),
]


def decompile_srs(srs_path: Path) -> dict:
    """Декомпилирует .srs файл в JSON через sing-box CLI."""
    result = subprocess.run(
        ["sing-box", "rule-set", "decompile", "--output", "/dev/stdout", str(srs_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        json_path = srs_path.with_suffix(".json")
        subprocess.run(
            ["sing-box", "rule-set", "decompile", str(srs_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(json_path.read_text())
        json_path.unlink()
        return data
    return json.loads(result.stdout)


def range_to_cidrs(start: int, end: int) -> list[IPv4Network]:
    """Конвертирует диапазон [start, end) в минимальный набор CIDR."""
    result: list[IPv4Network] = []
    while start < end:
        max_bits = (start & -start).bit_length() - 1 if start else 32
        remaining_bits = (end - start).bit_length() - 1
        bits = min(max_bits, remaining_bits)
        result.append(IPv4Network(f"{IPv4Address(start)}/{32 - bits}"))
        start += 1 << bits
    return result


def build_ru_intervals(ru_cidrs: list[str]) -> list[tuple[int, int]]:
    """Строит отсортированный список RU-интервалов [start, end)."""
    networks = sorted(
        [IPv4Network(c, strict=False) for c in ru_cidrs],
        key=lambda n: int(n.network_address),
    )
    networks = list(collapse_addresses(networks))
    return [
        (int(n.network_address), int(n.network_address) + n.num_addresses)
        for n in networks
    ]


def compute_coverage(
    ru_intervals: list[tuple[int, int]],
    block_start: int,
    block_end: int,
    ri_hint: int,
) -> tuple[int, int]:
    """Считает покрытие RU в блоке. Возвращает (covered, обновлённый ri)."""
    ri = ri_hint
    while ri < len(ru_intervals) and ru_intervals[ri][1] <= block_start:
        ri += 1

    covered = 0
    j = ri
    while j < len(ru_intervals) and ru_intervals[j][0] < block_end:
        overlap_start = max(ru_intervals[j][0], block_start)
        overlap_end = min(ru_intervals[j][1], block_end)
        covered += overlap_end - overlap_start
        j += 1

    return covered, ri


def classify_multilevel(
    ru_cidrs: list[str],
    levels: list[tuple[int, float]],
) -> tuple[list[IPv4Network], list[IPv4Network]]:
    """Многоуровневая классификация.

    levels — список (block_prefix, threshold), от крупных к мелким.
    Например: [(16, 0.05), (20, 0.10), (24, 0.50)]

    На каждом уровне: блоки с покрытием >= threshold → RU.
    Оставшиеся (не классифицированные) блоки разбиваются на следующем уровне.
    """
    ru_intervals = build_ru_intervals(ru_cidrs)

    # Начинаем с полного IPv4 как "нерешённое" пространство
    # Храним как список интервалов [start, end) выровненных по текущему блоку
    undecided: list[tuple[int, int]] = [(0, 2**32)]
    ru_result: list[tuple[int, int]] = []
    not_ru_result: list[tuple[int, int]] = []

    for level_idx, (block_prefix, threshold) in enumerate(levels):
        block_size = 2 ** (32 - block_prefix)
        is_last = level_idx == len(levels) - 1
        next_undecided: list[tuple[int, int]] = []

        total_blocks = sum((e - s) // block_size for s, e in undecided)
        processed = 0
        step = max(total_blocks // 10, 1)

        print(f"  /{block_prefix} ({threshold:.0%}): {total_blocks} блоков",
              end="", file=sys.stderr, flush=True)

        ri = 0
        for region_start, region_end in undecided:
            for block_start in range(region_start, region_end, block_size):
                block_end = block_start + block_size
                covered, ri = compute_coverage(
                    ru_intervals, block_start, block_end, ri
                )
                coverage = covered / block_size

                if coverage >= threshold:
                    ru_result.append((block_start, block_end))
                elif is_last:
                    not_ru_result.append((block_start, block_end))
                elif covered == 0:
                    # Точно не-RU, не нужно разбивать дальше
                    not_ru_result.append((block_start, block_end))
                else:
                    # Есть немного RU — разбить на следующем уровне
                    next_undecided.append((block_start, block_end))

                processed += 1

        print(" ✓", file=sys.stderr, flush=True)
        undecided = next_undecided

    # Конвертируем интервалы в CIDR
    ru_nets: list[IPv4Network] = []
    for s, e in ru_result:
        ru_nets.extend(range_to_cidrs(s, e))
    ru_nets = list(collapse_addresses(sorted(
        ru_nets, key=lambda n: int(n.network_address)
    )))

    not_ru_nets: list[IPv4Network] = []
    for s, e in not_ru_result:
        not_ru_nets.extend(range_to_cidrs(s, e))
    not_ru_nets = list(collapse_addresses(sorted(
        not_ru_nets, key=lambda n: int(n.network_address)
    )))

    return ru_nets, not_ru_nets




def download_srs(cc: str, dest_dir: Path) -> Path | None:
    """Скачивает .srs файл страны из GitHub."""
    url = f"{SRS_BASE_URL}/{cc}/{cc}.srs"
    dest = dest_dir / f"{cc}.srs"
    try:
        urllib.request.urlretrieve(url, dest)
        return dest
    except urllib.error.URLError as e:
        print(f"  {cc.upper()}: ошибка загрузки — {e}", file=sys.stderr)
        return None


def load_ip_cidrs(
    country_codes: list[str],
) -> tuple[list[str], dict[str, int]]:
    """Скачивает .srs файлы стран и извлекает IP CIDR.

    Возвращает (все CIDR, словарь страна → кол-во префиксов).
    """
    all_cidrs: list[str] = []
    stats: dict[str, int] = {}

    with tempfile.TemporaryDirectory(prefix="ipranges-") as tmpdir:
        tmp_path = Path(tmpdir)
        for cc in country_codes:
            srs_path = download_srs(cc, tmp_path)
            if srs_path is None:
                continue

            data = decompile_srs(srs_path)
            for rule in data.get("rules", []):
                cidrs = rule.get("ip_cidr", [])
                if cidrs:
                    print(f"  {cc.upper()}: {len(cidrs)} префиксов",
                          file=sys.stderr)
                    all_cidrs.extend(cidrs)
                    stats[cc.upper()] = stats.get(cc.upper(), 0) + len(cidrs)

    return all_cidrs, stats


def generate_readme(
    countries: list[str],
    country_stats: dict[str, int],
    levels: list[tuple[int, float]],
    original_count: int,
    original_ips: int,
    not_ru_count: int,
    ru_count: int,
    foreign_lost_pct: float,
    leaked_pct: float,
) -> str:
    """Генерирует содержимое README.md."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    levels_str = ", ".join(f"/{p}:{t:.0%}" for p, t in levels)

    country_lines = "\n".join(
        f"| {cc} | {country_stats.get(cc.upper(), 0):,} |"
        for cc in countries
    )

    return f"""\
# my-ip-prefixes

sing-box rule-set с IP-префиксами, **не** принадлежащими странам СНГ.

Обновлено: **{now}**

## Параметры

| Параметр | Значение |
|----------|----------|
| Уровни классификации | `{levels_str}` |
| Исходных префиксов | {original_count:,} |
| Исходных IP | {original_ips:,} |

## Загруженные страны

| Страна | Префиксов |
|--------|-----------|
{country_lines}

## Результат

| Метрика | Значение |
|---------|----------|
| Не-наших префиксов | **{not_ru_count:,}** |
| Наших префиксов | {ru_count:,} |
| Потеря (чужие IP в наших) | {foreign_lost_pct:.2f}% |
| Утечка (наши IP в чужих) | {leaked_pct:.2f}% |

## Скачать

[not-cis.srs](https://raw.githubusercontent.com/andreeyka/my-ip-prefixes/main/not-cis.srs)

## Использование в sing-box

```json
{{
  "rule_set": [
    {{
      "tag": "not-cis",
      "type": "remote",
      "url": "https://raw.githubusercontent.com/andreeyka/my-ip-prefixes/main/not-cis.srs",
      "format": "binary"
    }}
  ]
}}
```
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Многоуровневая классификация IPv4 по покрытию префиксами выбранных стран"
    )
    parser.add_argument(
        "--countries", type=str,
        default=",".join(DEFAULT_COUNTRIES),
        help=f"Коды стран через запятую (по умолчанию: {','.join(DEFAULT_COUNTRIES)})"
    )
    def_levels_str = ",".join(f"{p}:{t}" for p, t in DEFAULT_LEVELS)
    parser.add_argument(
        "--levels", type=str,
        default=def_levels_str,
        help=f"Уровни в формате 'prefix:threshold%%,...' (по умолчанию {def_levels_str})"
    )
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Путь для сохранения не-наших префиксов в JSON (sing-box rule-set формат)"
    )
    parser.add_argument(
        "--compile", "-c", action="store_true",
        help="Скомпилировать результат в .srs (требует --output)"
    )
    args = parser.parse_args()

    countries = [c.strip().lower() for c in args.countries.split(",")]

    levels: list[tuple[int, float]] = []
    for part in args.levels.split(","):
        prefix_str, thresh_str = part.split(":")
        levels.append((int(prefix_str), int(thresh_str) / 100))

    print(f"Загрузка: {', '.join(c.upper() for c in countries)}")

    all_cidrs, country_stats = load_ip_cidrs(countries)
    if not all_cidrs:
        print("Нет данных для обработки", file=sys.stderr)
        sys.exit(1)

    networks = list(collapse_addresses(sorted(
        [IPv4Network(c, strict=False) for c in all_cidrs],
        key=lambda n: int(n.network_address),
    )))
    original_cidrs = [str(n) for n in networks]
    original_ips = sum(n.num_addresses for n in networks)

    print(f"Исходных: {len(original_cidrs)} префиксов ({original_ips:,} IP)")
    print(f"Классификация ({', '.join(f'/{p}:{t:.0%}' for p, t in levels)}):",
          file=sys.stderr)

    ru_blocks, not_ru_blocks = classify_multilevel(original_cidrs, levels)

    ru_ips = sum(n.num_addresses for n in ru_blocks)
    not_ru_ips = sum(n.num_addresses for n in not_ru_blocks)
    exact_not_ru_ips = 2**32 - original_ips

    foreign_lost = max(0, exact_not_ru_ips - not_ru_ips)
    foreign_lost_pct = foreign_lost / exact_not_ru_ips * 100

    leaked = max(0, original_ips - ru_ips)
    leaked_pct = leaked / original_ips * 100

    print(f"Результат: {len(not_ru_blocks)} не-наших, {len(ru_blocks)} наших префиксов")
    print(f"Потеря: {foreign_lost_pct:.2f}%, Утечка: {leaked_pct:.2f}%")

    # Генерация README.md
    readme = generate_readme(
        countries=countries,
        country_stats=country_stats,
        levels=levels,
        original_count=len(original_cidrs),
        original_ips=original_ips,
        not_ru_count=len(not_ru_blocks),
        ru_count=len(ru_blocks),
        foreign_lost_pct=foreign_lost_pct,
        leaked_pct=leaked_pct,
    )
    Path("README.md").write_text(readme)
    print("README.md обновлён")

    if args.output:
        output_path = Path(args.output)
        ruleset = {
            "version": 1,
            "rules": [
                {"ip_cidr": [str(n) for n in not_ru_blocks]}
            ],
        }
        output_path.write_text(json.dumps(ruleset, indent=2) + "\n")

        if args.compile:
            srs_path = output_path.with_suffix(".srs")
            result = subprocess.run(
                ["sing-box", "rule-set", "compile",
                 "--output", str(srs_path), str(output_path)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                print(f"Ошибка компиляции: {result.stderr}", file=sys.stderr)
                sys.exit(1)
            output_path.unlink()
            print(f"Сохранён: {srs_path}")
        else:
            print(f"Сохранён: {output_path}")


if __name__ == "__main__":
    main()
