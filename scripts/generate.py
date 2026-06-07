#!/usr/bin/env python3
"""
Конвертер roscomvpn-routing → Shadowrocket .list + .conf.
Источник правил: https://github.com/hydraponique/roscomvpn-routing

Важно:
- lists/*.list и roscomvpn.conf генерируются автоматически;
- ручные закреплённые правила хранить в custom/my-rules.conf;
- custom/my-rules.conf вставляется в итоговый конфиг выше DIRECT/GEOIP/IP-CIDR.
"""

import os
import re
import base64
import requests
from datetime import datetime, timezone

GEOSITE_API = "https://api.github.com/repos/hydraponique/roscomvpn-geosite/contents/data/{}"
GEOIP_TEXT = "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geoip/release/text/{}"

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")
OUTPUT_DIR = os.path.join(ROOT_DIR, "lists")
CONF_PATH = os.path.join(ROOT_DIR, "roscomvpn.conf")
CUSTOM_RULES_PATH = os.path.join(ROOT_DIR, "custom", "my-rules.conf")

GITHUB_REPO = os.environ.get("GITHUB_REPO", "forg-lib-lov/roscomvpn-shadowrocket")
RAW_BASE = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/lists"
CONF_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/roscomvpn.conf"

# Формат: (source_name, type, action, output_filename)
# Порядок важен: REJECT → PROXY → CUSTOM → DIRECT.
DOMAIN_RULES = [
    ("win-spy", "geosite", "REJECT", "win-spy.list"),
    ("category-ads", "geosite", "REJECT", "category-ads.list"),

    ("twitch-ads", "geosite", "PROXY", "twitch-ads.list"),
    ("youtube", "geosite", "PROXY", "youtube.list"),
    ("telegram", "geosite", "PROXY", "telegram.list"),
    ("github", "geosite", "PROXY", "github.list"),
    ("tiktok", "geosite", "PROXY", "tiktok.list"),

    ("private", "geosite", "DIRECT", "private-domains.list"),
    ("torrent", "geosite", "DIRECT", "torrent-domains.list"),
    ("epicgames", "geosite", "DIRECT", "epicgames.list"),
    ("origin", "geosite", "DIRECT", "origin.list"),
    ("riot", "geosite", "DIRECT", "riot.list"),
    ("escapefromtarkov", "geosite", "DIRECT", "escapefromtarkov.list"),
    ("steam", "geosite", "DIRECT", "steam.list"),
    ("faceit", "geosite", "DIRECT", "faceit.list"),
    ("twitch", "geosite", "DIRECT", "twitch.list"),
    ("microsoft", "geosite", "DIRECT", "microsoft.list"),
    ("apple", "geosite", "DIRECT", "apple.list"),
    ("google-play", "geosite", "DIRECT", "google-play.list"),
    ("pinterest", "geosite", "DIRECT", "pinterest.list"),
    ("whitelist", "geosite", "DIRECT", "whitelist-domains.list"),
    ("category-ru", "geosite", "DIRECT", "category-ru.list"),
]

# Формат: (source_name, type, action, output_filename, no_resolve)
IP_RULES = [
    ("private", "geoip", "DIRECT", "private-ips.list", True),
    ("whitelist", "geoip", "DIRECT", "whitelist-ips.list", True),
    ("direct", "geoip", "DIRECT", "direct-ips.list", False),
]

# Формат: (url, action, output_filename)
PLAIN_URL_RULES = [
    (
        "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt",
        "DIRECT",
        "hxehex-whitelist.list",
    ),
]


def load_custom_rules(path: str = CUSTOM_RULES_PATH) -> list[str]:
    """Читает пользовательские закреплённые правила из custom/my-rules.conf."""
    if not os.path.exists(path):
        return []

    rules = []
    with open(path, encoding="utf-8") as f:
        for raw in f.read().splitlines():
            line = raw.strip()
            if line:
                rules.append(line)

    return rules


def fetch_plain_domains(url: str) -> list[str]:
    """Загружает plain-text домены и конвертирует их в DOMAIN-SUFFIX."""
    r = requests.get(url, timeout=30)
    if r.status_code != 200:
        print(f"  WARN: {url} → HTTP {r.status_code}")
        return []

    lines = []
    for raw in r.text.splitlines():
        domain = raw.strip()
        if not domain or domain.startswith("#"):
            continue
        if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", domain):
            lines.append(f"DOMAIN-SUFFIX,{domain}")

    return lines


def fetch_geosite(category: str) -> list[str]:
    """Загружает data/<category> через GitHub API и конвертирует в Shadowrocket-строки."""
    url = GEOSITE_API.format(category)
    r = requests.get(url, timeout=30)
    if r.status_code != 200:
        print(f"  WARN: {category} → HTTP {r.status_code}")
        return []

    content = base64.b64decode(r.json()["content"]).decode("utf-8", errors="replace")
    lines = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("@"):
            continue
        if line.startswith("include:"):
            lines.extend(fetch_geosite(line[8:].strip().lower()))
        elif line.startswith("full:"):
            lines.append(f"DOMAIN,{line[5:].strip()}")
        elif line.startswith("domain:"):
            lines.append(f"DOMAIN-SUFFIX,{line[7:].strip()}")
        elif line.startswith("keyword:"):
            lines.append(f"DOMAIN-KEYWORD,{line[8:].strip()}")
        elif line.startswith("regexp:"):
            pass
        elif re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]+)\.[a-zA-Z]{2,}$", line):
            lines.append(f"DOMAIN-SUFFIX,{line}")

    return lines


def fetch_geoip(name: str, no_resolve: bool = True) -> list[str]:
    """Загружает release/text/<name>.txt и конвертирует CIDR в IP-CIDR строки."""
    url = GEOIP_TEXT.format(f"{name}.txt")
    r = requests.get(url, timeout=60)
    if r.status_code != 200:
        print(f"  WARN: geoip/{name} → HTTP {r.status_code}")
        return []

    suffix = ",no-resolve" if no_resolve else ""
    lines = []
    for raw in r.text.splitlines():
        cidr = raw.strip()
        if not cidr or cidr.startswith("#"):
            continue
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", cidr):
            lines.append(f"IP-CIDR,{cidr}{suffix}")
        elif re.match(r"^[0-9a-fA-F:]+/\d{1,3}$", cidr):
            lines.append(f"IP-CIDR6,{cidr}{suffix}")

    return lines


def write_list(filename: str, entries: list[str], source: str):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        f"# NAME: {filename}",
        f"# SOURCE: {source}",
        f"# UPDATED: {now}",
        f"# TOTAL: {len(entries)}",
        "",
    ]
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(header + entries) + "\n")
    print(f"  ✓ lists/{filename}  ({len(entries)} rules)")


def build_conf(domain_rules, ip_rules):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    private_ip = next((r for r in ip_rules if r[3] == "private-ips.list"), None)
    other_ip_rules = [r for r in ip_rules if r[3] != "private-ips.list"]
    custom_rules = load_custom_rules()

    general = f"""# roscomvpn-shadowrocket — auto-generated {now}
# Source: https://github.com/hydraponique/roscomvpn-routing
# Repo:   https://github.com/{GITHUB_REPO}

[General]
bypass-system = true
ipv6 = false
prefer-ipv6 = false
private-ip-answer = true
dns-direct-system = false
dns-fallback-system = true
dns-direct-fallback-proxy = true

# Яндекс DNS для прямого трафика
# Google DNS для проксированного трафика
dns-server = https://77.88.8.8/dns-query, https://8.8.8.8/dns-query
fallback-dns-server = system
hijack-dns = :53

skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com
tun-excluded-routes = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32,239.255.255.250/32
tun-included-routes =

always-real-ip = time.*.com,ntp.*.com,*.cloudflareclient.com,*.apple.com
icmp-auto-reply = false
always-reject-url-rewrite = false
udp-policy-not-supported-behaviour = REJECT

# Shadowrocket будет проверять обновления по этому URL
update-url = {CONF_URL}
"""

    rule_lines = ["", "[Rule]"]

    if private_ip:
        _, _, _, outfile, _ = private_ip
        url = f"{RAW_BASE}/{outfile}"
        rule_lines.append("# ── Локальная сеть ──")
        rule_lines.append(f"RULE-SET,{url},DIRECT,no-resolve")
        rule_lines.append("")

    all_rules = domain_rules + other_ip_rules
    processed_actions = []
    custom_inserted = False

    for name, rtype, act, outfile, *flags in all_rules:
        no_resolve = flags[0] if flags else False

        if act == "DIRECT" and custom_rules and not custom_inserted:
            rule_lines.append("")
            rule_lines.append("# ═══ CUSTOM PINNED RULES (не затираются автообновлением) ═══")
            rule_lines.extend(custom_rules)
            rule_lines.append("")
            custom_inserted = True

        headers = {
            "REJECT": "# ═══ BLOCK ═══════════════════════════════════════════",
            "PROXY": "# ═══ PROXY (через VPN) ══════════════════════════════",
            "DIRECT": "# ═══ DIRECT (напрямую) ══════════════════════════════",
        }
        if act not in processed_actions:
            rule_lines.append(headers.get(act, f"# ═══ {act} ═══"))
            processed_actions.append(act)

        url = f"{RAW_BASE}/{outfile}"
        if no_resolve:
            rule_lines.append(f"RULE-SET,{url},{act},no-resolve")
        else:
            rule_lines.append(f"RULE-SET,{url},{act}")

    if custom_rules and not custom_inserted:
        rule_lines.append("")
        rule_lines.append("# ═══ CUSTOM PINNED RULES (не затираются автообновлением) ═══")
        rule_lines.extend(custom_rules)
        rule_lines.append("")

    if PLAIN_URL_RULES:
        rule_lines.append("")
        rule_lines.append("# ── Дополнительные DIRECT-домены ──")
        for _, _, outfile in PLAIN_URL_RULES:
            list_url = f"{RAW_BASE}/{outfile}"
            rule_lines.append(f"RULE-SET,{list_url},DIRECT")

    rule_lines.append("")
    rule_lines.append("# ── GEOIP: страховка для РФ/BY доменов вне category-ru ──")
    rule_lines.append("GEOIP,RU,DIRECT")
    rule_lines.append("GEOIP,BY,DIRECT")
    rule_lines.append("")
    rule_lines.append("FINAL,PROXY")
    rule_lines.append("")

    result_lines = []
    prev_empty = False
    for line in rule_lines:
        if line == "":
            if not prev_empty:
                result_lines.append(line)
            prev_empty = True
        else:
            result_lines.append(line)
            prev_empty = False

    return general + "\n".join(result_lines)


def main():
    print("=== Генерация Shadowrocket конфига из roscomvpn-routing ===\n")

    print("── Domain lists (geosite) ─────────────────────────────")
    for name, rtype, action, outfile in DOMAIN_RULES:
        if rtype != "geosite":
            continue
        print(f"  Fetching geosite/{name}...")
        entries = fetch_geosite(name)
        if not entries:
            print(f"  SKIP: {name} (empty)")
            continue
        write_list(
            outfile,
            entries,
            f"https://github.com/hydraponique/roscomvpn-geosite/blob/master/data/{name}",
        )

    print("\n── IP lists (geoip) ───────────────────────────────────")
    for name, rtype, action, outfile, no_resolve in IP_RULES:
        if rtype != "geoip":
            continue
        print(f"  Fetching geoip/{name}.txt (no-resolve={no_resolve})...")
        entries = fetch_geoip(name, no_resolve=no_resolve)
        if not entries:
            print(f"  SKIP: {name} (empty)")
            continue
        write_list(
            outfile,
            entries,
            f"https://github.com/hydraponique/roscomvpn-geoip/blob/master/release/text/{name}.txt",
        )

    if PLAIN_URL_RULES:
        print("\n── Plain-URL domain lists ─────────────────────────────")
        for src_url, _, outfile in PLAIN_URL_RULES:
            print(f"  Fetching {src_url}...")
            entries = fetch_plain_domains(src_url)
            if not entries:
                print(f"  SKIP: {outfile} (empty)")
                continue
            write_list(outfile, entries, src_url)

    print("\n── Генерация roscomvpn.conf ───────────────────────────")
    conf_content = build_conf(DOMAIN_RULES, IP_RULES)
    with open(CONF_PATH, "w", encoding="utf-8") as f:
        f.write(conf_content)
    print("  ✓ roscomvpn.conf")

    print("\n=== Готово! ===")


if __name__ == "__main__":
    main()
