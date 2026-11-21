#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Convert common proxy share links into a Mihomo-compatible YAML profile."""

import argparse
import base64
import html
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

import yaml


def first(query, key, default=""):
    values = query.get(key)
    return values[0] if values else default


def truthy(value):
    return str(value).lower() in ("1", "true", "yes")


def decode_name(fragment, fallback):
    name = unquote(fragment or "").strip()
    return name or fallback


def tls_fields(query, default=False):
    security = first(query, "security", "tls" if default else "").lower()
    enabled = security in ("tls", "reality")
    result = {"tls": enabled}
    sni = first(query, "sni") or first(query, "servername")
    if sni:
        result["servername"] = sni
    fp = first(query, "fp")
    if fp:
        result["client-fingerprint"] = fp
    alpn = first(query, "alpn")
    if alpn:
        result["alpn"] = [x for x in alpn.split(",") if x]
    if truthy(first(query, "insecure")) or truthy(first(query, "allowInsecure")):
        result["skip-cert-verify"] = True
    return result


def convert_vless(parts, fallback):
    host = parts.hostname
    port = parts.port
    uuid = unquote(parts.username or "")
    if not host or not port or not uuid:
        raise ValueError("VLESS URI missing server, port, or UUID")
    q = parse_qs(parts.query, keep_blank_values=True)
    node = {"name": decode_name(parts.fragment, fallback), "type": "vless",
            "server": host, "port": port, "uuid": uuid, "udp": True,
            "encryption": first(q, "encryption", "none")}
    network = first(q, "type", "tcp").lower()
    if network in ("ws", "grpc", "tcp", "http", "httpupgrade", "xhttp"):
        node["network"] = network
    node.update(tls_fields(q))
    if first(q, "flow"):
        node["flow"] = first(q, "flow")
    if network == "ws":
        ws = {}
        path = first(q, "path")
        host_header = first(q, "host")
        if path:
            ws["path"] = path
        if host_header:
            ws["headers"] = {"Host": host_header}
        if ws:
            node["ws-opts"] = ws
    elif network == "grpc":
        service = first(q, "serviceName") or first(q, "service-name")
        if service:
            node["grpc-opts"] = {"grpc-service-name": service}
    if first(q, "security").lower() == "reality":
        reality = {}
        if first(q, "pbk"):
            reality["public-key"] = first(q, "pbk")
        if first(q, "sid"):
            reality["short-id"] = first(q, "sid")
        if reality:
            node["reality-opts"] = reality
        node["tls"] = True
    return node


def convert_trojan(parts, fallback):
    host, port = parts.hostname, parts.port
    password = unquote(parts.username or "")
    if not host or not port or not password:
        raise ValueError("Trojan URI missing server, port, or password")
    q = parse_qs(parts.query, keep_blank_values=True)
    node = {"name": decode_name(parts.fragment, fallback), "type": "trojan",
            "server": host, "port": port, "password": password, "udp": True}
    network = first(q, "type", "tcp").lower()
    if network in ("ws", "grpc"):
        node["network"] = network
        if network == "ws":
            ws = {}
            if first(q, "path"):
                ws["path"] = first(q, "path")
            if first(q, "host"):
                ws["headers"] = {"Host": first(q, "host")}
            if ws:
                node["ws-opts"] = ws
        elif first(q, "serviceName"):
            node["grpc-opts"] = {"grpc-service-name": first(q, "serviceName")}
    node.update(tls_fields(q, default=True))
    return node


def decode_base64_text(value):
    value = value.strip()
    value += "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value).decode("utf-8")
    except Exception:
        return base64.b64decode(value).decode("utf-8")


def convert_vmess(uri, fallback):
    raw = uri[len("vmess://"):]
    data = json.loads(decode_base64_text(raw))
    host = data.get("add") or data.get("host")
    port = int(data.get("port", 0))
    if not host or not port or not data.get("id"):
        raise ValueError("VMess URI missing server, port, or UUID")
    node = {"name": data.get("ps") or fallback, "type": "vmess",
            "server": host, "port": port, "uuid": data["id"],
            "alterId": int(data.get("aid", 0)), "cipher": data.get("scy") or "auto",
            "udp": True}
    network = (data.get("net") or "tcp").lower()
    if network in ("ws", "grpc", "http", "h2"):
        node["network"] = "ws" if network == "h2" else network
    if str(data.get("tls", "")).lower() in ("tls", "true", "1"):
        node["tls"] = True
        if data.get("sni"):
            node["servername"] = data["sni"]
        elif data.get("host") and network != "ws":
            node["servername"] = data["host"]
    if data.get("fp"):
        node["client-fingerprint"] = data["fp"]
    if network == "ws":
        ws = {}
        if data.get("path"):
            ws["path"] = data["path"]
        if data.get("host"):
            ws["headers"] = {"Host": data["host"]}
        if ws:
            node["ws-opts"] = ws
    return node


def convert_ss(uri, fallback):
    raw = uri[len("ss://"):]
    fragment = ""
    if "#" in raw:
        raw, fragment = raw.split("#", 1)
    query_text = ""
    if "?" in raw:
        raw, query_text = raw.split("?", 1)
    if "@" in raw:
        userinfo, server = raw.rsplit("@", 1)
        try:
            decoded = decode_base64_text(userinfo)
        except Exception:
            decoded = unquote(userinfo)
        if ":" not in decoded:
            raise ValueError("Shadowsocks userinfo missing method:password")
        method, password = decoded.split(":", 1)
    else:
        decoded = decode_base64_text(raw)
        userinfo, server = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
    endpoint = urlsplit("ss://" + server)
    if not endpoint.hostname or not endpoint.port:
        raise ValueError("Shadowsocks URI missing server or port")
    node = {"name": decode_name(fragment, fallback), "type": "ss",
            "server": endpoint.hostname, "port": endpoint.port,
            "cipher": method, "password": password, "udp": True}
    q = parse_qs(query_text, keep_blank_values=True)
    plugin = first(q, "plugin")
    if plugin:
        node["plugin"] = plugin.split(";", 1)[0]
        if ";" in plugin:
            node["plugin-opts"] = dict(
                item.split("=", 1) for item in plugin.split(";")[1:] if "=" in item
            )
    return node


def convert_hy2(parts, fallback):
    host, port = parts.hostname, parts.port
    password = unquote(parts.username or "")
    if not host or not port or not password:
        raise ValueError("Hysteria2 URI missing server, port, or password")
    q = parse_qs(parts.query, keep_blank_values=True)
    node = {"name": decode_name(parts.fragment, fallback), "type": "hysteria2",
            "server": host, "port": port, "password": password, "tls": True,
            "sni": first(q, "sni") or host, "skip-cert-verify": truthy(first(q, "insecure")),
            "udp": True}
    obfs = first(q, "obfs")
    if obfs:
        node["obfs"] = obfs
        if first(q, "obfs-password"):
            node["obfs-password"] = first(q, "obfs-password")
    return node


def convert(line, index):
    line = html.unescape(line.strip())
    if not line or line.startswith("#"):
        return None
    scheme = line.split(":", 1)[0].lower()
    fallback = f"{scheme.upper()}-{index}"
    if scheme == "vmess":
        return convert_vmess(line, fallback)
    parts = urlsplit(line)
    if scheme == "vless":
        return convert_vless(parts, fallback)
    if scheme == "trojan":
        return convert_trojan(parts, fallback)
    if scheme in ("hysteria2", "hy2"):
        return convert_hy2(parts, fallback)
    if scheme == "ss":
        return convert_ss(line, fallback)
    raise ValueError(f"unsupported scheme: {scheme}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="sub/high_quality_nodes.txt")
    parser.add_argument("--output", default="test_nodes.yaml")
    args = parser.parse_args()

    proxies = []
    errors = []
    with open(args.input, "r", encoding="utf-8-sig") as handle:
        for index, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                node = convert(raw, index)
                if node:
                    proxies.append(node)
            except Exception as exc:
                errors.append(f"line {index}: {exc}")

    if not proxies:
        raise SystemExit("No supported proxy URI could be converted; YAML was not written.")

    # Keep names unique so Mihomo can load every proxy.
    seen = {}
    for node in proxies:
        name = str(node["name"])
        seen[name] = seen.get(name, 0) + 1
        if seen[name] > 1:
            node["name"] = f"{name} ({seen[name]})"

    names = [node["name"] for node in proxies]
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "proxies": proxies,
        "proxy-groups": [{"name": "Proxy", "type": "select", "proxies": names + ["DIRECT"]}],
        "rules": ["MATCH,Proxy"],
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, allow_unicode=True, sort_keys=False)

    print(f"✅ Mihomo YAML generated: {args.output}")
    print(f"✅ Converted proxies: {len(proxies)}")
    if errors:
        print(f"⚠️ Skipped {len(errors)} unsupported/invalid entries (first 20):")
        for message in errors[:20]:
            print(f"  - {message}")


if __name__ == "__main__":
    main()
