#!/usr/bin/env python3
"""
VPN Keys Checker Pro - максимально точная проверка ключей
Многоуровневая проверка: TCP → Sing-box → IP → Download → Latency
"""

import os
import base64
import asyncio
import json
import subprocess
import tempfile
import hashlib
import time
import socket
from urllib.parse import urlparse, unquote, parse_qs
from typing import Optional, Tuple
from dataclasses import dataclass
import aiohttp
from aiohttp_socks import ProxyConnector

# ============== НАСТРОЙКИ ==============
TIMEOUT_TCP = 5          # Таймаут TCP пинга
TIMEOUT_PROXY = 25       # Таймаут проверки через прокси
STARTUP_DELAY = 3        # Время запуска sing-box
MAX_CONCURRENT = 50      # Параллельных проверок (агрессивно)
MAX_LATENCY_MS = 3000    # Максимальный пинг (мс)
MIN_SPEED_KBPS = 50      # Минимальная скорость (KB/s)

# Тестовые URL
TEST_FILE_URL = "https://www.google.com/favicon.ico"  # ~1KB файл
TEST_FILE_HASH = None  # Будет вычислен динамически
IP_CHECK_URLS = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://icanhazip.com"
]
CONNECTIVITY_URLS = [
    "https://www.google.com/generate_204",
    "https://cp.cloudflare.com/",
    "https://connectivitycheck.gstatic.com/generate_204"
]


@dataclass
class CheckResult:
    """Результат проверки ключа"""
    key: str
    working: bool
    tcp_ok: bool = False
    proxy_ok: bool = False
    ip_changed: bool = False
    download_ok: bool = False
    latency_ms: int = 0
    speed_kbps: float = 0
    exit_ip: str = ""
    exit_country: str = ""
    country_code: str = ""
    isp: str = ""
    error: str = ""


# Флаги стран
COUNTRY_FLAGS = {
    "RU": "🇷🇺", "DE": "🇩🇪", "NL": "🇳🇱", "US": "🇺🇸", "GB": "🇬🇧",
    "FR": "🇫🇷", "FI": "🇫🇮", "SE": "🇸🇪", "NO": "🇳🇴", "PL": "🇵🇱",
    "UA": "🇺🇦", "KZ": "🇰🇿", "BY": "🇧🇾", "LT": "🇱🇹", "LV": "🇱🇻",
    "EE": "🇪🇪", "CZ": "🇨🇿", "AT": "🇦🇹", "CH": "🇨🇭", "IT": "🇮🇹",
    "ES": "🇪🇸", "PT": "🇵🇹", "GR": "🇬🇷", "TR": "🇹🇷", "IL": "🇮🇱",
    "AE": "🇦🇪", "SG": "🇸🇬", "JP": "🇯🇵", "KR": "🇰🇷", "HK": "🇭🇰",
    "TW": "🇹🇼", "AU": "🇦🇺", "CA": "🇨🇦", "BR": "🇧🇷", "IN": "🇮🇳",
    "AM": "🇦🇲", "GE": "🇬🇪", "MD": "🇲🇩", "RO": "🇷🇴", "BG": "🇧🇬",
    "HU": "🇭🇺", "SK": "🇸🇰", "RS": "🇷🇸", "HR": "🇭🇷", "SI": "🇸🇮",
    "IE": "🇮🇪", "BE": "🇧🇪", "LU": "🇱🇺", "DK": "🇩🇰", "IS": "🇮🇸",
}

# Приоритет сортировки стран (меньше = выше)
COUNTRY_PRIORITY = {
    # СНГ
    "RU": 0,   # Россия
    "KZ": 1,   # Казахстан
    "BY": 2,   # Беларусь
    "UA": 3,   # Украина
    "AM": 4,   # Армения
    "GE": 5,   # Грузия
    "MD": 6,   # Молдова
    # Европа - основные
    "DE": 10,  # Германия
    "NL": 11,  # Нидерланды
    "FI": 12,  # Финляндия
    "SE": 13,  # Швеция
    "NO": 14,  # Норвегия
    "PL": 15,  # Польша
    "FR": 16,  # Франция
    "GB": 17,  # Великобритания
    # Прибалтика
    "LT": 20,  # Литва
    "LV": 21,  # Латвия
    "EE": 22,  # Эстония
    # Европа - остальные
    "AT": 30,  # Австрия
    "CH": 31,  # Швейцария
    "BE": 32,  # Бельгия
    "LU": 33,  # Люксембург
    "DK": 34,  # Дания
    "IE": 35,  # Ирландия
    "CZ": 36,  # Чехия
    "SK": 37,  # Словакия
    "HU": 38,  # Венгрия
    "RO": 39,  # Румыния
    "BG": 40,  # Болгария
    "RS": 41,  # Сербия
    "HR": 42,  # Хорватия
    "SI": 43,  # Словения
    "GR": 44,  # Греция
    "IT": 45,  # Италия
    "ES": 46,  # Испания
    "PT": 47,  # Португалия
    "IS": 48,  # Исландия
    # Ближний Восток
    "TR": 50,  # Турция
    "IL": 51,  # Израиль
    "AE": 52,  # ОАЭ
    # Азия
    "JP": 60,  # Япония
    "KR": 61,  # Южная Корея
    "HK": 62,  # Гонконг
    "TW": 63,  # Тайвань
    "SG": 64,  # Сингапур
    "IN": 65,  # Индия
    # Америка
    "US": 70,  # США
    "CA": 71,  # Канада
    "BR": 72,  # Бразилия
    # Океания
    "AU": 80,  # Австралия
}


def decode_base64(data: str) -> str:
    """Декодирует base64"""
    for decoder in [base64.urlsafe_b64decode, base64.b64decode]:
        try:
            padding = 4 - len(data) % 4
            if padding != 4:
                data_padded = data + '=' * padding
            else:
                data_padded = data
            return decoder(data_padded).decode('utf-8', errors='ignore')
        except:
            continue
    return ""


def parse_subscription(content: str) -> list[str]:
    """Парсит подписку (поддерживает разделение через \\n, пробелы, или смешанное)"""
    import re
    
    # Пробуем декодировать base64
    decoded = decode_base64(content.strip())
    if decoded and any(p in decoded for p in ['vless://', 'vmess://', 'ss://', 'trojan://']):
        content = decoded
    
    protocols = ['vless://', 'vmess://', 'ss://', 'trojan://', 
                 'hysteria2://', 'hy2://', 'hysteria://', 'tuic://']
    
    keys = []
    
    # Сначала пробуем стандартный парсинг по строкам
    for line in content.split('\n'):
        line = line.strip()
        if any(line.startswith(p) for p in protocols):
            keys.append(line)
    
    # Если нашли мало ключей, но в контенте есть протоколы — используем regex
    # (для подписок где ключи разделены пробелами)
    if len(keys) < 10 and any(p in content for p in protocols):
        keys = []
        for proto in protocols:
            # Ищем от протокола до пробела/переноса
            pattern = re.escape(proto) + r'[^\s\n]+' 
            matches = re.findall(pattern, content)
            keys.extend(matches)
    
    # Убираем дубликаты сохраняя порядок
    seen = set()
    unique_keys = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            unique_keys.append(k)
    
    return unique_keys


def get_key_name(key: str) -> str:
    """Извлекает имя ключа для логов"""
    if '#' in key:
        return unquote(key.split('#')[-1])[:35]
    try:
        parsed = urlparse(key)
        return f"{parsed.hostname}:{parsed.port}"[:35]
    except:
        return key[:35]


async def get_ip_info(session: aiohttp.ClientSession, ip: str) -> Tuple[str, str, str]:
    """Получает информацию об IP: страна, код страны, провайдер"""
    try:
        # Используем ip-api.com (бесплатный, без ключа)
        async with session.get(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode,isp,org",
            ssl=False
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                country = data.get('country', 'Unknown')
                code = data.get('countryCode', 'XX')
                isp = data.get('isp', '') or data.get('org', 'Unknown')
                # Сокращаем название провайдера
                isp = isp.replace('LLC', '').replace('Ltd', '').replace('Limited', '')
                isp = isp.replace('Corporation', '').replace('Inc.', '').strip()
                if len(isp) > 25:
                    isp = isp[:22] + "..."
                return country, code, isp
    except:
        pass
    return "Unknown", "XX", "Unknown"


def get_host_port(key: str) -> Optional[Tuple[str, int]]:
    """Извлекает хост и порт из ключа"""
    try:
        if key.startswith('vmess://'):
            data = json.loads(decode_base64(key[8:]))
            return data.get('add'), int(data.get('port', 443))
        else:
            parsed = urlparse(key)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
    except:
        pass
    return None


# ============== SING-BOX CONFIG GENERATORS ==============

def parse_vless_to_singbox(uri: str) -> Optional[dict]:
    """VLESS → Sing-box outbound"""
    try:
        parsed = urlparse(uri)
        params = dict(p.split('=', 1) for p in parsed.query.split('&') if '=' in p)
        
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "uuid": parsed.username,
            "flow": params.get('flow', ''),
        }
        
        # TLS
        security = params.get('security', 'none')
        if security == 'tls':
            outbound["tls"] = {
                "enabled": True,
                "server_name": params.get('sni', parsed.hostname),
                "insecure": True,
                "utls": {"enabled": True, "fingerprint": params.get('fp', 'chrome')}
            }
        elif security == 'reality':
            outbound["tls"] = {
                "enabled": True,
                "server_name": params.get('sni', ''),
                "insecure": True,
                "utls": {"enabled": True, "fingerprint": params.get('fp', 'chrome')},
                "reality": {
                    "enabled": True,
                    "public_key": params.get('pbk', ''),
                    "short_id": params.get('sid', '')
                }
            }
        
        # Transport
        transport_type = params.get('type', 'tcp')
        if transport_type == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": unquote(params.get('path', '/')),
                "headers": {"Host": params.get('host', parsed.hostname)}
            }
        elif transport_type == 'grpc':
            outbound["transport"] = {
                "type": "grpc",
                "service_name": params.get('serviceName', '')
            }
        elif transport_type == 'http':
            outbound["transport"] = {
                "type": "http",
                "path": unquote(params.get('path', '/'))
            }
        
        return outbound
    except:
        return None


def parse_vmess_to_singbox(uri: str) -> Optional[dict]:
    """VMess → Sing-box outbound"""
    try:
        data = json.loads(decode_base64(uri[8:]))
        
        outbound = {
            "type": "vmess",
            "tag": "proxy",
            "server": data.get('add'),
            "server_port": int(data.get('port', 443)),
            "uuid": data.get('id'),
            "security": data.get('scy', 'auto'),
            "alter_id": int(data.get('aid', 0))
        }
        
        if data.get('tls') == 'tls':
            outbound["tls"] = {
                "enabled": True,
                "server_name": data.get('sni', data.get('host', '')),
                "insecure": True
            }
        
        net = data.get('net', 'tcp')
        if net == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": data.get('path', '/'),
                "headers": {"Host": data.get('host', '')}
            }
        elif net == 'grpc':
            outbound["transport"] = {
                "type": "grpc",
                "service_name": data.get('path', '')
            }
        elif net == 'h2':
            outbound["transport"] = {
                "type": "http",
                "path": data.get('path', '/')
            }
        
        return outbound
    except:
        return None


def parse_trojan_to_singbox(uri: str) -> Optional[dict]:
    """Trojan → Sing-box outbound"""
    try:
        parsed = urlparse(uri)
        params = dict(p.split('=', 1) for p in parsed.query.split('&') if '=' in p)
        
        outbound = {
            "type": "trojan",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": unquote(parsed.username),
            "tls": {
                "enabled": True,
                "server_name": params.get('sni', parsed.hostname),
                "insecure": True
            }
        }
        
        transport_type = params.get('type', 'tcp')
        if transport_type == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": unquote(params.get('path', '/'))
            }
        elif transport_type == 'grpc':
            outbound["transport"] = {
                "type": "grpc",
                "service_name": params.get('serviceName', '')
            }
        
        return outbound
    except:
        return None


def parse_ss_to_singbox(uri: str) -> Optional[dict]:
    """Shadowsocks → Sing-box outbound"""
    try:
        key_part = uri[5:].split('#')[0]
        
        if '@' in key_part:
            method_pass, host_port = key_part.rsplit('@', 1)
            decoded = decode_base64(method_pass)
            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                return None
            host, port = host_port.rsplit(':', 1)
        else:
            decoded = decode_base64(key_part)
            if '@' in decoded:
                method_pass, host_port = decoded.rsplit('@', 1)
                method, password = method_pass.split(':', 1)
                host, port = host_port.rsplit(':', 1)
            else:
                return None
        
        return {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": host,
            "server_port": int(port),
            "method": method,
            "password": password
        }
    except:
        return None


def parse_hysteria2_to_singbox(uri: str) -> Optional[dict]:
    """Hysteria2 → Sing-box outbound"""
    try:
        parsed = urlparse(uri)
        params = dict(p.split('=', 1) for p in parsed.query.split('&') if '=' in p)
        
        return {
            "type": "hysteria2",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": parsed.username or params.get('password', ''),
            "tls": {
                "enabled": True,
                "server_name": params.get('sni', parsed.hostname),
                "insecure": True
            }
        }
    except:
        return None


def key_to_singbox_config(key: str, socks_port: int) -> Optional[dict]:
    """Конвертирует ключ в sing-box конфиг"""
    outbound = None
    
    if key.startswith('vless://'):
        outbound = parse_vless_to_singbox(key)
    elif key.startswith('vmess://'):
        outbound = parse_vmess_to_singbox(key)
    elif key.startswith('trojan://'):
        outbound = parse_trojan_to_singbox(key)
    elif key.startswith('ss://'):
        outbound = parse_ss_to_singbox(key)
    elif key.startswith(('hysteria2://', 'hy2://')):
        outbound = parse_hysteria2_to_singbox(key)
    
    if not outbound:
        return None
    
    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}]
    }


# ============== ПРОВЕРКИ ==============

async def check_tcp(host: str, port: int) -> Tuple[bool, int]:
    """Быстрая TCP проверка + измерение latency"""
    start = time.time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TIMEOUT_TCP
        )
        latency = int((time.time() - start) * 1000)
        writer.close()
        await writer.wait_closed()
        return True, latency
    except:
        return False, 0


async def check_connectivity(session: aiohttp.ClientSession) -> Tuple[bool, str]:
    """Проверка базового соединения через прокси"""
    last_error = ""
    for url in CONNECTIVITY_URLS:
        try:
            async with session.get(url, allow_redirects=False, ssl=False) as resp:
                if resp.status in [200, 204, 301, 302, 403]:
                    return True, ""
                last_error = f"status={resp.status}"
        except asyncio.TimeoutError:
            last_error = "timeout"
        except Exception as e:
            last_error = f"{type(e).__name__}"
    return False, last_error


async def check_ip(session: aiohttp.ClientSession, my_ip: str) -> Tuple[bool, str]:
    """Проверка смены IP"""
    for url in IP_CHECK_URLS:
        try:
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if 'json' in url:
                        exit_ip = json.loads(text).get('ip', '')
                    else:
                        exit_ip = text.strip()
                    
                    if exit_ip and exit_ip != my_ip:
                        return True, exit_ip
        except:
            continue
    return False, ""


async def check_download(session: aiohttp.ClientSession) -> Tuple[bool, float]:
    """Проверка скачивания файла + скорость"""
    try:
        start = time.time()
        async with session.get(TEST_FILE_URL, ssl=False) as resp:
            if resp.status == 200:
                data = await resp.read()
                elapsed = time.time() - start
                if len(data) > 0 and elapsed > 0:
                    speed_kbps = (len(data) / 1024) / elapsed
                    return True, speed_kbps
    except:
        pass
    return False, 0


async def get_my_ip() -> str:
    """Получает текущий IP без прокси"""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get("https://api.ipify.org") as resp:
                return (await resp.text()).strip()
    except:
        return ""


async def check_key_full(
    key: str, 
    semaphore: asyncio.Semaphore, 
    counter: list, 
    total: int,
    my_ip: str
) -> CheckResult:
    """Полная многоуровневая проверка ключа"""
    
    async with semaphore:
        counter[0] += 1
        num = counter[0]
        port = 20000 + (num % 5000)
        name = get_key_name(key)
        
        result = CheckResult(key=key, working=False)
        
        print(f"\n[{num}/{total}] {name}", flush=True)
        
        # === ЭТАП 1: TCP Ping ===
        host_port = get_host_port(key)
        if host_port:
            host, port_server = host_port
            tcp_ok, latency = await check_tcp(host, port_server)
            result.tcp_ok = tcp_ok
            result.latency_ms = latency
            
            if not tcp_ok:
                print(f"  ✗ TCP: сервер недоступен", flush=True)
                return result
            
            if latency > MAX_LATENCY_MS:
                print(f"  ✗ TCP: слишком высокий пинг ({latency}ms)", flush=True)
                return result
            
            print(f"  ✓ TCP: {latency}ms", flush=True)
        
        # === ЭТАП 2: Sing-box ===
        config = key_to_singbox_config(key, port)
        if not config:
            print(f"  ✗ Config: не удалось распарсить", flush=True)
            result.error = "parse_error"
            return result
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            config_path = f.name
        
        process = None
        try:
            process = subprocess.Popen(
                ['sing-box', 'run', '-c', config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            await asyncio.sleep(STARTUP_DELAY)
            
            if process.poll() is not None:
                stderr = process.stderr.read().decode() if process.stderr else ""
                print(f"  ✗ Sing-box: процесс упал ({stderr[:50]})", flush=True)
                result.error = "singbox_crash"
                return result
            
            proxy_url = f"socks5://127.0.0.1:{port}"
            timeout = aiohttp.ClientTimeout(total=TIMEOUT_PROXY, connect=10)
            
            # Используем ProxyConnector для SOCKS5
            connector = ProxyConnector.from_url(proxy_url)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                
                # === ЭТАП 3: Базовое соединение ===
                conn_ok, conn_err = await check_connectivity(session)
                if not conn_ok:
                    print(f"  ✗ Proxy: нет соединения ({conn_err})", flush=True)
                    result.error = f"no_connectivity: {conn_err}"
                    return result
                
                result.proxy_ok = True
                print(f"  ✓ Proxy: соединение есть", flush=True)
                
                # === ЭТАП 4: IP проверка ===
                ip_changed, exit_ip = await check_ip(session, my_ip)
                result.ip_changed = ip_changed
                result.exit_ip = exit_ip
                
                if ip_changed:
                    # Получаем информацию о стране и провайдере
                    country, code, isp = await get_ip_info(session, exit_ip)
                    result.exit_country = country
                    result.country_code = code
                    result.isp = isp
                    flag = COUNTRY_FLAGS.get(code, "🌍")
                    print(f"  ✓ IP: {exit_ip} | {flag} {country} | {isp}", flush=True)
                else:
                    print(f"  ⚠ IP: не изменился (возможно прозрачный прокси)", flush=True)
                
                # === ЭТАП 5: Скачивание файла ===
                download_ok, speed = await check_download(session)
                result.download_ok = download_ok
                result.speed_kbps = speed
                
                if download_ok:
                    if speed >= MIN_SPEED_KBPS:
                        print(f"  ✓ Download: {speed:.1f} KB/s", flush=True)
                    else:
                        print(f"  ⚠ Download: слишком медленно ({speed:.1f} KB/s)", flush=True)
                else:
                    print(f"  ⚠ Download: не удалось скачать файл", flush=True)
            
            # === ИТОГ ===
            # Ключ рабочий если: TCP OK + Proxy OK + (IP изменился ИЛИ скачивание OK)
            result.working = result.tcp_ok and result.proxy_ok and (result.ip_changed or result.download_ok)
            
            if result.working:
                print(f"  ★ РАБОЧИЙ!", flush=True)
            else:
                print(f"  ✗ Не прошёл проверку", flush=True)
            
            return result
            
        except Exception as e:
            print(f"  ✗ Error: {e}", flush=True)
            result.error = str(e)
            return result
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
            try:
                os.unlink(config_path)
            except:
                pass


async def fetch_subscription(url: str) -> str:
    """Загружает подписку (с User-Agent как у VPN клиента)"""
    # User-Agent как у популярных VPN клиентов
    headers = {
        "User-Agent": "v2rayNG/1.8.5",
        "Accept": "*/*",
    }
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    return await resp.text()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return ""


async def main():
    print("=" * 60)
    print("VPN Keys Checker Pro")
    print("=" * 60)
    
    # Проверяем sing-box
    try:
        result = subprocess.run(['sing-box', 'version'], capture_output=True, text=True)
        print(f"Using: {result.stdout.split(chr(10))[0]}")
    except FileNotFoundError:
        print("ERROR: sing-box not found!")
        print("Falling back to xray...")
        # Можно добавить fallback на xray
        return
    
    # Получаем свой IP
    print("\nПолучаю текущий IP...")
    my_ip = await get_my_ip()
    if my_ip:
        print(f"Мой IP: {my_ip}")
    else:
        print("Не удалось получить IP (проверка IP будет пропущена)")
    
    # Загружаем подписки
    subscription_urls = os.environ.get('SUBSCRIPTION_URLS', '')
    
    if not subscription_urls:
        if os.path.exists('subscriptions.txt'):
            with open('subscriptions.txt', 'r') as f:
                subscription_urls = f.read()
    
    urls = [url.strip() for url in subscription_urls.split('\n') 
            if url.strip() and not url.strip().startswith('#')]
    
    if not urls:
        print("No subscription URLs found!")
        return
    
    all_keys = []
    print(f"\nЗагружаю {len(urls)} подписок...")
    
    for url in urls:
        print(f"  {url[:60]}...")
        content = await fetch_subscription(url)
        if content:
            keys = parse_subscription(content)
            print(f"    Найдено {len(keys)} ключей")
            all_keys.extend(keys)
    
    # Убираем дубликаты
    all_keys = list(set(all_keys))
    print(f"\nВсего уникальных ключей: {len(all_keys)}")
    
    if not all_keys:
        print("Ключи не найдены!")
        return
    
    # Проверяем
    print(f"\n{'=' * 60}")
    print("НАЧИНАЮ ПРОВЕРКУ")
    print(f"{'=' * 60}")
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    counter = [0]
    total = len(all_keys)
    
    tasks = [check_key_full(key, semaphore, counter, total, my_ip) for key in all_keys]
    results = await asyncio.gather(*tasks)
    
    # Фильтруем рабочие
    working = [r for r in results if r.working]
    
    # Сортируем по качеству (пинг + скорость)
    working.sort(key=lambda r: (r.latency_ms, -r.speed_kbps))
    
    # Статистика
    print(f"\n{'=' * 60}")
    print("РЕЗУЛЬТАТЫ")
    print(f"{'=' * 60}")
    print(f"Всего проверено: {len(results)}")
    print(f"TCP доступны: {sum(1 for r in results if r.tcp_ok)}")
    print(f"Proxy работает: {sum(1 for r in results if r.proxy_ok)}")
    print(f"IP изменился: {sum(1 for r in results if r.ip_changed)}")
    print(f"Download OK: {sum(1 for r in results if r.download_ok)}")
    print(f"\n★ РАБОЧИХ КЛЮЧЕЙ: {len(working)}")
    
    if working:
        # Сортируем по: 1) страна (Россия первая), 2) провайдер, 3) пинг
        def sort_key(r):
            country_priority = COUNTRY_PRIORITY.get(r.country_code, 99)
            isp_name = (r.isp or "zzz").lower()  # провайдер по алфавиту
            return (country_priority, isp_name, r.latency_ms)
        
        working.sort(key=sort_key)
        
        # Топ-5 по качеству
        print(f"\nТоп-5 по качеству:")
        for i, r in enumerate(working[:5], 1):
            flag = COUNTRY_FLAGS.get(r.country_code, "🌍")
            print(f"  {i}. {flag} {r.exit_country} | {r.latency_ms}ms | {r.speed_kbps:.1f}KB/s | {r.isp}")
        
        # === КОНФИГ 1: Оригинальные имена ===
        working_keys = [r.key for r in working]
        
        with open('vpn.txt', 'w') as f:
            f.write('\n'.join(working_keys))
        
        encoded = base64.b64encode('\n'.join(working_keys).encode()).decode()
        with open('vpn_base64.txt', 'w') as f:
            f.write(encoded)
        
        # === КОНФИГ 2: С переименованием (флаг + страна + провайдер) ===
        # Сначала считаем сколько серверов у каждого провайдера в каждой стране
        isp_counters = {}
        
        for r in working:
            key_base = f"{r.country_code}_{r.isp or 'Server'}"
            isp_counters[key_base] = isp_counters.get(key_base, 0) + 1
        
        # Теперь генерируем имена с нумерацией
        isp_current = {}
        renamed_keys = []
        
        for r in working:
            flag = COUNTRY_FLAGS.get(r.country_code, "🌍")
            country = r.exit_country or "Unknown"
            isp = r.isp or "Server"
            
            # Текущий номер для этого провайдера
            key_base = f"{r.country_code}_{isp}"
            isp_current[key_base] = isp_current.get(key_base, 0) + 1
            num = isp_current[key_base]
            
            # Новое имя: 🇷🇺 Russia | Yandex Cloud 1
            new_name = f"{flag} {country} | {isp} {num}"
            
            # Заменяем имя в ключе
            if '#' in r.key:
                new_key = r.key.rsplit('#', 1)[0] + '#' + new_name
            else:
                new_key = r.key + '#' + new_name
            
            renamed_keys.append(new_key)
        
        with open('vpn_renamed.txt', 'w') as f:
            f.write('\n'.join(renamed_keys))
        
        encoded_renamed = base64.b64encode('\n'.join(renamed_keys).encode()).decode()
        with open('vpn_renamed_base64.txt', 'w') as f:
            f.write(encoded_renamed)
        
        # === JSON отчёт ===
        report = {
            "name": "🦊 Bobi VPN",
            "description": "🔒 Bobi VPN — надёжный и быстрый\n⚡ Проверенные серверы по всему миру",
            "total_checked": len(results),
            "working_count": len(working),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "countries": {},
            "keys": []
        }
        
        # Группируем по странам
        for r in working:
            code = r.country_code or "XX"
            if code not in report["countries"]:
                report["countries"][code] = {
                    "name": r.exit_country,
                    "flag": COUNTRY_FLAGS.get(code, "🌍"),
                    "count": 0
                }
            report["countries"][code]["count"] += 1
            
            report["keys"].append({
                "name": get_key_name(r.key),
                "country": r.exit_country,
                "country_code": r.country_code,
                "flag": COUNTRY_FLAGS.get(r.country_code, "🌍"),
                "isp": r.isp,
                "latency_ms": r.latency_ms,
                "speed_kbps": round(r.speed_kbps, 1),
                "exit_ip": r.exit_ip,
                "key": r.key
            })
        
        with open('vpn_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # === Happ конфиг (правильный формат) ===
        import random
        
        # Рандомная вторая строка описания
        announce_lines = [
            "⚡ Только проверенные серверы",
            "🌍 Серверы по всему миру",
            "🔒 Безопасное соединение 24/7",
            "🚀 Максимальная скорость",
            "✨ Обновляется автоматически",
            "🛡️ Защита твоего трафика",
            "💎 Премиум качество бесплатно",
            "🔥 Работает когда другие нет",
            "⭐ Лучшие серверы для тебя",
            "🌐 Свобода без границ",
            "💪 Стабильное соединение",
            "🎯 Только рабочие ключи",
            "✅ Проверено и работает",
            "🏆 Топовые серверы",
            "🔓 Обходи любые блокировки",
            "💫 Качество без компромиссов",
            "🌟 Твой надёжный VPN",
            "⚙️ Умная проверка серверов",
            "🎁 Бесплатно и без рекламы",
            "🦾 Сила в каждом сервере",
        ]
        
        random_line = random.choice(announce_lines)
        announce_text = f"🐶 BobiVPN — Быстрый и Надёжный\n{random_line}"
        announce_b64 = base64.b64encode(announce_text.encode()).decode()
        
        happ_header = f"""#profile-update-interval: 1
#profile-title: 🐶BobiVPN🐶
#subscription-userinfo: upload=0; download=0; total=107374182400; expire=1767225600
#support-url: https://bobivpn.netlify.app/
#profile-web-page-url: https://bobivpn.netlify.app/
#announce: base64:{announce_b64}
"""
        happ_config = happ_header + "\n" + "\n".join(renamed_keys)
        
        with open('bobi_vpn.txt', 'w', encoding='utf-8') as f:
            f.write(happ_config)
        
        encoded_happ = base64.b64encode(happ_config.encode()).decode()
        with open('bobi_vpn_base64.txt', 'w') as f:
            f.write(encoded_happ)
        
        # === bobi_vpn_lite.txt — Россия все, остальные макс 35 с уникальными ISP и IP ===
        ru_keys = []  # Российские ключи отдельно (без лимита)
        other_keys = []  # Остальные страны
        
        for i, r in enumerate(working):
            if r.country_code == "RU":
                # Россия — все ключи без ограничений
                ru_keys.append((r, renamed_keys[i]))
            else:
                other_keys.append((r, renamed_keys[i]))
        
        # Для остальных стран: макс 35 ключей с уникальными ISP и IP
        lite_keys = []
        
        # Сначала добавляем все российские
        for r, key in ru_keys:
            lite_keys.append((r, key))
        
        # Сортируем остальные по качеству (пинг, потом скорость)
        other_keys.sort(key=lambda x: (x[0].latency_ms, -x[0].speed_kbps))
        
        # Выбираем до 35 ключей с уникальными ISP и IP
        used_isps = set()
        used_ips = set()
        other_selected = []
        
        for r, key in other_keys:
            isp = r.isp or "Unknown"
            ip = r.exit_ip or ""
            
            # Пропускаем если ISP или IP уже использованы
            if isp in used_isps or ip in used_ips:
                continue
            
            used_isps.add(isp)
            if ip:
                used_ips.add(ip)
            other_selected.append((r, key))
            
            # Лимит 35 ключей для не-России
            if len(other_selected) >= 35:
                break
        
        # Добавляем отобранные ключи
        for r, key in other_selected:
            lite_keys.append((r, key))
        
        # Сортируем итоговый список как обычно
        def sort_key_lite(item):
            r = item[0]
            country_priority = COUNTRY_PRIORITY.get(r.country_code, 99)
            isp_name = (r.isp or "zzz").lower()
            return (country_priority, isp_name, r.latency_ms)
        
        lite_keys.sort(key=sort_key_lite)
        
        # Генерируем имена заново с правильной нумерацией
        isp_current_lite = {}
        lite_renamed_keys = []
        
        for r, _ in lite_keys:
            flag = COUNTRY_FLAGS.get(r.country_code, "🌍")
            country = r.exit_country or "Unknown"
            isp = r.isp or "Server"
            
            key_base = f"{r.country_code}_{isp}"
            isp_current_lite[key_base] = isp_current_lite.get(key_base, 0) + 1
            num = isp_current_lite[key_base]
            
            new_name = f"{flag} {country} | {isp} {num}"
            
            if '#' in r.key:
                new_key = r.key.rsplit('#', 1)[0] + '#' + new_name
            else:
                new_key = r.key + '#' + new_name
            
            lite_renamed_keys.append(new_key)
        
        # Happ header для lite версии
        random_line_lite = random.choice(announce_lines)
        announce_text_lite = f"🐶 BobiVPN Lite — Без дубликатов\n{random_line_lite}"
        announce_b64_lite = base64.b64encode(announce_text_lite.encode()).decode()
        
        happ_header_lite = f"""#profile-update-interval: 1
#profile-title: 🐶BobiVPN Lite🐶
#subscription-userinfo: upload=0; download=0; total=107374182400; expire=1767225600
#support-url: https://bobivpn.netlify.app/
#profile-web-page-url: https://bobivpn.netlify.app/
#announce: base64:{announce_b64_lite}
"""
        happ_config_lite = happ_header_lite + "\n" + "\n".join(lite_renamed_keys)
        
        with open('bobi_vpn_lite.txt', 'w', encoding='utf-8') as f:
            f.write(happ_config_lite)
        
        # Статистика lite
        ru_count = len(ru_keys)
        other_count = len(other_selected)
        
        # === Создаём папку countries/ с подписками по странам ===
        countries_dir = 'countries'
        if not os.path.exists(countries_dir):
            os.makedirs(countries_dir)
        
        # Группируем ключи по странам
        country_keys = {}
        for i, r in enumerate(working):
            code = r.country_code or "XX"
            if code not in country_keys:
                country_keys[code] = []
            country_keys[code].append((r, renamed_keys[i]))
        
        # Создаём файл для каждой страны
        country_files_created = []
        for code, keys_list in country_keys.items():
            country_name = keys_list[0][0].exit_country or "Unknown"
            flag = COUNTRY_FLAGS.get(code, "🌍")
            
            # Перенумеровываем ключи для этой страны
            country_renamed = []
            isp_counter = {}
            for r, _ in keys_list:
                isp = r.isp or "Server"
                isp_counter[isp] = isp_counter.get(isp, 0) + 1
                num = isp_counter[isp]
                
                new_name = f"{flag} {country_name} | {isp} {num}"
                if '#' in r.key:
                    new_key = r.key.rsplit('#', 1)[0] + '#' + new_name
                else:
                    new_key = r.key + '#' + new_name
                country_renamed.append(new_key)
            
            # Happ header для страны
            announce_country = f"{flag} BobiVPN — {country_name}\n⚡ {len(keys_list)} проверенных серверов"
            announce_b64_country = base64.b64encode(announce_country.encode()).decode()
            
            happ_header_country = f"""#profile-update-interval: 1
#profile-title: {flag} BobiVPN {country_name}
#subscription-userinfo: upload=0; download=0; total=107374182400; expire=1767225600
#support-url: https://bobivpn.netlify.app/
#profile-web-page-url: https://bobivpn.netlify.app/
#announce: base64:{announce_b64_country}
"""
            happ_config_country = happ_header_country + "\n" + "\n".join(country_renamed)
            
            # Имя файла: russia.txt, germany.txt и т.д.
            filename = f"{country_name.lower().replace(' ', '_')}.txt"
            filepath = os.path.join(countries_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(happ_config_country)
            
            country_files_created.append((code, country_name, len(keys_list), filename))
        
        print(f"\n{'=' * 60}")
        print("СОХРАНЕНО:")
        print(f"{'=' * 60}")
        print(f"  📄 vpn.txt - {len(working)} ключей (оригинал)")
        print(f"  📄 vpn_renamed.txt - с красивыми именами")
        print(f"  🦊 bobi_vpn.txt - для Happ (с заголовком)")
        print(f"  🦊 bobi_vpn_lite.txt - Lite версия ({len(lite_keys)} ключей, RU: {ru_count}, другие: {other_count})")
        print(f"  📊 vpn_report.json - детальный отчёт")
        print(f"  📁 countries/ - {len(country_files_created)} файлов по странам")
        print(f"\nПо странам:")
        for code, name, count, filename in sorted(country_files_created, 
                                                   key=lambda x: COUNTRY_PRIORITY.get(x[0], 99)):
            flag = COUNTRY_FLAGS.get(code, "🌍")
            print(f"  {flag} {name}: {count} серверов → countries/{filename}")
    else:
        print("\nРабочих ключей не найдено!")
        with open('vpn.txt', 'w') as f:
            f.write('')
        with open('bobi_vpn.txt', 'w') as f:
            f.write('')
        with open('bobi_vpn_lite.txt', 'w') as f:
            f.write('')


if __name__ == '__main__':
    asyncio.run(main())
