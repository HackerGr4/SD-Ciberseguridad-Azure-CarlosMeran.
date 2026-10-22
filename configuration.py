"""Explicit, validated policy; imports never read config files."""
import ipaddress
import json
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).with_name('config.json')
DEFAULTS = {
    'client_name': 'Empresa de Prueba',
    'AUTHORIZED_IPS': ['127.0.0.0/8', '::1/128'],
    'BLOCKED_IPS': [],
    'ENFORCE_ALLOWLIST': False,
    'SUSPICIOUS_KEYWORDS': [],
    'PROCESS_WATCHLIST': [],
}


def parse_address(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def parse_network(value):
    network = ipaddress.ip_network(value, strict=True)
    if isinstance(network, ipaddress.IPv6Network):
        mapped = network.network_address.ipv4_mapped
        if mapped is not None and network.prefixlen >= 96:
            return ipaddress.ip_network(f'{mapped}/{network.prefixlen - 96}')
    return network


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError('La configuración debe ser un objeto JSON.')
    result = {**DEFAULTS, **config}
    if not isinstance(result['client_name'], str):
        raise ValueError('client_name debe ser texto.')
    if type(result['ENFORCE_ALLOWLIST']) is not bool:
        raise ValueError('ENFORCE_ALLOWLIST debe ser true o false.')
    for key in ('AUTHORIZED_IPS', 'BLOCKED_IPS', 'SUSPICIOUS_KEYWORDS', 'PROCESS_WATCHLIST'):
        values = result[key]
        if not isinstance(values, list) or any(not isinstance(v, str) or not v.strip() for v in values):
            raise ValueError(f'{key} debe ser una lista de textos no vacíos.')
        result[key] = list(values)
    for key in ('AUTHORIZED_IPS', 'BLOCKED_IPS'):
        for value in result[key]:
            parse_network(value)
    if result['ENFORCE_ALLOWLIST'] and not result['AUTHORIZED_IPS']:
        raise ValueError('Una lista permitida obligatoria no puede estar vacía.')
    return result


def load_config(path=None):
    with open(path or DEFAULT_CONFIG_PATH, encoding='utf-8') as stream:
        return validate_config(json.load(stream))
