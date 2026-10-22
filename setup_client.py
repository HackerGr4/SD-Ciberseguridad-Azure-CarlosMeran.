import json
from configuration import DEFAULT_CONFIG_PATH, validate_config


def setup_client(client_name, extra_authorized_ips=None, config_path=None):
    """Create an observation-only policy, never enable enforcement implicitly."""
    config = validate_config({
        'client_name': client_name,
        'AUTHORIZED_IPS': ['127.0.0.0/8', '::1/128'] + list(extra_authorized_ips or []),
        'BLOCKED_IPS': [], 'ENFORCE_ALLOWLIST': False,
        'SUSPICIOUS_KEYWORDS': [], 'PROCESS_WATCHLIST': [],
    })
    path = config_path or DEFAULT_CONFIG_PATH
    # Do not silently overwrite a reviewed policy.
    with open(path, 'x', encoding='utf-8') as stream:
        json.dump(config, stream, indent=4, ensure_ascii=False)
    return str(path)


if __name__ == '__main__':
    setup_client(input('Nombre del cliente: '))
