import json
import os

def setup_client(client_name, extra_authorized_ips=None):
    """Prepares the environment for a new client audit."""
    print(f"--- CONFIGURANDO ENTORNO PARA: {client_name} ---")

    config = {
        "client_name": client_name,
        "AUTHORIZED_IPS": [
            "127.0.0.1",
            "::1",
            "0.0.0.0"
        ],
        "SUSPICIOUS_KEYWORDS": [
            "eval(",
            "base64.b64decode(",
            "os.system(",
            "subprocess.Popen(",
            "subprocess.call(",
            "requests.get(",
            "socket.socket(",
            "__import__('os')"
        ]
    }

    if extra_authorized_ips:
        config["AUTHORIZED_IPS"].extend(extra_authorized_ips)

    with open("config.json", "w") as f:
        json.dump(config, f, indent=4)

    print(f"[+] Archivo config.json generado para {client_name}.")
    print("[!] El sistema está listo para ejecutar 'python3 main.py'.")

if __name__ == "__main__":
    name = input("Nombre del cliente: ")
    setup_client(name)
