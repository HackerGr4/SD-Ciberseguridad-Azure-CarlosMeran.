import argparse
import json
import sys
import psutil
from configuration import load_config
from network_monitor import scan_network
from malware_scanner import full_scan
from reporter import generate_json_report, generate_html_report
from remediation import remediate_process, confirmation_text


def review_remediation(findings, config, *, apply=False):
    """Review one candidate at a time; no bulk acknowledgement or piped approval."""
    outcomes = []
    seen = set()
    for finding in findings:
        identity = finding.get('process_identity')
        if not finding.get('remediation_eligible') or not isinstance(identity, dict):
            continue
        key = (finding.get('pid'), identity.get('create_time'))
        if key in seen:
            continue
        seen.add(key)
        preview = remediate_process(finding, config=config)
        print(json.dumps({'process': identity, 'evidence': finding.get('reason'),
                          'preview': preview}, ensure_ascii=True))
        if not apply or preview['status'] != 'dry_run':
            outcomes.append(preview)
            continue
        if not sys.stdin.isatty():
            outcomes.append({'pid': finding['pid'], 'status': 'cancelled',
                             'reason': 'Se requiere una terminal interactiva.'})
            continue
        print('ADVERTENCIA: termina toda la aplicación, no solo esta conexión; puede perder trabajo.')
        try:
            answer = input(f"Escriba {confirmation_text(identity)!r} para este proceso; Enter cancela: ")
        except (EOFError, KeyboardInterrupt):
            outcomes.append({'pid': finding['pid'], 'status': 'cancelled',
                             'reason': 'Revisión interrumpida; no se continúa con otros procesos.'})
            break
        # Guards are repeated after the user responds; preview is not authorization.
        outcome = remediate_process(finding, config=config, apply=True, confirmation=answer)
        outcomes.append(outcome)
        print(json.dumps(outcome, ensure_ascii=True))
        if outcome['status'] == 'interrupted':
            break
    return outcomes


def main(argv=None):
    parser = argparse.ArgumentParser(description='Observaciones de seguridad; no certifica ausencia de malware.')
    parser.add_argument('--config', help='Ruta de política JSON (por defecto junto al programa).')
    parser.add_argument('--directory', default='.', help='Directorio autorizado a inspeccionar.')
    parser.add_argument('--review-remediation', action='store_true', help='Simular protecciones sin enviar señales.')
    parser.add_argument('--apply-remediation', action='store_true', help='Opt-in Linux: revisión y confirmación individual.')
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as error:
        print(f'Configuración inválida; no se ejecutó el escaneo: {error}')
        return 2
    errors = []
    try:
        findings = scan_network(config)
    except (psutil.Error, OSError) as error:
        findings = []
        errors.append(f'Red no inspeccionada: {error}')
    results = full_scan(args.directory, config)
    errors.extend(results.get('errors', []))
    data = {'client_name': config['client_name'], 'unauthorized_conns': findings,
            'malware_results': results, 'scan_errors': errors, 'remediation_results': [],
            'policy': {'enforce_allowlist': config['ENFORCE_ALLOWLIST'],
                       'blocked_rules': len(config['BLOCKED_IPS'])}}
    # Preserve the read-only evidence before any optional intervention.
    generate_json_report(data)
    generate_html_report(data)
    print('Observaciones de seguridad generadas. Los indicios requieren revisión humana.')
    if errors:
        print('ESCANEO INCOMPLETO. Consulte los errores en el informe; remediación deshabilitada.')
    elif args.review_remediation or args.apply_remediation:
        data['remediation_results'] = review_remediation(findings, config, apply=args.apply_remediation)
        generate_json_report(data)
        generate_html_report(data)
    print('Informes: scan_report.json y scan_report.html. No constituyen garantía de seguridad.')
    return 1 if errors else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\nOperación cancelada.')
        sys.exit(130)
