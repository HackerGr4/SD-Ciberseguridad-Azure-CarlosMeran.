def generate_email(client_name, scan_results=None):
    """Generates a persuasive sales email based on scan results."""

    if not scan_results or not scan_results.get('threats_found', False):
        # Lead Magnet Email
        subject = f"Protección gratuita para {client_name} - Análisis de Ciberseguridad"
        body = f"""
Hola {client_name},

He estado analizando los desafíos de ciberseguridad que enfrentan las empresas de tu sector recientemente.

He desarrollado un sistema de auditoría rápida que detecta conexiones no autorizadas y malware en menos de 60 segundos. Me gustaría ofrecerte un escaneo gratuito para asegurar que tus equipos de trabajo están limpios.

Solo toma un minuto y te entregaré un reporte profesional en HTML con los resultados. ¿Te interesaría recibirlo hoy?

Saludos,
Tu Especialista en Seguridad Digital
        """
    else:
        # Upsell Email after scan
        subject = f"URGENTE: Hallazgos de seguridad en {client_name}"
        body = f"""
Hola {client_name},

He completado el análisis de seguridad en tu sistema y, lamentablemente, hemos detectado {scan_results.get('threat_count')} puntos críticos que requieren atención inmediata.

Adjunto encontrarás el reporte profesional. Estos hallazgos podrían comprometer la privacidad de tus datos si no se cierran los puertos/procesos detectados.

He preparado un "Pack de Remediación Inmediata" por solo $50 para solucionar esto por ti hoy mismo. ¿Te gustaría que procedamos con la limpieza?

Quedo a la espera de tus noticias.
        """

    return {"subject": subject.strip(), "body": body.strip()}

if __name__ == "__main__":
    # Demo
    print("--- EMAIL DE PROSPECCIÓN ---")
    print(generate_email("Empresa ABC")["body"])
    print("\n--- EMAIL DE VENTA (AMENAZAS DETECTADAS) ---")
    print(generate_email("Empresa ABC", {"threats_found": True, "threat_count": 3})["body"])
