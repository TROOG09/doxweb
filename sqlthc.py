import socket
import whois
import json
import re
import urllib.request

# Información del Proyecto
"""
######################################
#   THESIXCLOWN                    #
######################################
#  Creado por: THESIXCLOWN Team      #
#  Autores: lapsus group / 333g      #
#  GitHub: https://github.com/TROOG09  #
#  Licencia: MIT                    #
######################################

# ASCII Art - THESIXCLOWN
# Creado por: THESIXCLOWN team / lapsus group / creator: 333g

▄▄▄▄▄▄▄▄▄ ▄▄                                ▄▄                     
▀▀▀███▀▀▀ ██                ▀▀              ██                     
   ███    ████▄ ▄█▀█▄ ▄█▀▀▀ ██  ██ ██ ▄████ ██ ▄███▄ ██   ██ ████▄ 
   ███    ██ ██ ██▄█▀ ▀███▄ ██   ███  ██    ██ ██ ██ ██ █ ██ ██ ██ 
   ███    ██ ██ ▀█▄▄▄ ▄▄▄█▀ ██▄ ██ ██ ▀████ ██ ▀███▀  ██▀██  ██ ██ 
"""

# Función para mostrar el arte ASCII y la información del proyecto
def mostrar_ascii():
    print("""
    ######################################
    #   THESIXCLOWN                    #
    ######################################
    #  Creado por: THESIXCLOWN Team      #
    #  Autores: lapsus group / 333g      #
    #  GitHub: https://github.com/TROOG09  #
    #  Licencia: MIT                    #
    ######################################
▄▄▄▄▄▄▄▄▄ ▄▄                                ▄▄                     
▀▀▀███▀▀▀ ██                ▀▀              ██                     
   ███    ████▄ ▄█▀█▄ ▄█▀▀▀ ██  ██ ██ ▄████ ██ ▄███▄ ██   ██ ████▄ 
   ███    ██ ██ ██▄█▀ ▀███▄ ██   ███  ██    ██ ██ ██ ██ █ ██ ██ ██ 
   ███    ██ ██ ▀█▄▄▄ ▄▄▄█▀ ██▄ ██ ██ ▀████ ██ ▀███▀  ██▀██  ██ ██ 

    ######################################
    # 1. Ingresar dominio               #
    # 0. Salir                          #
    ######################################
    """)

# Función para obtener información WHOIS
def obtener_info_whois(dominio):
    print(f"Consultando WHOIS para {dominio}...")
    try:
        w = whois.whois(dominio)
        return w
    except Exception as e:
        print(f"Error al obtener datos WHOIS: {e}")
        return None

# Función para obtener la IP del dominio
def obtener_ip(dominio):
    try:
        ip = socket.gethostbyname(dominio)
        return ip
    except socket.gaierror:
        return None

# Función para obtener información DNS (A, MX, TXT)
def obtener_datos_dns(dominio):
    print(f"Consultando DNS para {dominio}...")
    resultado = {}
    try:
        # Consultando registros A
        registros_a = socket.gethostbyname(dominio)
        resultado['A'] = registros_a
    except Exception as e:
        resultado['A'] = None
        print(f"Error al obtener registros A: {e}")

    try:
        # Consultando registros MX (correo)
        registros_mx = socket.gethostbyname(f"mx.{dominio}")
        resultado['MX'] = registros_mx
    except Exception as e:
        resultado['MX'] = None
        print(f"Error al obtener registros MX: {e}")

    try:
        # Consultando registros TXT (SPF, DKIM)
        registros_txt = socket.gethostbyname(f"txt.{dominio}")
        resultado['TXT'] = registros_txt
    except Exception as e:
        resultado['TXT'] = None
        print(f"Error al obtener registros TXT: {e}")

    return resultado

# Función para obtener la geolocalización de la IP
def obtener_geolocalizacion(ip):
    print(f"Obteniendo geolocalización para la IP {ip}...")
    url = f"http://ip-api.com/json/{ip}?fields=country,city,zip,region"
    try:
        respuesta = urllib.request.urlopen(url)
        data = json.load(respuesta)
        if data['status'] == 'fail':
            return None
        return data
    except Exception as e:
        print(f"Error al obtener la geolocalización: {e}")
        return None

# Función para obtener información ASN (sin usar pyasn)
def obtener_asn(ip):
    print(f"Consultando ASN para la IP {ip}...")
    # Aquí asumimos que estamos obteniendo información de un servicio como ARIN o RIPE.
    # En este caso, usaremos un servicio público de consultas ASN.
    url = f"https://api.ip2asn.com/v1/{ip}"
    try:
        respuesta = urllib.request.urlopen(url)
        data = json.load(respuesta)
        return data.get('asn', 'Desconocido')
    except Exception as e:
        print(f"Error al obtener ASN: {e}")
        return None

# Función para obtener correos electrónicos de tipo Gmail de los datos WHOIS
def extraer_usuarios_y_correos_whois(whois_data):
    usuarios_y_correos = []
    if whois_data:
        campos = ['Registrant Name', 'Admin Name', 'Tech Name', 'Registrant Email', 
                  'Admin Email', 'Tech Email', 'Registrant Organization', 
                  'Admin Organization', 'Tech Organization']
        
        for campo in campos:
            if campo in whois_data:
                value = whois_data.get(campo)
                if isinstance(value, str):
                    if re.match(r"[^@]+@gmail\.com", value):  # Filtra correos @gmail.com
                        usuarios_y_correos.append((campo, value))
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and re.match(r"[^@]+@gmail\.com", item):  # Filtra correos @gmail.com
                            usuarios_y_correos.append((campo, item))
    return usuarios_y_correos

# Función principal que obtiene toda la información
def obtener_info_completa(dominio):
    ip = obtener_ip(dominio)
    if ip:
        print(f"La IP de {dominio} es {ip}")
    else:
        print("No se pudo obtener la IP.")
        return

    # Obtener datos DNS
    datos_dns = obtener_datos_dns(dominio)
    if datos_dns:
        print(f"Datos DNS de {dominio}: {json.dumps(datos_dns, indent=4)}")

    # Obtener información WHOIS
    info_whois = obtener_info_whois(dominio)
    if info_whois:
        print(f"Información WHOIS para {dominio}: {json.dumps(info_whois, indent=4)}")
        usuarios_y_correos = extraer_usuarios_y_correos_whois(info_whois)
        if usuarios_y_correos:
            print("Usuarios y correos de Gmail encontrados en WHOIS:")
            for usuario, correo in usuarios_y_correos:
                print(f"{usuario}: {correo}")

    # Geolocalización de la IP
    geolocalizacion = obtener_geolocalizacion(ip)
    if geolocalizacion:
        print(f"Geolocalización de la IP: {geolocalizacion}")

    # ASN (sin usar pyasn)
    asn = obtener_asn(ip)
    if asn:
        print(f"ASN de la IP: {asn}")

# Función para
