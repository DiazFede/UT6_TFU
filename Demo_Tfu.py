import http.server
import socketserver
import requests
import threading
import time

# --- Configuración de Puertos ---
# Puerto para el Microservicio de Estudiantes
PORT_ESTUDIANTES_MS = 8001
# Puerto para el Microservicio de Préstamos
PORT_PRESTAMOS_MS = 8002
# Puerto para el Reverse Proxy (API Gateway simulado)
PORT_REVERSE_PROXY = 8000
# Puerto para el Forward Proxy
PORT_FORWARD_PROXY = 9000

# --- 1. Definición de Microservicios ---
class MicroserviceHandler(http.server.SimpleHTTPRequestHandler):
    """
    Manejador para un microservicio simple.
    Responde con un mensaje específico del microservicio basado en la ruta.
    """
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        service_id = self.server.server_address[1]

        if service_id == PORT_PRESTAMOS_MS and self.path == "/api/prestamos/registrar":
            response_message = "Préstamo registrado exitosamente para el usuario autorizado."
            print(f"[Servicio Préstamos] Recibida petición para registrar préstamo. Respondiendo: '{response_message}'")
        elif service_id == PORT_ESTUDIANTES_MS and self.path == "/api/estudiantes/listar":
            response_message = "Lista de estudiantes obtenida: [Estudiante1, Estudiante2]."
            print(f"[Servicio Estudiantes] Recibida petición para listar estudiantes. Respondiendo: '{response_message}'")
        else:
            response_message = f"Hola desde el Microservicio en puerto {service_id}! Ruta no reconocida: {self.path}"
            print(f"[Microservicio Genérico] Recibida petición para '{self.path}'. Respondiendo: '{response_message}'")

        self.wfile.write(response_message.encode("utf-8"))

# --- 2. Definición del Reverse Proxy (API Gateway) ---
class ReverseProxyHandler(http.server.SimpleHTTPRequestHandler):
    """
    Manejador para el Reverse Proxy.
    Actúa como un API Gateway simulado con autenticación JWT y enrutamiento a microservicios específicos.
    """
    def do_GET(self):
        # 1. Autenticación/Autorización (Simulada con JWT)
        auth_header = self.headers.get('Authorization')
        expected_jwt = "Bearer token_valido_jwt_simulado" # Un token JWT simulado para la demo

        if auth_header != expected_jwt:
            self.send_error(401, "Acceso no autorizado: Token JWT inválido o ausente.")
            print(f"[Reverse Proxy - Seguridad] Bloqueada petición de {self.client_address[0]}: Token JWT ausente o inválido.")
            return
        
        print(f"[Reverse Proxy - Seguridad] Token JWT válido recibido de {self.client_address[0]}.")

        target_port = None
        
        # 2. Enrutamiento Inteligente
        if self.path.startswith("/api/prestamos/registrar"):
            target_port = PORT_PRESTAMOS_MS
            print(f"[Reverse Proxy - Enrutamiento] Enrutando '{self.path}' a Servicio de Préstamos (Puerto: {target_port})")
        elif self.path.startswith("/api/estudiantes/listar"):
            target_port = PORT_ESTUDIANTES_MS
            print(f"[Reverse Proxy - Enrutamiento] Enrutando '{self.path}' a Servicio de Estudiantes (Puerto: {target_port})")
        else:
            self.send_error(404, "Ruta de API no reconocida por el Gateway.")
            print(f"[Reverse Proxy - Enrutamiento] ERROR 404: Ruta '{self.path}' no encontrada en el API Gateway.")
            return

        try:
            # 3. Interacción con el Servicio de Backend
            backend_url = f"http://localhost:{target_port}{self.path}" # El Gateway reenvía la ruta exacta
            
            # Reenvía la petición al microservicio. Re-pasamos el encabezado de autorización
            # en caso de que el microservicio también necesite validarlo (aunque en esta demo no lo hace).
            resp = requests.get(backend_url, headers={'Authorization': auth_header}) 

            # 4. Respuesta Unificada al Cliente
            self.send_response(resp.status_code)
            for header, value in resp.headers.items():
                # Evitar encabezados que puedan causar problemas o sean específicos de la conexión HTTP
                if header.lower() not in ('content-encoding', 'transfer-encoding', 'connection'):
                    self.send_header(header, value)
            self.end_headers()
            self.wfile.write(resp.content)
            print(f"[Reverse Proxy - Resposta] Petición a {backend_url} completada. Estado: {resp.status_code}")

        except requests.exceptions.ConnectionError:
            self.send_error(503, "Servicio de backend no disponible.")
            print(f"[Reverse Proxy - ERROR] Microservicio en puerto {target_port} no disponible.")
        except Exception as e:
            self.send_error(500, f"Error interno del Reverse Proxy: {e}")
            print(f"[Reverse Proxy - ERROR] Error inesperado: {e}")

# --- 3. Definición del Forward Proxy ---
class ForwardProxyHandler(http.server.SimpleHTTPRequestHandler):
    """
    Manejador para el Forward Proxy.
    Interpreta las peticiones del cliente (que incluyen la URL completa del destino)
    y las reenvía a ese destino.
    """
    def do_GET(self):
        # El cliente le solicita al forward proxy la URL COMPLETA que quiere alcanzar.
        # CORRECCIÓN: Eliminar la barra inicial '/' que agrega SimpleHTTPRequestHandler
        # si la URL ya es absoluta (empieza con 'http://' o 'https://').
        requested_url = self.path
        if requested_url.startswith('/http://') or requested_url.startswith('/https://'):
            requested_url = requested_url[1:] # Eliminar la primera barra

        print(f"[Forward Proxy] Recibida petición para reenviar: '{requested_url}'")

        try:
            # Reenvía la petición al destino final (que en este caso es el Reverse Proxy)
            # Reutilizamos los encabezados del cliente original para que el JWT llegue al Reverse Proxy
            headers_to_forward = {k: v for k, v in self.headers.items() if k.lower() not in ('host', 'connection', 'proxy-connection')}
            resp = requests.get(requested_url, headers=headers_to_forward)
            
            # Envía la respuesta del destino de vuelta al cliente original
            self.send_response(resp.status_code)
            for header, value in resp.headers.items():
                if header.lower() not in ('content-encoding', 'transfer-encoding', 'connection'):
                    self.send_header(header, value)
            self.end_headers()
            self.wfile.write(resp.content)
            print(f"[Forward Proxy] Petición a '{requested_url}' completada. Estado: {resp.status_code}")

        except requests.exceptions.ConnectionError:
            self.send_error(503, f"Destino '{requested_url}' no disponible o error de conexión.")
            print(f"[Forward Proxy] ERROR: Destino '{requested_url}' no disponible.")
        except Exception as e:
            self.send_error(500, f"Error interno del Forward Proxy: {e}")
            print(f"[Forward Proxy] ERROR: {e}")

# --- Función para iniciar un servidor HTTP ---
def start_server(port, handler_class, server_name):
    """Inicia un servidor HTTP en un puerto dado."""
    with socketserver.TCPServer(("", port), handler_class) as httpd:
        print(f"[{server_name}] Servidor iniciado en el puerto {port}")
        # La línea a continuación mantendrá el servidor ejecutándose indefinidamente
        # hasta que se apague manualmente o el programa termine.
        httpd.serve_forever()

# --- Simulación del Cliente ---
def simulate_client():
    """Simula un cliente haciendo peticiones a través de proxies para el escenario de la biblioteca."""
    time.sleep(2) # Dar tiempo para que todos los servidores se inicien

    print("\n--- INICIO DE LA SIMULACIÓN DEL CLIENTE ---")

    # TOKEN JWT SIMULADO
    valid_jwt = "Bearer token_valido_jwt_simulado"
    invalid_jwt = "Bearer token_invalido_jwt_simulado"

    # Escenario 1: Cliente accede directamente al API Gateway (Reverse Proxy) con JWT válido
    print("\n>>> ESCENARIO 1: Cliente accede directamente al API Gateway con JWT válido <<<")
    
    print("\n[Cliente] Petición: Registrar Préstamo (con JWT válido)...")
    try:
        headers = {'Authorization': valid_jwt}
        response = requests.get(f"http://localhost:{PORT_REVERSE_PROXY}/api/prestamos/registrar", headers=headers)
        print(f"[Cliente] Recibida respuesta de API Gateway (registrar préstamo): {response.status_code} - '{response.text}'")
    except Exception as e:
        print(f"[Cliente] ERROR al acceder a API Gateway para registrar préstamo: {e}")

    time.sleep(1)

    print("\n[Cliente] Petición: Listar Estudiantes (con JWT válido)...")
    try:
        headers = {'Authorization': valid_jwt}
        response = requests.get(f"http://localhost:{PORT_REVERSE_PROXY}/api/estudiantes/listar", headers=headers)
        print(f"[Cliente] Recibida respuesta de API Gateway (listar estudiantes): {response.status_code} - '{response.text}'")
    except Exception as e:
        print(f"[Cliente] ERROR al acceder a API Gateway para listar estudiantes: {e}")

    time.sleep(1)

    # Escenario 1.5: Cliente accede directamente al API Gateway SIN JWT (debería fallar con 401)
    print("\n>>> ESCENARIO 1.5: Cliente accede directamente al API Gateway SIN JWT (Esperado: 401 Unauthorized) <<<")
    try:
        response = requests.get(f"http://localhost:{PORT_REVERSE_PROXY}/api/prestamos/registrar") # Sin encabezado de autorización
        print(f"[Cliente] Recibida respuesta de API Gateway (sin JWT): {response.status_code} - '{response.text}'")
    except Exception as e:
        print(f"[Cliente] ERROR al acceder a API Gateway sin JWT: {e}")

    time.sleep(1)

    # Escenario 2: Cliente accede a través del Forward Proxy para llegar al API Gateway (con JWT válido)
    print("\n>>> ESCENARIO 2: Cliente accede A TRAVÉS del Forward Proxy al API Gateway (con JWT válido) <<<")
    print("\n[Cliente] Petición vía Forward Proxy: Listar Estudiantes (con JWT válido)...")
    try:
        headers = {'Authorization': valid_jwt}
        # El cliente le pide al forward proxy la URL COMPLETA que quiere alcanzar (el API Gateway).
        target_url_for_fp = f"http://localhost:{PORT_REVERSE_PROXY}/api/estudiantes/listar"
        response = requests.get(f"http://localhost:{PORT_FORWARD_PROXY}/{target_url_for_fp}", headers=headers)
        print(f"[Cliente] Recibida respuesta vía Forward Proxy (listar estudiantes): {response.status_code} - '{response.text}'")
    except Exception as e:
        print(f"[Cliente] ERROR al acceder vía Forward Proxy: {e}")
    
    time.sleep(1)

    print("\n[Cliente] Petición vía Forward Proxy: Registrar Préstamo (con JWT válido)...")
    try:
        headers = {'Authorization': valid_jwt}
        target_url_for_fp = f"http://localhost:{PORT_REVERSE_PROXY}/api/prestamos/registrar"
        response = requests.get(f"http://localhost:{PORT_FORWARD_PROXY}/{target_url_for_fp}", headers=headers)
        print(f"[Cliente] Recibida respuesta vía Forward Proxy (registrar préstamo): {response.status_code} - '{response.text}'")
    except Exception as e:
        print(f"[Cliente] ERROR al acceder vía Forward Proxy: {e}")


# --- Hilo Principal de Ejecución ---
if __name__ == "__main__":
    print("Iniciando simulación de proxies y microservicios...")

    # Hilos para Microservicios
    thread_ms_estudiantes = threading.Thread(target=start_server, args=(PORT_ESTUDIANTES_MS, MicroserviceHandler, "Servicio Estudiantes"))
    thread_ms_prestamos = threading.Thread(target=start_server, args=(PORT_PRESTAMOS_MS, MicroserviceHandler, "Servicio Préstamos"))
    
    # Hilo para Reverse Proxy (API Gateway)
    thread_rp = threading.Thread(target=start_server, args=(PORT_REVERSE_PROXY, ReverseProxyHandler, "Reverse Proxy (API Gateway)"))
    
    # Hilo para Forward Proxy
    thread_fp = threading.Thread(target=start_server, args=(PORT_FORWARD_PROXY, ForwardProxyHandler, "Forward Proxy"))

    # Iniciar todos los hilos en segundo plano (daemon=True)
    # Esto permite que el programa principal termine incluso si los hilos del servidor siguen corriendo,
    # aunque para un control más robusto, se recomendaría un bucle de gestión de servidores.
    thread_ms_estudiantes.daemon = True
    thread_ms_prestamos.daemon = True
    thread_rp.daemon = True
    thread_fp.daemon = True

    thread_ms_estudiantes.start()
    thread_ms_prestamos.start()
    thread_rp.start()
    thread_fp.start()

    # Ejecutar la simulación del cliente en el hilo principal
    simulate_client()

    print("\n--- Simulación Completada ---")
    print("Puedes terminar el programa presionando Ctrl+C.")
    # Mantener el hilo principal vivo para que los servidores sigan ejecutándose un tiempo.
    # En un entorno real, usarías un mecanismo de gestión de procesos o esperarías a que los hilos terminen.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nCerrando servidores...")
        # Los hilos demonio se cerrarán automáticamente al terminar el hilo principal.