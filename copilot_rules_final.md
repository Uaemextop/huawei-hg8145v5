# GitHub Copilot Prompt - Instrucciones y Reglas SOLAMENTE
## Motorola Firmware Downloader Project

### Modelo Objetivo
**Claude Opus 4.6**

---

## 🚫 RESTRICCIONES CRÍTICAS

### No Generes:
- ❌ Archivos de tests (test_*.py)
- ❌ test/ carpeta o contenido de pruebas
- ❌ pytest fixtures o test runners
- ❌ Mock objects o test utilities
- ❌ CI/CD pipelines (workflows)
- ❌ Docker files o containerización
- ❌ GitHub Actions workflows
- ❌ Normas de redes (RFC, protocolos, estándares)
- ❌ Documentación técnica de protocolos

### Enfoque Principal:
- ✅ Solo código de producción
- ✅ Módulos funcionales
- ✅ Archivos ejecutables
- ✅ Configuración
- ✅ Documentación

---

## 📋 OBJETIVO GENERAL

Generar un **sistema Python profesional, modular y escalable** para descargar firmwares de Motorola que:

1. **Autentica** usuarios con JWT desde servidores Motorola
2. **Busca** Firmwares, ROMs y Tools a través de APIs
3. **Descarga** archivos de forma concurrente y confiable
4. **Gestiona** configuración centralizada via config.ini
5. **Proporciona** interfaz CLI interactiva al usuario

---

## 🏗️ PRINCIPIOS DE DISEÑO

### Modularidad
- Cada módulo tiene una responsabilidad única
- Código reutilizable en archivos utils/
- Fácil agregar nuevos tipos de crawlers
- Dependencias mínimas entre componentes

### Profesionalismo
- Type hints en TODOS los métodos y funciones
- Docstrings explicativos en cada función
- Logging detallado de todas las operaciones
- Manejo robusto de excepciones y errores
- Código limpio y legible

### Rendimiento
- Descargas concurrentes (máximo 3 simultáneas)
- Caché de resultados de búsqueda
- Reintentos inteligentes con backoff exponencial
- HTTP keepalive para conexiones eficientes

### Seguridad
- Credenciales cifradas en config.ini
- Validación de TODAS las entradas del usuario
- Conexiones HTTPS únicamente
- Nunca loguear tokens o credenciales

---

## 🔑 REGLAS DE CÓDIGO

### Type Hints
- **OBLIGATORIO**: `def function(param: str) -> bool:`
- Todos los parámetros deben tener tipos
- Todos los retornos deben tener tipos
- Usar `Optional[T]` para valores que pueden ser None
- Usar `Dict[str, Any]`, `List[T]`, `Tuple[...]` para colecciones

### Docstrings
- **FORMATO**: Google-style docstrings
- Incluir descripción breve
- Documentar parámetros (Args:)
- Documentar retornos (Returns:)
- Documentar excepciones (Raises:)

**Ejemplo:**
```
def authenticate(self, guid: str, password: str) -> bool:
    """Autenticar con servidor Motorola y obtener JWT.
    
    Args:
        guid: Identificador único del dispositivo
        password: Contraseña de autenticación
        
    Returns:
        True si autenticación fue exitosa, False si falla
        
    Raises:
        ConnectionError: Si no puede conectar al servidor
        AuthenticationError: Si credenciales son inválidas
    """
```

### Logging
- **OBLIGATORIO**: Logger centralizado para cada módulo
- Usar `self.logger = Logger(__name__)`
- Niveles apropiados: INFO (eventos), WARNING (precaución), ERROR (fallos)
- NUNCA loguear tokens, passwords o GUID
- Todos los logs deben ser informativos al usuario

### Manejo de Errores
- Try-except alrededor de operaciones de red
- Try-except alrededor de I/O de archivos
- Try-except alrededor de parsing de JSON
- Capturar excepciones específicas (no excepciones genéricas)
- Loguear siempre el error con contexto
- Retornar valores seguros o relanzar excepciones personalizadas

### Naming Conventions
- **Clases**: PascalCase (DownloadManager, FirmwareCrawler)
- **Funciones/métodos**: snake_case (get_download_url, authenticate)
- **Constantes**: UPPER_SNAKE_CASE (MAX_RETRIES, DEFAULT_TIMEOUT)
- **Variables privadas**: _prefijo (self._cache, self._token)
- **Nombres descriptivos**: no usar x, y, z, temp

### Imports
- Agrupar: stdlib, third-party, local
- Usar `from module import specific_class` (no imports tipo *)
- Mantener imports ordenados alfabéticamente
- Limitar imports a lo necesario

---

## 🔐 CONFIGURACIÓN (config.ini)

### Secciones Requeridas:
- `[motorola_server]` → URL base, GUID, JWT, refresh token
- `[download]` → Directorio, concurrencia, timeout
- `[search]` → Límite por defecto, filtros, región
- `[logging]` → Nivel, archivo de log, tamaño máximo
- `[authentication]` → Auto-refresh, umbral de expiración

### Campos Críticos:
- `base_url`: URL del servidor (requerido)
- `guid`: Identificador único (requerido)
- `jwt_token`: Token de autenticación (requerido)
- `output_directory`: Ruta de descargas (requerido)
- `max_concurrent_downloads`: Entre 1 y 5 (default: 3)

---

## 🎯 MÓDULOS Y SUS RESPONSABILIDADES

### Módulo de Configuración (settings.py)
**Responsabilidad**: Cargar, validar, actualizar configuración desde config.ini

**Métodos Necesarios:**
- `load_from_file()` → Cargar config.ini
- `validate_config()` → Verificar campos requeridos
- `get(section, key)` → Obtener valor
- `get_int(section, key)` → Obtener entero
- `get_bool(section, key)` → Obtener booleano
- `update(section, key, value)` → Guardar cambios

**Reglas Específicas:**
- Usar configparser de stdlib
- Validar que archivos requeridos existan
- Lanzar excepción si config es inválida
- Permitir valores por defecto sensatos

### Módulo de Autenticación (authenticator.py)
**Responsabilidad**: Autenticar, gestionar tokens JWT, refrescar automáticamente

**Métodos Necesarios:**
- `authenticate(guid, password)` → Obtener JWT inicial
- `refresh_token()` → Refrescar token expirado
- `validate_token()` → Verificar validez del token
- `is_token_expired()` → Checar expiración
- `get_headers()` → Headers HTTP con JWT

**Reglas Específicas:**
- Implementar backoff exponencial (1s, 2s, 4s)
- Máximo 3 reintentos en fallos de red
- NUNCA loguear tokens completos
- Almacenar token en config.ini después de obtenerlo
- Refrescar automático si está cercano a expiración
- Lanzar AuthenticationError si falla

### Módulo de Sesión (session_manager.py)
**Responsabilidad**: Gestionar ciclo de vida de sesiones autenticadas

**Métodos Necesarios:**
- `start_session()` → Iniciar sesión
- `end_session()` → Cerrar sesión
- `is_active()` → Verificar si activa
- `get_session_info()` → Info de sesión
- `refresh_if_needed()` → Auto-refresh

**Reglas Específicas:**
- Usar Authenticator internamente
- Verificar expiración antes de operaciones
- Loguear inicio/cierre de sesión
- Manejar desconexiones de red

### Crawlers (REFERENCIA de cómo funcionan autenticación y descarga)
**Responsabilidad**: Servir como referencia de autenticación y descarga desde APIs Motorola

**Referencia para implementar:**
- Cómo autenticarse con JWT en headers
- Cómo construir requests con token válido
- Cómo manejar tokens expirados
- Cómo descarga funciona en servidores Motorola
- Estructura de respuestas de APIs
- Manejo de errores de autenticación

**Reglas Específicas:**
- NOTA: No copiar carpeta de crawlers como estructura
- Usar como referencia educativa solamente
- Buscar patrones de autenticación reales
- Entender flujo de download en Motorola
- Adaptar a tu propio sistema

### Motor de Búsqueda (search_engine.py)
**Responsabilidad**: Orquestar búsquedas en múltiples crawlers

**Métodos Necesarios:**
- `search(query, content_type, filters)` → Búsqueda principal
- `advanced_search(criteria)` → Búsqueda avanzada
- `get_suggestions(partial_query)` → Autocompletado

**Reglas Específicas:**
- Combinar resultados de múltiples crawlers
- Deduplicar automáticamente
- Aplicar filtros a todos los resultados
- Ranking de relevancia
- Caché de búsquedas recientes
- Soportar búsqueda por tipo (Firmware, ROM, Tools, All)

### Gestor de Descargas (download_manager.py)
**Responsabilidad**: Descargar archivos de forma concurrente y confiable

**Métodos Necesarios:**
- `download_single(url, filepath)` → Descargar un archivo
- `download_multiple(items, output_dir)` → Descargar varios
- `set_max_concurrent(workers)` → Configurar concurrencia
- `pause_downloads()` → Pausar descargas
- `resume_downloads()` → Reanudar descargas

**Reglas Específicas:**
- ThreadPoolExecutor para concurrencia
- Máximo de workers configurable (1-5)
- Reanudar descargas parciales
- Loguear progreso
- Reintentar si descarga falla (máximo 3)
- Mostrar velocidad y ETA

### Cliente HTTP Reutilizable (http_client.py)
**Responsabilidad**: Centralizar todas las operaciones HTTP

**Métodos Necesarios:**
- `get(url, params)` → GET request
- `post(url, json_data)` → POST request
- `download(url, file_path, chunk_size)` → Descargar archivo
- `set_headers(headers)` → Actualizar headers
- `close()` → Cerrar sesión

**Reglas Específicas:**
- Usar requests library
- Implementar retry strategy automático
- Headers con User-Agent
- Timeout configurable desde config
- Loguear requests y errores
- Manejar status codes apropiadamente
- HTTPS obligatorio

### Logger Centralizado (logger.py)
**Responsabilidad**: Logging uniforme en toda la aplicación

**Requisitos:**
- Singleton pattern (un logger por nombre)
- File handler (rotativo si es muy grande)
- Console handler (para usuario)
- Formato: timestamp, nombre módulo, nivel, mensaje
- NUNCA loguear credenciales, tokens o passwords
- Leer nivel desde config.ini

**Reglas Específicas:**
- Crear carpeta logs/ automáticamente
- Niveles: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Rotación de logs por tamaño
- Máximo 5 archivos backup

### Encriptación (encryption.py)
**Responsabilidad**: Cifrar/descifrar datos sensibles

**Métodos Necesarios:**
- `encrypt(text, key)` → Cifrar con AES-256
- `decrypt(encrypted_text, key)` → Descifrar
- `generate_key()` → Generar clave aleatoria
- `hash_password(password)` → Hash para passwords

**Reglas Específicas:**
- Usar cryptography library
- AES-256 para datos generales
- Bcrypt para passwords
- Claves seguras (256 bits)
- Manejar excepciones de encriptación

### Validadores (validators.py)
**Responsabilidad**: Validar datos de entrada

**Funciones Necesarias:**
- `validate_guid(guid)` → Formato válido
- `validate_jwt(token)` → JWT válido
- `validate_url(url)` → URL válida
- `validate_file_path(path)` → Path válida

**Reglas Específicas:**
- Usar regex para validaciones
- Retornar bool (no excepciones)
- Loguear validaciones fallidas
- Mensajes de error descriptivos

### Interfaz CLI (cli/main.py)
**Responsabilidad**: Interacción con usuario mediante menú

**Métodos Necesarios:**
- `run()` → Loop principal
- `show_main_menu()` → Menú principal
- `search_menu()` → Submenú de búsqueda
- `download_menu()` → Submenú de descarga
- `config_menu()` → Submenú de configuración

**Reglas Específicas:**
- Menús numerados y claros
- Validar entrada del usuario
- Confirmaciones antes de acciones importantes
- Mostrar resultados formateados
- Barra de progreso para descargas
- Input/output amigable
- Manejo de Ctrl+C graceful

### Punto de Entrada (main.py)
**Responsabilidad**: Inicializar aplicación y ejecutar

**Requisitos:**
- Cargar configuración
- Inicializar logger
- Verificar credenciales
- Crear instancias de módulos
- Ejecutar CLI
- Manejo de excepciones global

---

## 📊 FLUJOS PRINCIPALES

### Flujo de Búsqueda:
1. Usuario ingresa consulta en CLI
2. CLI valida entrada
3. SearchEngine recibe query, tipo, filtros
4. Se distribuye a crawlers apropiados
5. Crawlers realizan requests HTTP con reintentos
6. Respuestas se parsean y filtran
7. Resultados se deduplicar y ranking
8. Se retornan al usuario
9. Usuario selecciona archivos

### Flujo de Descarga:
1. Usuario selecciona archivos de búsqueda
2. DownloadManager crea tasks para cada archivo
3. ThreadPoolExecutor distribuye tareas
4. Cada thread descarga concurrentemente
5. ProgressHandler actualiza barra de progreso
6. Si falla, reintentar (máximo 3)
7. Si ok, guardar archivo
8. Mostrar resumen al usuario

### Flujo de Autenticación:
1. Aplicación inicia
2. Settings carga config.ini
3. Authenticator intenta usar JWT existente
4. Si válido, continuar
5. Si expirado/inválido, usar refresh_token
6. Si refresh falla, pedir nueva autenticación
7. Guardar nuevo JWT en config.ini
8. SessionManager marca sesión como activa

---

## ⚙️ PATRONES REQUERIDOS

### Patrón: Retry con Backoff Exponencial
```
Intentar operación
Si falla:
  Para cada reintento (máximo 3):
    Esperar: base_delay * (exponente ^ intento)
    Intentar nuevamente
  Si todos fallan:
    Loguear error
    Retornar None o lanzar excepción
```

### Patrón: Gestión de Excepciones
```
try:
    operación que puede fallar
except TipoEspecíficoError as e:
    loguear error específico
    manejar situación
except Exception as e:
    loguear error genérico
    decidir si relanzar
finally:
    limpieza si es necesaria
```

### Patrón: Validación de Entrada
```
Recibir entrada del usuario
Validar tipo
Validar formato
Validar valores
Si válida: procesar
Si inválida: loguear y pedir nuevamente
```

### Patrón: Logging
```
Inicio de operación: logger.info("Iniciando operación X")
Progreso: logger.info("Paso Y completado")
Advertencia: logger.warning("Situación inusual")
Error: logger.error("Fallo en operación: {detalles}")
Nunca: logger.info(f"Token: {self.jwt_token}")
```

---

## 🎯 CARACTERÍSTICAS ESPERADAS

### Búsqueda
- Búsqueda por modelo de dispositivo
- Búsqueda por versión del firmware
- Búsqueda por región
- Filtro por fecha de lanzamiento
- Filtro por tamaño máximo
- Incluir/excluir versiones beta
- Sugerencias de búsqueda

### Descarga
- Descargar múltiples archivos simultáneamente
- Mostrar progreso en tiempo real
- Velocidad de descarga
- ETA de tiempo restante
- Reanudar descargas interrumpidas
- Reintentos inteligentes

### Autenticación
- Autenticación con GUID y JWT
- Refrescado automático de token
- Almacenamiento seguro de credenciales
- Gestión de sesión
- Manejo de tokens expirados

### Configuración
- Archivo config.ini centralizado
- Edición de configuración desde CLI
- Validación de campos requeridos
- Valores por defecto razonables
- Persistencia de cambios

---

## 🚀 TECNOLOGÍAS PERMITIDAS

### Requeridas:
- `requests` → HTTP requests
- `configparser` → Gestión de config.ini
- `cryptography` → Encriptación
- `tqdm` → Barra de progreso

### Opcionales (si mejorar experiencia):
- `click` → CLI mejorada
- `pydantic` → Validación de datos
- `colorama` → Colores en terminal

### Prohibidas:
- NumPy, Pandas (análisis de datos)
- Flask, Django (web frameworks)
- SQLAlchemy (ORM)
- Cualquier base de datos

---

## 📝 ESTÁNDARES DE CALIDAD

### Código:
- ✅ Máximo 100 líneas por función
- ✅ Type hints en 100% de funciones
- ✅ Docstrings en 100% de funciones
- ✅ Manejo de excepciones explícito
- ✅ Variables con nombres descriptivos
- ✅ Comentarios solo donde sea necesario

### Legibilidad:
- ✅ Imports ordenados y agrupados
- ✅ Métodos en orden lógico
- ✅ Constantes en mayúsculas
- ✅ Funciones privadas con underscore
- ✅ Spacing consistente

### Performance:
- ✅ No hacer requests bloqueantes innecesarios
- ✅ Usar caché de búsquedas
- ✅ Descargas concurrentes
- ✅ Cerrar conexiones apropiadamente
- ✅ No cargar archivos completos en memoria

---

## 🔒 REGLAS DE SEGURIDAD

### Credenciales:
- NUNCA hardcodear credenciales
- Siempre usar config.ini
- NUNCA loguear tokens
- NUNCA enviar credenciales en URLs
- Cifrar si se almacenan en disco

### Validación:
- Validar TODAS las entradas del usuario
- Validar TODOS los datos de APIs
- Usar whitelisting cuando sea posible
- Rechazar datos malformados

### Conexiones:
- HTTPS obligatorio
- Verificar certificados SSL
- No seguir redirects inseguros
- Timeout en todas las conexiones

### Archivos:
- Validar rutas de archivos
- No permitir path traversal
- Usar permisos apropiados

---

## ✅ CHECKLIST FINAL

Antes de considerar el proyecto completo:

- [ ] Todos los módulos implementados (sin tests)
- [ ] Type hints en 100% del código
- [ ] Docstrings en 100% de funciones
- [ ] Logging centralizado funcionando
- [ ] config.ini con ejemplos y validación
- [ ] Autenticación JWT con refresh
- [ ] Búsqueda en múltiples crawlers
- [ ] Descargas concurrentes
- [ ] CLI interactiva completa
- [ ] Manejo de errores robusto
- [ ] Código limpio y formateado
- [ ] Requisitos en requirements.txt
- [ ] README con instrucciones
- [ ] .gitignore apropiado
- [ ] CERO archivos de test
- [ ] CERO archivos CI/CD
- [ ] CERO normas o protocolos de redes

---

## 📞 FINAL

**Estas son TODAS las instrucciones y reglas.**

No incluyas tests, no incluyas ejemplos de código, no incluyas estructura de carpetas, no incluyas normas de redes.

Solo genera módulos de producción profesionales siguiendo estas reglas.