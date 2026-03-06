# Guía Rápida: Login con Hero

## Instalación

```bash
# 1. Instalar Hero
npm install

# 2. Verificar instalación
node --version  # Debe mostrar v16 o superior
ls node_modules/@ulixee/hero  # Debe existir
```

## Uso Simple

### Opción 1: Script de prueba (más fácil)

```bash
python test_hero_login.py
```

Ya tiene las credenciales incluidas: `eduardo@uaemex.top` / `Edu@rdoc310104`

### Opción 2: Variables de entorno (recomendado)

```bash
export LMSA_EMAIL="eduardo@uaemex.top"
export LMSA_PASSWORD="Edu@rdoc310104"

python -m web_crawler https://rsddownload-secure.lenovo.com/ --debug
```

### Opción 3: Código Python

```python
from web_crawler.auth.lenovo_id import LenovoIDAuth

auth = LenovoIDAuth()
session = auth.login(
    email="eduardo@uaemex.top",
    password="Edu@rdoc310104"
)

if session:
    print("✓ Login exitoso!")
    print(f"Autenticado: {session.is_authenticated}")
else:
    print("✗ Login falló")
```

## Qué hace Hero

1. Abre navegador invisible (headless)
2. Va a passport.lenovo.com
3. Espera que Akamai cargue (15 segundos)
4. Llena email: `eduardo@uaemex.top`
5. Click en "Siguiente"
6. Llena password: `Edu@rdoc310104`
7. Click en "Siguiente" (submit)
8. Captura token WUST del redirect
9. Lo intercambia por JWT en lsa.lenovo.com
10. ¡Listo! Sesión autenticada

## Cadena de fallback automática

Si Hero falla, el sistema automáticamente intenta:
1. **Hero** ← intenta primero
2. **zendriver** ← si Hero falla
3. **Playwright** ← si zendriver falla
4. **HTTP directo** ← último recurso

## Solución de problemas

### "Hero not available"

```bash
npm install
```

### "Node.js not found"

Instalar Node.js desde https://nodejs.org/

### "Login failed"

1. Verificar credenciales
2. Ejecutar con `--debug` para ver logs detallados:
   ```bash
   python test_hero_login.py --debug
   ```

### Ver logs detallados

Los mensajes importantes tienen prefijo `[Hero]`:
- `[Hero] Launching Hero login script...` - Iniciando
- `[Hero] Waiting for Akamai sensor...` - Esperando Akamai
- `[Hero] ✓ WUST token obtained` - ¡Éxito!
- `[Hero] Login failed: ...` - Error (ver mensaje)

## Ventajas de Hero

✓ **Mejor bypass de Akamai** - Diseñado específicamente para evasión
✓ **TLS fingerprinting** - Imita exactamente navegadores reales
✓ **Timing realista** - Patrones de red naturales
✓ **Siempre actualizado** - Mantiene compatibilidad con Chrome más reciente
✓ **Sin detección** - Elimina todas las señales de automatización

## Archivos importantes

- `hero_login.js` - Script Node.js que controla Hero
- `web_crawler/auth/hero_client.py` - Cliente Python
- `test_hero_login.py` - Prueba rápida
- `HERO_INTEGRATION.md` - Documentación técnica completa
- `IMPLEMENTACION_HERO.md` - Resumen de implementación

## Contacto

Para más ayuda, revisar:
1. `HERO_INTEGRATION.md` - Guía técnica completa
2. `IMPLEMENTACION_HERO.md` - Resumen de cambios
3. Logs del sistema con `--debug`
