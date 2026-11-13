# Plataforma de órdenes de bloqueo en vivo

Solo biblioteca estándar de Python 3.9+. Para el PDF hace falta Chrome o Chromium.

## Correr el circuito completo (partido de práctica)

```bash
python simulador/servidor.py --escenario datos/escenario_practica.json --acelerar 6   # simulador (puerto 8080)
python plataforma/servidor.py --simulador http://localhost:8080                        # plataforma (puerto 8090)
```

- Interfaz del juez (se adapta al celular): http://localhost:8090/
- Registro público de transparencia: http://localhost:8090/publico

Usuarios de demostración (ficticios):

| Usuario | Contraseña | Juez | Turno (min) |
|---|---|---|---|
| `laura` | `laura-demo-2026` | Dra. Laura Ficticia | −60 a 50 |
| `martin` | `martin-demo-2026` | Dr. Martín Ejemplo | 50 a 240 |

Para el partido final, apuntar `--simulador` a la IP asignada.

## Con Supabase (la app del equipo hace de interfaz del juez)

El motor sigue hablando con el simulador, pero publica todo en el Supabase de la app web. El juez firma desde
`https://expedientes-futbol.vercel.app/#/juez` y el motor manda las órdenes a los proveedores.

1. Una sola vez, en el SQL Editor de Supabase: `supabase/schema.sql` (si no se corrió) y después `supabase/motor.sql`.
2. En la compu del equipo, conectada a la red del simulador:

```bash
export SUPABASE_SERVICE_KEY=...   # Project Settings → API → service_role. Nunca al repositorio.
python plataforma/servidor.py --simulador http://<ip-asignada>:8080 --supabase-url https://<proyecto>.supabase.co
```

Al arrancar, el motor:
- crea en Supabase Auth a `laura@jueces.test` y `martin@jueces.test` (mismas contraseñas de la tabla de arriba);
- copia los turnos del simulador a `turnos`, en hora real, así la RLS solo deja firmar al juez de turno.

| Qué | Dónde queda en Supabase |
|---|---|
| Expediente de cada servidor pirata, con resumen, IP/ASN, marca y riesgo colateral | `expedientes` (`en_cola_juez`, `contenido.origen = 'motor'`) |
| Firma o rechazo del juez desde la app | `firmas` / `expedientes.estado`: el motor lo toma y firma la orden con HMAC para el simulador |
| Reenvío que necesita otra firma (el juez que firmó salió de turno) | `expedientes` con número `RE-…` |
| Estado de cada orden en cada proveedor: aplicada, fallida, reintentos, vencida, levantada | `ordenes` (`origen = 'motor'`) |
| Reclamos del simulador con la verificación del motor; el juez los acepta o rechaza en la app | `reclamos` |
| Cada evento de la auditoría local, con su hash | `auditoria` (`detalle.hash_local`) |

La auditoría local y `entrega/` se siguen generando igual, y `verificar.py` se corre igual.
Si Supabase se corta, el motor sigue enviando y confirmando órdenes y reintenta la sincronización.

Prueba sin la app, con un juez automático que usa la clave anon y la RLS igual que el navegador:
`python pruebas/juez_supabase.py --supabase-url <url> --anon <clave-anon>`.
Con `--sin-reclamos` firma los expedientes y deja los reclamos para resolverlos desde la app (Juez → Reclamos → «Aceptar y levantar»):
el motor levanta la orden en cada proveedor y la reemplaza por un bloqueo por dominio.

## Qué hace

1. **Expediente** (`expedientes.py`): marca de agua verificada contra el partido y los licenciatarios, servidor (host, IP y ASN), riesgo colateral por DNS pasivo (IP o dominio), hashes encadenados de las capturas, promoción y vencimiento.
2. **Juez**:
   - Notifica al juez de turno. Cada juez entra con usuario y contraseña (PBKDF2) y ve solo lo que tiene asignado.
   - Firma solo si está de turno. Al cambio de turno, lo pendiente pasa al juez entrante.
   - La decisión queda firmada sobre el hash del expediente.
3. **Proveedores**:
   - Envía la orden firmada a cada proveedor en el tipo que acepta. FibraValle solo acepta dominio, así que se le piden los dominios del sitio.
   - Sigue la confirmación. Si falla, reintenta con un `orden_id` nuevo (las firmas de reserva se generan al aprobar).
   - Si el juez que firmó ya salió de turno, el reenvío lo firma el entrante.
4. **Vencimiento**: todas las órdenes vencen en el minuto 105. Después del partido se verifica que no quede ningún bloqueo por IP activo.
5. **Auditoría**: `entrega/auditoria.jsonl`, encadenada con SHA-256. Se verifica con `python plataforma/servidor.py --verificar-auditoria entrega/auditoria.jsonl`.
6. **Extras**:
   - Reclamos: verificación por DNS pasivo, levantamiento firmado y reemplazo por dominio.
   - Registro público.
   - Interfaz para celular con notificaciones, sonido y vibración.
7. **Costo para el pirata**:
   - Si un sitio aparece en otro servidor, el expediente se marca reincidente y se muestra primero al juez.
   - Al aprobar, se emiten avisos al hosting dueño de la IP (suspender al cliente, preservar datos, no darle otra IP) y a cada red donde se promocionó el enlace. Quedan en `entrega/avisos/` y en la auditoría.

## Salidas en `entrega/`

- `expedientes.json` y `expedientes/EXP-*.json`: expedientes del punto 1. Se verifican con `python plataforma/expedientes.py --verificar entrega/expedientes.json`.
- `evidencia/EXP-*/D-*.ts` y `evidencia/SHA256SUMS`: cada captura como archivo propio. El juez la descarga desde su pantalla (queda en la auditoría) y la verifica con `cd entrega/evidencia && sha256sum -c SHA256SUMS`.
- `plataforma.json`: decisiones, envíos, reintentos, reclamos y transparencia.
- `avisos/EXP-*-HOST.txt` y `avisos/EXP-*-RED*.txt`: avisos al hosting y a las redes sociales.
- `auditoria.jsonl`: registro de auditoría.
- `informe_expedientes.pdf`: informe completo. Se genera con `python plataforma/informe_pdf.py`.
- `propuesta_normativa.md`.

## Prueba automática

`pruebas/juez_automatico.py` simula a los dos jueces usando la misma API que la interfaz web (login con contraseña, aprobar, firmar reenvíos, decidir reclamos). También intenta firmar fuera de turno para comprobar que se rechaza. Se usa solo para probar.
