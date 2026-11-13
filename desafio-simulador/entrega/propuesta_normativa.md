# Propuesta normativa: órdenes de bloqueo en vivo de transmisiones deportivas

Qué tendría que establecer una ley o una resolución para que la plataforma funcione, y por qué. Todo lo que sigue se ejercitó en el simulador del desafío.

**1. Orden marco previa al partido.** Antes de cada torneo, el titular de derechos tramita una orden marco ante un juzgado competente. La orden identifica el evento, las marcas de agua oficiales y los licenciatarios autorizados con sus dominios. Durante el partido el juez no vuelve a decidir si hay derecho: decide si cada stream concreto encuadra en esa orden. *Por qué:* así la decisión en vivo tarda minutos y no días, sin dejar de ser judicial.

**2. Juez de turno y firma digital.** Debe haber un juez de turno durante todo el partido, con traspaso explícito de lo pendiente al cambio de turno. Cada orden la firma un juez identificado y solo mientras está de turno. Nadie puede firmar en su nombre. *Por qué:* responsabilidad personal y competencia clara en cada minuto.

**3. Estándar mínimo de evidencia.** Cada pedido debe incluir:
- la marca de agua que lo vincula con el partido;
- el servidor que entrega el video (host, IP y ASN), y no la página del reproductor;
- los sitios que comparten esa IP;
- capturas con hash y sello de tiempo;
- el vencimiento propuesto.

*Por qué:* el juez decide con hechos verificables, y cualquier alteración posterior se puede detectar.

**4. Registro de proveedores con API obligatoria.** Los proveedores de internet de cierto tamaño deben inscribirse e informar:
- qué tipo de bloqueo pueden aplicar (IP o dominio);
- un punto de recepción automático de órdenes firmadas.

**5. Plazos de aplicación.** Cada proveedor tiene que aplicar la orden y confirmarlo dentro de un plazo corto y fijo (por ejemplo, 5 minutos para los grandes y 10 para los chicos). Si falla, reintenta enseguida. *Por qué:* un bloqueo que llega en el segundo tiempo no sirve.

**6. Control del daño colateral.**
- Se prohíbe bloquear por IP cuando la evidencia muestra que la IP es compartida (CDN, hosting compartido): en ese caso, el bloqueo es por dominio.
- Nunca se bloquea a un licenciatario en sus dominios autorizados.
- Ningún bloqueo puede quedar activo después del partido: los bloqueos por IP vencen automáticamente al terminar.

*Por qué:* el costo de un error recae sobre terceros que no tienen nada que ver con el partido.

**7. Reclamos rápidos.** Cualquier sitio afectado puede reclamar por una vía simple. El reclamo se verifica de inmediato y, si corresponde, el juez de turno levanta la orden con su firma y la reemplaza por un bloqueo más preciso, en minutos y no en días. También se definen responsabilidades por bloqueos indebidos.

**8. Auditoría y transparencia.**
- Cada paso queda registrado en forma inalterable: detección, firma, envío, confirmación, vencimiento y reclamo.
- Existe un registro público de órdenes que dice qué se bloqueó, quién lo ordenó, en qué proveedor y hasta cuándo.
- Se publican informes periódicos con errores y reclamos.

*Por qué:* el control social y judicial posterior legitima una herramienta que restringe el acceso a internet.

**9. Deber de colaboración de hosting y redes.** Con la misma orden firmada, el hosting dueño de la IP debe suspender al cliente que opera el servidor, preservar sus datos de contratación y pago, y no darle otra IP para el mismo uso; las redes sociales deben retirar las publicaciones que promocionan el enlace. *Por qué:* cada bloqueo le cuesta un servidor nuevo al pirata, y si además pierde el hosting y la difusión, transmitir deja de convenirle.

**10. Protección de datos.** Se conservan solo los datos técnicos necesarios (dominios, IP, capturas del stream), con un plazo de borrado definido y sin datos de usuarios finales.
