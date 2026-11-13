#!/usr/bin/env python3
"""Genera el informe en PDF a partir de entrega/expedientes.json (punto 1) y, si existe, entrega/plataforma.json
(juez, firma, proveedores, vencimiento, reclamos, transparencia y auditoría).

Arma un HTML pensado para impresión A4 y lo convierte a PDF con Chrome/Chromium en modo headless.

Uso:
  python plataforma/informe_pdf.py                                  # entrega/expedientes.json -> entrega/informe_expedientes.pdf
  python plataforma/informe_pdf.py --entrada X.json --salida Y.pdf
"""
import argparse
import html
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from expedientes import ETIQUETAS, REPO_DIR, exportar_capturas, sha256, verificar_archivo  # noqa: E402

h = html.escape

CSS = """
@page { size: A4; margin: 16mm 14mm 18mm 14mm;
  @bottom-center { content: counter(page); } }
* { box-sizing: border-box; }
body { font-family: 'DejaVu Serif', Georgia, serif; font-size: 10pt; color: #111; line-height: 1.35; }
h1 { font-size: 20pt; margin: 0 0 4pt; } h2 { font-size: 13pt; border-bottom: 1.5pt solid #1d3557; padding-bottom: 2pt; margin: 14pt 0 6pt; color: #1d3557; }
h2, h3 { break-after: avoid; page-break-after: avoid; }
thead { display: table-header-group; }
.nw { white-space: nowrap; word-break: normal; }
h3 { font-size: 10.5pt; margin: 9pt 0 3pt; color: #1d3557; }
p { margin: 3pt 0; } small, .chico { font-size: 8pt; color: #444; }
code, .mono { font-family: 'DejaVu Sans Mono', monospace; font-size: 7.6pt; word-break: break-all; }
table { width: 100%; border-collapse: collapse; margin: 4pt 0 6pt; font-size: 8.4pt; page-break-inside: auto; }
th, td { border: 0.6pt solid #9aa5b1; padding: 2.5pt 4pt; text-align: left; vertical-align: top; }
th { background: #e8edf3; } tr { page-break-inside: avoid; }
.portada { border: 2pt solid #1d3557; padding: 12pt 14pt; margin-bottom: 10pt; }
.aviso { border: 0.8pt solid #c9a227; background: #fff8e1; padding: 5pt 8pt; font-size: 8.5pt; margin: 6pt 0; }
.exp { page-break-before: always; }
.cab { display: flex; justify-content: space-between; border: 1.2pt solid #1d3557; padding: 6pt 9pt; background: #f2f5f9; }
.cab b { font-size: 13pt; } .kv td:first-child { width: 30%; background: #f7f9fb; font-weight: bold; }
.ok { color: #0b6b3a; font-weight: bold; } .alerta { color: #a4161a; font-weight: bold; }
.pedido { border: 1.5pt solid #1d3557; padding: 7pt 10pt; margin-top: 8pt; page-break-inside: avoid; }
.firma { display: flex; gap: 18pt; margin-top: 16pt; } .firma div { flex: 1; border-top: 0.8pt solid #111; padding-top: 2pt; font-size: 8pt; text-align: center; }
.resumen td, .resumen th { font-size: 8pt; }
"""


def fila(k: str, v: str) -> str:
    return f"<tr><td>{h(k)}</td><td>{v}</td></tr>"


def portada(d: dict, verificacion: str) -> str:
    p, exps, desc = d["partido"], d["expedientes"], d["detecciones_descartadas"]
    sitios = sorted({e["sitio"] for e in exps})
    filas = "".join(
        f"<tr><td>{h(e['expediente_id'])}</td><td>{h(e['sitio'])}{' (cambio de servidor)' if e['cambio_de_servidor'] else ''}</td>"
        f"<td class=mono>{h(e['servidor']['host_stream'])}</td><td class='mono nw'>{h(e['servidor']['ip'])}</td>"
        f"<td>AS{e['servidor']['asn']}</td><td>{len(e['riesgo_colateral']['dominios_de_terceros'])}</td>"
        f"<td><b>{h(e['pedido']['tipo'].upper())}</b> <br><span class=mono>{h(e['pedido']['objetivo'])}</span></td>"
        f"<td>{e['primera_deteccion_min']:g}–{e['ultima_deteccion_min']:g}</td><td>{e['pedido']['vence_min']}</td></tr>"
        for e in exps)
    filas_desc = "".join(
        f"<tr><td>{h(x['deteccion_id'])}</td><td>{x['minuto']:g}</td><td class=mono>{h(x['host_stream'])}</td>"
        f"<td class=mono>{h(str(x['marca']))}</td><td>{h(ETIQUETAS.get(x['motivo'], x['motivo']))}</td><td>{h(x['detalle'])}</td></tr>"
        for x in desc)
    licenciatarios = "; ".join(f"{l['nombre']} ({l['prefijo_marca']}: {', '.join(l['dominios_autorizados'])})"
                               for l in p.get("licenciatarios", []))
    marcas = "; ".join(f"{m['prefijo']} — {m['origen']}" for m in p.get("marcas_de_agua_validas", []))
    return f"""
<div class=portada>
<div class=chico>PLATAFORMA FEDERAL DE ÓRDENES DE BLOQUEO EN VIVO · CONSIGNA 1</div>
<h1>Informe de expedientes de streams piratas</h1>
<p><b>Partido:</b> {h(p.get('nombre', ''))} &nbsp;·&nbsp; <b>ID:</b> {h(str(p.get('id', '')))}</p>
<p><b>Titular de derechos:</b> {h(p.get('titular_derechos', ''))} &nbsp;·&nbsp; <b>Inicio:</b> {h(p.get('inicio_iso', ''))}</p>
<p><b>Generado:</b> {h(d['generado_utc'])} (UTC), minuto de partido {d['minuto_partido']} &nbsp;·&nbsp; <b>Fuente:</b> API del simulador</p>
</div>
<div class=aviso>Todos los datos son ficticios (simulador del Desafío Fútbol, Hackathon Argentina Space 2026). Dominios .test/.example,
IPs de documentación y ASN privados. No se bloquea nada real. Este informe no es asesoramiento legal.</div>

<h2>1. Resumen</h2>
<p>Se analizaron <b>{sum(len(e['evidencia']) for e in exps) + len(desc)}</b> detecciones. Se identificaron <b>{len(sitios)}</b> sitios piratas
({h(', '.join(sitios))}) servidos desde <b>{len(exps)}</b> servidores distintos, con <b>{sum(e['cambio_de_servidor'] for e in exps)}</b>
cambios de servidor durante el partido. Se abrió un expediente por servidor. Se piden <b>{sum(e['pedido']['tipo'] == 'ip' for e in exps)}</b>
bloqueos por IP y <b>{sum(e['pedido']['tipo'] == 'dominio' for e in exps)}</b> por dominio. <b>{len(desc)}</b> detecciones se descartaron sin pedir bloqueo.</p>
<table class=resumen><thead><tr><th>Expediente</th><th>Sitio</th><th>Host del stream</th><th>IP</th><th>ASN</th><th>Terceros en la IP</th><th>Bloqueo pedido</th><th>Detectado (min)</th><th>Vence (min)</th></tr></thead>{filas}</table>

<h2>2. Criterios aplicados</h2>
<table class=kv>
{fila('Señal oficial', f'La marca de agua extraída debe empezar con un prefijo válido del partido ({h(marcas)}). Si corresponde a un licenciatario y se sirve desde sus dominios autorizados, es retransmisión legal y se descarta. Licenciatarios: {h(licenciatarios)}.')}
{fila('Servidor', 'Se identifica el host y la IP que entregan el video (stream HLS) y su ASN. Se bloquea el servidor del video y no la página del reproductor, porque bloquear la página no corta el video.')}
{fila('Riesgo colateral', 'Se consulta el DNS pasivo de la IP. Si aloja dominios de terceros (CDN u hosting compartido), se pide bloqueo por dominio del host del stream. Si solo aloja dominios del propio sitio, se pide bloqueo por IP, que también corta los espejos.')}
{fila('Integridad', 'Cada detección se sella con el SHA-256 de la captura, el SHA-256 de la detección original y un hash encadenado con la evidencia anterior. Cada expediente tiene además su propio hash. Cualquier modificación posterior rompe la cadena.')}
{fila('Sellos de tiempo', 'Minuto de partido y hora oficial de la captura (inicio del partido + minuto), más la hora UTC en que la plataforma recibió la detección.')}
{fila('Vencimiento', 'Todos los pedidos vencen al terminar el partido (minuto 105). Los bloqueos por IP no deben quedar activos después.')}
</table>

<h2>3. Detecciones descartadas</h2>
<table><thead><tr><th>Detección</th><th>Min</th><th>Host</th><th>Marca extraída</th><th>Motivo</th><th>Fundamento</th></tr></thead>{filas_desc}</table>

<h2>4. Verificación de integridad</h2>
<p>Hash final de la cadena de evidencia: <span class=mono>{d['hash_cadena_final']}</span></p>
<p>Resultado de <span class=mono>python plataforma/expedientes.py --verificar entrega/expedientes.json</span>: <b class=ok>{h(verificacion)}</b></p>
"""


FIRMA_EN_BLANCO = """<p>Decisión: &nbsp; ☐ Aprueba &nbsp;&nbsp; ☐ Rechaza</p>
<div class=firma><div>Juez de turno</div><div>Juzgado</div><div>Firma y fecha/hora</div></div>"""


CAPTURAS: dict = {}
PARTIDO: dict = {}


def _datos(nombre: str) -> dict:
    return json.loads((REPO_DIR / "datos" / nombre).read_text(encoding="utf-8"))


def juzgado_de_turno(minuto: float) -> tuple:
    j = _datos("juzgados.json")
    for t in j["turnos"]:
        if t["desde_min"] <= minuto < t["hasta_min"]:
            for jz in j["juzgados"]:
                for juez in jz["jueces"]:
                    if juez["id"] == t["juez_id"]:
                        return juez["nombre"], jz["nombre"], jz["jurisdiccion"]
    return "", "", ""


def alcance(pe: dict) -> tuple:
    provs = _datos("proveedores.json")["proveedores"]
    filas, total = [], 0
    for pr in provs:
        tipo = pe["tipo"] if pe["tipo"] in pr["capacidades"] else "dominio"
        total += pr["clientes"]
        filas.append(f"{h(pr['nombre'])}: {tipo} ({pr['clientes']:,} clientes)".replace(",", "."))
    return total, filas


def resumen_juez(e: dict, tramite: dict = None) -> str:
    vm, srv, rc, pe = e["verificacion_marca"], e["servidor"], e["riesgo_colateral"], e["pedido"]
    juez, juzgado, jurisdiccion = juzgado_de_turno(e["primera_deteccion_min"])
    if tramite and tramite.get("decision"):
        juzgado = tramite["decision"].get("juzgado") or juzgado
    total, filas = alcance(pe)
    restantes = max(0, pe["vence_min"] - e["primera_deteccion_min"])
    terceros = len(rc["dominios_de_terceros"])
    previos = e["expedientes_previos_del_sitio"]
    return f"""<div class=pedido style="margin-bottom:6pt"><b>Resumen para decidir</b>
<table class=kv>
{fila('Qué se pide', f"Bloqueo por <b>{h(pe['tipo'].upper())}</b> de <span class=mono>{h(pe['objetivo'])}</span> hasta el minuto {pe['vence_min']} ({h(pe['vence_hora'] or '')})")}
{fila('Por qué es el partido', f"Marca <span class=mono>{h(vm.get('marca', ''))}</span> = prefijo oficial <span class=mono>{h(vm.get('prefijo') or '')}</span>; el host no es de un licenciatario")}
{fila('Dónde está el video', f"<span class=mono>{h(srv['stream_url'])}</span> → {h(srv['ip'])}, AS{srv['asn']} {h(srv.get('organizacion_asn') or '')}")}
{fila('Terceros afectados', 'ninguno: la IP es exclusiva del sitio' if not terceros else f"{terceros} dominios comparten la IP; por eso se pide dominio")}
{fila('Prueba', f"{len(e['evidencia'])} capturas de video con SHA-256, sellos de tiempo y archivo propio (sección 4)")}
{fila('Antecedentes', 'primer servidor del sitio' if not previos else 'el sitio ya fue detectado en ' + h(', '.join(previos)) + ' y cambió de servidor')}
{fila('Alcance', f"{len(filas)} proveedores, {total:,} clientes: ".replace(',', '.') + '; '.join(filas))}
{fila('Juez competente', f"{h(juez)} — {h(juzgado)} ({h(jurisdiccion)}), de turno al detectarse")}
{fila('Urgencia', f"detectado en el minuto {e['primera_deteccion_min']:g}; quedan {restantes:g} min de partido")}
</table></div>"""


def tabla_marcas(e: dict) -> str:
    vm, host = e["verificacion_marca"], e["servidor"]["host_stream"]
    marca = vm.get("marca") or ""
    lic = {l["prefijo_marca"]: l for l in PARTIDO.get("licenciatarios", [])}
    filas = ""
    for m in PARTIDO.get("marcas_de_agua_validas", []):
        coincide = marca.startswith(m["prefijo"])
        l = lic.get(m["prefijo"])
        dominios = ", ".join(l["dominios_autorizados"]) if l else "plataforma propia del titular"
        en_su_dominio = bool(l) and any(host == d or host.endswith("." + d) for d in l["dominios_autorizados"])
        filas += (f"<tr><td class=mono>{h(m['prefijo'])}</td><td>{h(m['origen'])}</td><td>{h(dominios)}</td>"
                  f"<td class={'ok' if coincide else ''}>{'sí' if coincide else 'no'}</td>"
                  f"<td>{'sí' if en_su_dominio else 'no'}</td></tr>")
    return (f"<table><thead><tr><th>Prefijo válido del partido</th><th>Origen</th><th>Dominios autorizados</th>"
            f"<th>¿Coincide con la marca?</th><th>¿Host <span class=mono>{h(host)}</span> autorizado?</th></tr></thead>{filas}</table>")


def custodia(e: dict) -> str:
    codigo = REPO_DIR / "plataforma" / "expedientes.py"
    return f"""<table class=kv>
{fila('Origen de la evidencia', f"Detector del simulador, <span class=mono>GET /detecciones</span>; la captura es un segmento del stream <span class=mono>{h(e['servidor']['stream_url'])}</span>")}
{fila('Herramienta', f"plataforma/expedientes.py, SHA-256 <span class=mono>{sha256(codigo.read_bytes())}</span>")}
{fila('Archivos', "Cada captura se guarda tal cual en <span class=mono>entrega/evidencia/</span>; su hash se comprueba con <span class=mono>sha256sum -c SHA256SUMS</span> (Anexo G)")}
{fila('Integridad', "Cada sello incluye el hash del anterior; el expediente tiene hash propio. Alterar un byte rompe la cadena")}
</table>"""


def expediente(e: dict, capitulo: str = "", tramite: dict = None) -> str:
    vm, srv, rc, pe = e["verificacion_marca"], e["servidor"], e["riesgo_colateral"], e["pedido"]
    previos = ", ".join(e["expedientes_previos_del_sitio"])
    evid = "".join(
        f"<tr><td>{h(i['deteccion_id'])}</td><td>{i['captura_min']:g}</td><td>{h(i['captura_hora'] or '')}</td>"
        f"<td>{h(i['recibida_por_plataforma_utc'])}</td><td>{h(i['captura_formato'] or '')}, {i['captura_duracion_seg']} s, {i['captura_bytes']} B</td>"
        f"<td class=mono>{h(CAPTURAS.get(i['deteccion_id'], ''))}</td></tr>"
        for i in e["evidencia"])
    hashes = "".join(
        f"<tr><td>{h(i['deteccion_id'])}</td><td class=mono>{i['sha256_captura']}</td><td class=mono>{i['sha256_deteccion']}</td>"
        f"<td class=mono>{i['hash_encadenado']}</td></tr>" for i in e["evidencia"])
    promo = "".join(f"<tr><td>{h(x['red'])}</td><td class=mono>{h(x['url'])}</td><td>{x['minuto']:g}</td></tr>" for x in e["promocion"])
    terceros = ", ".join(rc["dominios_de_terceros"]) or "ninguno"
    marca_ok = vm["es_senal_del_partido"]
    return f"""
<section class=exp>
<div class=chico>{h(capitulo)}</div>
<div class=cab><div><b>{h(e['expediente_id'])}</b><br>{h(e['sitio'])} · fase {e['fase_del_sitio']}{' · sigue a ' + h(previos) if previos else ''}</div>
<div style="text-align:right">Estado: <b>{h((('orden ' + tramite['estado']) if tramite else e['estado']).replace('_', ' '))}</b><br><small>Abierto {h(e['abierto_utc'])} UTC</small></div></div>
<table class=kv>{fila('Página del reproductor', f"<span class=mono>{h(e['pagina'])}</span>")}
{fila('Detecciones', f"{len(e['evidencia'])} (minutos {e['primera_deteccion_min']:g} a {e['ultima_deteccion_min']:g})")}
{fila('Titular de derechos', h(e.get('titular_derechos') or ''))}</table>
{resumen_juez(e, tramite)}

<h3>1. Prueba de que es la señal oficial</h3><p class=chico>«La marca de agua extraída coincide con el partido y no corresponde a un licenciatario autorizado en su propio dominio.»</p>
<table class=kv>{fila('Marca extraída', f"<span class=mono>{h(vm.get('marca', ''))}</span>")}
{fila('Resultado', f"<span class={'ok' if marca_ok else 'alerta'}>{h(ETIQUETAS.get(vm['resultado'], vm['resultado']))}</span>")}
{fila('Fundamento', h(vm['detalle']))}</table>
{tabla_marcas(e)}

<h3>2. El servidor que entrega el video (host e IP) y su proveedor (ASN)</h3><p class=chico>«Bloquear la página que muestra el reproductor no corta el video.» Se identifica el servidor del stream, no la página.</p>
<table class=kv>{fila('URL del stream', f"<span class=mono>{h(srv['stream_url'])}</span>")}
{fila('Host', f"<span class=mono>{h(srv['host_stream'])}</span>")}
{fila('IP', f"<span class=mono>{h(srv['ip'])}</span>")}
{fila('ASN / proveedor', f"AS{srv['asn']} — {h(srv['organizacion_asn'] or 's/d')}")}
{fila('IPs vistas para el host', h(', '.join(x['ip'] for x in srv['ips_vistas_para_el_host']) or 's/d'))}</table>

<h3>3. Riesgo colateral: qué otros sitios comparten esa IP</h3><p class=chico>«Si es una CDN o un hosting compartido, la plataforma recomienda bloquear el dominio en vez de la IP.»</p>
<table class=kv>{fila('Dominios en la IP', f"{len(rc['dominios_en_la_ip'])}: <span class=mono>{h(', '.join(rc['dominios_en_la_ip']))}</span>")}
{fila('Del mismo sitio', f"<span class=mono>{h(', '.join(rc['dominios_del_mismo_sitio']) or 'ninguno')}</span>")}
{fila('De terceros (legítimos)', f"<b class={'alerta' if rc['dominios_de_terceros'] else 'ok'}>{len(rc['dominios_de_terceros'])}</b> <span class=mono>{h(terceros)}</span>")}
{fila('Conclusión', h(rc['motivo']))}</table>

<h3>4. Hashes de la captura y sellos de tiempo</h3><p class=chico>«Para que cualquier alteración posterior se detecte.»</p>
<table><thead><tr><th>Detección</th><th>Min</th><th>Hora de captura</th><th>Recibida por la plataforma (UTC)</th><th>Captura</th><th>Archivo</th></tr></thead>{evid}</table>
<table><thead><tr><th style="width:9%">Detección</th><th>SHA-256 de la captura</th><th>SHA-256 de la detección</th><th>Hash encadenado</th></tr></thead>{hashes}</table>
<p class=chico>Hash del expediente: <span class=mono>{e['hash_expediente']}</span></p>
<p><b>Cadena de custodia</b></p>{custodia(e)}

<h3>5. Dónde se promocionó el enlace (X, Discord, Telegram) — extra</h3>
<table><thead><tr><th style="width:14%">Red</th><th>URL</th><th style="width:12%">Minuto</th></tr></thead>{promo or '<tr><td colspan=3>Sin datos</td></tr>'}</table>

<h3>6. Vencimiento propuesto</h3>
<div class=pedido>
<p>Se solicita el <b>bloqueo por {h(pe['tipo'].upper())}</b> de <span class=mono style="font-size:9pt"><b>{h(pe['objetivo'])}</b></span>
en todos los proveedores de internet del registro, <b>con vencimiento automático en el minuto {pe['vence_min']}</b>
({h(pe['vence_hora'] or '')}).</p>
<p class=chico>{h(pe['fundamento_vencimiento'])} {h(rc['motivo'])}</p>
{'' if tramite else FIRMA_EN_BLANCO}
</div>
{tramite_html(e, tramite) if tramite else ''}
</section>"""


PLAT: dict = {}


def nombre_prov(pid: str) -> str:
    return next((p["nombre"] for p in PLAT.get("proveedores", []) if p["id"] == pid), pid)


def fmin(v) -> str:
    return "—" if v is None else f"{float(v):.2f}"


def aplicadas(t: dict) -> list:
    return sorted(float(it["aplicada_min"]) for env in t["envios"] for it in env["intentos"] if it.get("aplicada_min") is not None)


def costo_html(e: dict, t: dict) -> str:
    ap = aplicadas(t)
    ini = e["primera_deteccion_min"]
    al_aire = f"{ap[0] - ini:.1f} min hasta el primer bloqueo; {ap[-1] - ini:.1f} min hasta que lo bloquearon todos los proveedores" if ap else "sin bloqueo aplicado"
    avisos = t.get("avisos") or []
    filas = "".join(f"<tr><td>{h(a['id'])}</td><td>{'Hosting del servidor' if a['tipo'] == 'hosting' else 'Publicación en red social'}</td>"
                    f"<td>{h(a['destinatario'])}</td><td class=mono>{h(a['objetivo'])}</td></tr>" for a in avisos)
    host = next((a for a in avisos if a["tipo"] == "hosting"), None)
    return f"""<h3>10. Costo para el pirata y avisos a quienes le dan servicio</h3>
<table class=kv>{fila('Prioridad', '<span class=alerta>reincidente: el sitio cambió de servidor, el expediente se mostró primero al juez</span>' if t.get('reincidente') else 'normal (primer servidor del sitio)')}
{fila('Tiempo al aire desde la detección', al_aire)}
{fila('Qué pierde el pirata', f"El servidor {h(e['servidor']['ip'])} queda inutilizable para este partido; para seguir tiene que montar otro y volver a promocionarlo")}</table>
{'<table><thead><tr><th>Aviso</th><th>Tipo</th><th>Destinatario</th><th>Objetivo</th></tr></thead>' + filas + '</table>' if avisos else '<p>Sin avisos (no hubo aprobación).</p>'}
{f'<p class=chico><b>Texto del aviso al hosting:</b> {h(host["texto"])}</p>' if host else ''}"""


def costo_resumen(d: dict) -> str:
    tram = {t["expediente_id"]: t for t in PLAT["tramites"]}
    fin = d["partido"].get("fin_min", 105)
    sitios: dict = {}
    for e in sorted(d["expedientes"], key=lambda x: x["primera_deteccion_min"]):
        sitios.setdefault(e["sitio"], []).append(e)
    filas = ""
    for sitio, exps in sitios.items():
        libres, rebloqueos = 0.0, []
        for e in exps:
            ap = aplicadas(tram.get(e["expediente_id"], {"envios": []}))
            if ap:
                libres += ap[0] - e["primera_deteccion_min"]
                if e["expedientes_previos_del_sitio"]:
                    rebloqueos.append(ap[0] - e["primera_deteccion_min"])
        avisos = sum(len(tram.get(e["expediente_id"], {}).get("avisos") or []) for e in exps)
        filas += (f"<tr><td>{h(sitio)}</td><td>{len(exps)}</td><td>{len(exps) - 1}</td>"
                  f"<td>{libres:.1f} min ({100 * libres / fin:.1f} %)</td>"
                  f"<td>{(f'{sum(rebloqueos) / len(rebloqueos):.1f} min') if rebloqueos else '—'}</td><td>{avisos}</td></tr>")
    return f"""<section class=exp><h2>Costo impuesto a cada sitio pirata</h2>
<p>El objetivo no es solo cortar una transmisión sino que transmitir deje de convenir. Cada bloqueo rápido inutiliza el servidor
y obliga al pirata a contratar otro, cambiar la IP y volver a promocionar el enlace; mientras tanto pierde audiencia.
La plataforma lo hace de tres formas:</p>
<ol><li><b>Bloqueo en minutos:</b> la detección llega con la evidencia armada y el juez firma desde el celular.</li>
<li><b>Prioridad al reincidente:</b> si el mismo sitio aparece en otro servidor, el expediente se marca y se muestra primero al juez.</li>
<li><b>Avisos a quienes le dan servicio:</b> con la firma se emite un pedido al hosting dueño de la IP (suspender al cliente,
preservar datos de pago y acceso, no darle otra IP) y a cada red social donde se promocionó el enlace (retirar la publicación).</li></ol>
<table><thead><tr><th>Sitio</th><th>Servidores bloqueados</th><th>Cambios de servidor forzados</th>
<th>Minutos al aire sin ningún bloqueo (del partido)</th><th>Re-bloqueo tras cambio de servidor</th><th>Avisos emitidos</th></tr></thead>{filas}</table>
<p class=chico>«Minutos al aire sin ningún bloqueo» suma, por cada servidor, el tiempo entre la primera detección y el primer
proveedor que aplicó el bloqueo. Lo que el sitio transmitió antes de ser detectado no se puede medir.</p></section>"""


def tramite_html(e: dict, t: dict) -> str:
    d = t.get("decision")
    asign = "".join(f"<tr><td>{fmin(a['minuto'])}</td><td>{h(PLAT['jueces'].get(a['juez_id'] or '', {}).get('nombre', a['juez_id'] or '—'))}</td>"
                    f"<td>{h(a['motivo'])}</td></tr>" for a in t["asignaciones"])
    if d:
        dec = f"""<table class=kv>{fila('Decisión', f"<b class={'ok' if d['decision'] == 'aprobado' else 'alerta'}>{h(d['decision'].upper())}</b>")}
{fila('Juez', h(d['juez']) + f" <span class=mono>({h(d['juez_id'])})</span>")}{fila('Juzgado', h(d['juzgado']))}
{fila('Minuto / hora UTC', f"{fmin(d['minuto'])} · {h(d['utc'])}")}{fila('Fundamento', h(d['motivo'] or '—'))}
{fila('Texto firmado', f"<span class=mono>{h(d['texto_firmado'])}</span>")}{fila('Firma (HMAC-SHA256)', f"<span class=mono>{h(d['firma'])}</span>")}
{fila('Demora detección → firma', f"{float(d['minuto']) - float(t['abierto_min']):.2f} min")}</table>
<p class=chico>La firma cubre el hash del expediente: si el expediente cambia después de firmado, la firma deja de coincidir.</p>"""
    else:
        dec = "<p class=alerta>Sin decisión registrada.</p>"
    filas = ""
    for env in t["envios"]:
        if not env["intentos"]:
            filas += f"<tr><td>{h(nombre_prov(env['proveedor']))}</td><td colspan=6>{h(env['nota'])}</td><td>{h(env['estado'])}</td></tr>"
        for i, it in enumerate(env["intentos"], start=1):
            filas += (f"<tr><td>{h(nombre_prov(env['proveedor']))}</td><td><b>{h((env['tipo'] or '').upper())}</b> <span class=mono>{h(env['objetivo'])}</span></td>"
                      f"<td class='mono nw'>{h(it['orden_id'])}</td><td>{i}</td><td>{fmin(it['enviado_min'])}</td><td>{fmin(it.get('aplicada_min'))}</td>"
                      f"<td>{fmin(it.get('finalizada_min'))}</td><td class={'ok' if it['estado'] in ('aplicada', 'vencida') else 'alerta' if it['estado'] in ('fallida', 'rechazada') else ''}>"
                      f"{h(it['estado'])}{('<br><span class=chico>' + h(it['motivo']) + '</span>') if it.get('motivo') else ''}</td></tr>")
    notas = sorted({env["nota"] for env in t["envios"] if env.get("nota") and env["nota"] != "tipo pedido"})
    vencidas = [it for env in t["envios"] for it in env["intentos"] if it["estado"] == "vencida"]
    activas = [it for env in t["envios"] for it in env["intentos"] if it["estado"] in ("recibida", "aplicada")]
    return f"""<h3>7. Notificación al juez de turno y decisión firmada</h3>
<table><thead><tr><th>Minuto</th><th>Asignado a</th><th>Motivo</th></tr></thead>{asign}</table>{dec}
<h3>8. Envío a cada proveedor, reintentos y confirmación</h3>
<table><thead><tr><th>Proveedor</th><th>Bloqueo</th><th>Orden</th><th>Intento</th><th>Enviada</th><th>Aplicada</th><th>Fin</th><th>Estado</th></tr></thead>{filas}</table>
{''.join(f'<p class=chico>Nota: {h(n)}.</p>' for n in notas)}
<h3>9. Vencimiento automático</h3>
<p>{len(vencidas)} orden(es) vencida(s) automáticamente en el minuto {h(str(e['pedido']['vence_min']))}.
{'<span class=ok>Ninguna orden de este expediente quedó activa.</span>' if not activas else f'<span class=alerta>{len(activas)} orden(es) seguían activas al exportar.</span>'}</p>
{costo_html(e, t)}"""


NUCLEO = [
    ("Expediente con marca de agua verificada, servidor, hashes y riesgo colateral.", "Secciones 1 a 6 de cada expediente (punto 1)."),
    ("Notificación al juez de turno y decisión firmada.", "Sección 7 de cada expediente: a quién se notificó, decisión, texto firmado y firma."),
    ("Ingreso del juez con usuario y contraseña; cada juez ve y firma solo lo suyo mientras está de turno.", "Anexo A: logins, intentos fallidos y firmas rechazadas fuera de turno."),
    ("Al cambio de turno, lo pendiente pasa al juez entrante y el saliente ya no puede firmar.", "Anexo A y Anexo F.1 (prueba con un expediente pendiente al cambio de turno)."),
    ("Envío a cada proveedor en el tipo que acepta, con reintento si falla, y seguimiento de la confirmación.", "Sección 8 de cada expediente: orden, intentos, minuto de aplicación."),
    ("Vencimiento automático de los bloqueos por IP.", "Sección 9 de cada expediente y Anexo D (verificación post-partido)."),
    ("Auditoría de cada paso.", "Anexo D: registro encadenado con hashes y su verificación."),
    ("Extra: reclamos, levantamiento firmado y reemplazo por un bloqueo más preciso.", "Anexo B y Anexo F.2 (reclamo resuelto)."),
    ("Extra: registro público de transparencia.", "Anexo C (copia de la página pública /publico)."),
    ("Extra: dónde se promocionó el enlace.", "Sección 5 de cada expediente."),
    ("Extra: interfaz judicial cuidada, para celular y con notificaciones.", "Anexo A (descripción de la interfaz)."),
    ("Propio: subirle el costo al pirata (prioridad al reincidente, avisos al hosting y a las redes).", "«Costo impuesto a cada sitio pirata» y sección 10 de cada expediente."),
]


def circuito_resumen() -> str:
    filas = "".join(f"<tr><td>{n}</td><td>{h(a)}</td><td>{h(b)}</td></tr>" for n, (a, b) in enumerate(NUCLEO, start=1))
    ts = PLAT["tramites"]
    demoras = [float(t["decision"]["minuto"]) - float(t["abierto_min"]) for t in ts if t.get("decision")]
    primeras = []
    for t in ts:
        ap = [float(it["aplicada_min"]) for env in t["envios"] for it in env["intentos"] if it.get("aplicada_min") is not None]
        if ap:
            primeras.append(min(ap) - float(t["abierto_min"]))
    intentos = [it for t in ts for env in t["envios"] for it in env["intentos"]]
    return f"""<section class=exp><h2>Circuito completo: núcleo obligatorio y extras</h2>
<p>Además del expediente (punto 1), este informe documenta lo que pasó con cada expediente en la plataforma durante el partido:
juez de turno, firma, envío a proveedores, confirmación, vencimiento y auditoría.</p>
<table class=kv>{fila('Expedientes con decisión firmada', f"{len(demoras)} de {len(ts)}")}
{fila('Demora media detección → firma', f"{sum(demoras) / len(demoras):.2f} min" if demoras else '—')}
{fila('Demora media detección → primer bloqueo confirmado', f"{sum(primeras) / len(primeras):.2f} min" if primeras else '—')}
{fila('Órdenes enviadas (incluye reintentos)', str(len(intentos)))}
{fila('Reintentos por falla del proveedor', str(sum(1 for t in ts for env in t['envios'] for it in env['intentos'][1:])))}
{fila('Órdenes vencidas automáticamente', str(sum(1 for it in intentos if it['estado'] == 'vencida')))}
{fila('Reclamos recibidos', str(len(PLAT['reclamos'])) + (' (ver Anexo F.2 para un reclamo provocado y resuelto)' if not PLAT['reclamos'] else ''))}
{fila('Entradas de auditoría', str(PLAT['auditoria']['entradas']))}</table>
<table><thead><tr><th>#</th><th>Requisito</th><th>Dónde se documenta</th></tr></thead>{filas}</table></section>"""


def anexos(auditoria: list, verif_audit: str, evaluacion: str) -> str:
    ev = lambda nombre: [a for a in auditoria if a["evento"] == nombre]
    jn = lambda j: PLAT["jueces"].get(j or "", {}).get("nombre", j or "—")
    acc = "".join(f"<tr><td>{fmin(a['minuto'])}</td><td>{h(a['evento'])}</td><td>{h(jn(a['actor']) if a['actor'] in PLAT['jueces'] else a['actor'])}</td>"
                  f"<td>{h(a['datos'].get('motivo') or a['datos'].get('expediente_id') or a['datos'].get('ref') or '')}</td></tr>"
                  for a in auditoria if a["evento"] in ("login", "login_fallido", "login_bloqueado", "logout", "firma_rechazada"))
    turnos = "".join(f"<tr><td>{fmin(a['minuto'])}</td><td>{h(a['datos']['tipo'])} {h(a['datos']['ref'])}</td><td>{h(jn(a['datos']['juez_saliente']))}</td>"
                     f"<td>{h(jn(a['datos']['juez_entrante']))}</td></tr>" for a in ev("pendiente_reasignado"))
    vig = "; ".join(f"min {fmin(a['minuto'])}: {', '.join(jn(j) for j in a['datos']['jueces_de_turno'])}" for a in ev("turno_vigente"))
    a_html = f"""<section class=exp><h2>Anexo A. Ingreso de jueces, turnos e interfaz judicial</h2>
<p>Cada juez entra a la plataforma con su usuario y contraseña (contraseñas guardadas con PBKDF2-SHA256 y sal; 5 intentos fallidos bloquean el usuario 1 minuto).
La sesión es una cookie HttpOnly. La plataforma firma con la clave del juez <b>solo</b> cuando ese juez, con la sesión iniciada y estando de turno, aprueba.
Cada juez ve únicamente los pendientes asignados a él y sus propias decisiones.</p>
<p><b>Turnos vigentes durante el partido:</b> {h(vig)}</p>
<h3>Reasignaciones por cambio de turno</h3>
<table><thead><tr><th>Minuto</th><th>Pendiente</th><th>Juez saliente</th><th>Juez entrante</th></tr></thead>{turnos or '<tr><td colspan=4>No había pendientes al cambio de turno.</td></tr>'}</table>
<h3>Ingresos e intentos de firma rechazados</h3>
<table><thead><tr><th>Minuto</th><th>Evento</th><th>Usuario</th><th>Detalle</th></tr></thead>{acc}</table>
<h3>Interfaz judicial</h3>
<p>Página web adaptada a celular: el expediente se muestra con las mismas 6 secciones del punto 1 y botones grandes de «Aprobar y firmar» o «Rechazar».
Cuando llega un expediente, un reenvío o un reclamo, avisa con una notificación del navegador, un sonido, vibración y el contador en el título de la pestaña.
Muestra si el juez está de turno y el estado de cada orden en cada proveedor.</p></section>"""
    recl = ""
    for r in PLAT["reclamos"]:
        v = r["verificacion"]
        recl += (f"<tr><td>{h(r['id'])}</td><td>{fmin(r['minuto'])}</td><td class=mono>{h(r['dominio'])}</td><td>{h(r['mensaje'])}</td>"
                 f"<td>{'válido' if v['valido'] else 'no válido'}: {h(v['motivo'])}</td><td>{h(r['estado'])} {h(jn(r.get('decidido_por')) if r.get('decidido_por') else '')}"
                 f"{('<br><span class=chico>levantadas: ' + ', '.join(r.get('levantadas', [])) + '; reemplazos: ' + ', '.join(r.get('reemplazos', [])) + '</span>') if r.get('levantadas') or r.get('reemplazos') else ''}</td></tr>")
    b_html = f"""<section class=exp><h2>Anexo B. Reclamos de sitios afectados (extra)</h2>
<p>Cada reclamo se verifica contra el DNS pasivo: es válido si el dominio comparte la IP de una orden nuestra y no pertenece a un sitio pirata.
El juez de turno decide; si acepta, la plataforma levanta las órdenes con su firma (<span class=mono>LEVANTAR|orden_id|juez_id</span>) y las reemplaza por un bloqueo por dominio del servidor pirata.</p>
<table><thead><tr><th>Id</th><th>Min</th><th>Dominio</th><th>Mensaje</th><th>Verificación</th><th>Resolución</th></tr></thead>{recl or '<tr><td colspan=6>No hubo reclamos: ninguna orden afectó a sitios legítimos, porque las IP compartidas se pidieron por dominio desde el principio.</td></tr>'}</table></section>"""
    filas = "".join(f"<tr><td>{h(o['expediente_id'])}</td><td>{h(o['sitio'])}</td><td>{h(o['proveedor'])}</td><td>{h(o['tipo'])}</td><td class=mono>{h(o['objetivo'])}</td>"
                    f"<td>{h(o['juez'])}</td><td>{fmin(o['enviada_min'])}</td><td>{fmin(o['aplicada_min'])}</td><td>{fmin(o['finalizada_min'])}</td><td>{h(o['estado'])}</td></tr>"
                    for o in PLAT["transparencia"])
    c_html = f"""<section class=exp><h2>Anexo C. Registro público de transparencia (extra)</h2>
<p>Publicado sin login en <span class=mono>/publico</span>: qué se bloqueó, quién lo ordenó, en qué proveedor y hasta cuándo.</p>
<table class=resumen><thead><tr><th>Expediente</th><th>Sitio</th><th>Prov.</th><th>Tipo</th><th>Objetivo</th><th>Juez</th><th>Enviada</th><th>Aplicada</th><th>Fin</th><th>Estado</th></tr></thead>{filas}</table></section>"""
    cuenta: dict = {}
    for a in auditoria:
        cuenta[a["evento"]] = cuenta.get(a["evento"], 0) + 1
    tabla = "".join(f"<tr><td>{h(k)}</td><td>{v}</td></tr>" for k, v in sorted(cuenta.items()))
    claves = ("expediente_abierto", "juez_notificado", "decision_firmada", "pendiente_reasignado", "reintento", "reenvio_firmado",
              "orden_fallida", "reclamo_decidido", "orden_levantada", "vencimiento_verificado", "turno_vigente")
    extracto = "".join(f"<tr><td>{a['n']}</td><td>{fmin(a['minuto'])}</td><td>{h(a['evento'])}</td><td>{h(a['actor'])}</td>"
                       f"<td class=mono>{h(a['hash'][:16])}…</td></tr>" for a in auditoria if a["evento"] in claves)
    d_html = f"""<section class=exp><h2>Anexo D. Registro de auditoría</h2>
<p>Archivo <span class=mono>entrega/auditoria.jsonl</span>: una línea por paso (detección, expediente, notificación, login, firma, envío, respuesta del proveedor, reintento,
confirmación, vencimiento, reclamo). Cada entrada incluye el hash SHA-256 de la anterior, así que borrar o modificar una línea rompe la cadena.</p>
<p><b>Verificación</b> (<span class=mono>python plataforma/servidor.py --verificar-auditoria entrega/auditoria.jsonl</span>): <span class=ok>{h(verif_audit)}</span></p>
<table><thead><tr><th>Evento</th><th>Cantidad</th></tr></thead>{tabla}</table>
<h3>Extracto: pasos de decisión, turno, reintentos y vencimiento</h3>
<table><thead><tr><th>#</th><th>Min</th><th>Evento</th><th>Actor</th><th>Hash</th></tr></thead>{extracto}</table></section>"""
    e_html = (f"""<section class=exp><h2>Anexo E. Resultado de evaluacion/verificar.py</h2>
<p>Salida del script de evaluación del desafío sobre el registro del simulador de esta corrida.</p><pre class=mono style="white-space:pre-wrap;font-size:7.4pt">{h(evaluacion)}</pre></section>"""
              if evaluacion else "")
    return a_html + b_html + c_html + d_html + e_html


def anexo_pruebas(base: Path) -> str:
    """Corridas complementarias para mostrar casos que el partido principal no produjo."""
    partes = []
    turno = base / "pruebas" / "cambio_turno"
    if (turno / "plataforma.json").exists():
        pl = json.loads((turno / "plataforma.json").read_text(encoding="utf-8"))
        au = [json.loads(x) for x in (turno / "auditoria.jsonl").read_text(encoding="utf-8").splitlines()]
        jn = lambda j: pl["jueces"].get(j or "", {}).get("nombre", j or "—")
        filas = "".join(f"<tr><td>{a['n']}</td><td>{fmin(a['minuto'])}</td><td>{h(a['evento'])}</td><td>{h(jn(a['actor']) if a['actor'] in pl['jueces'] else a['actor'])}</td>"
                        f"<td>{h(json.dumps({k: v for k, v in a['datos'].items() if k in ('expediente_id', 'ref', 'juez_saliente', 'juez_entrante', 'juez_id', 'motivo', 'decision', 'jueces_de_turno')}, ensure_ascii=False))}</td></tr>"
                        for a in au if a["evento"] in ("turno_vigente", "expediente_abierto", "juez_notificado", "pendiente_reasignado", "firma_rechazada", "decision_firmada"))
        partes.append(f"""<h3>F.1 Cambio de turno con un expediente pendiente</h3>
<p>Partido de práctica iniciado en el minuto 36 (<span class=mono>--inicio-min 36</span>). La Dra. Laura Ficticia no atiende los expedientes que se le notifican (los ya activos al arrancar y el del minuto 37,5).
En el minuto 50 los pendientes pasan al Dr. Martín Ejemplo. La jueza saliente intenta firmar y la plataforma lo rechaza. El juez entrante firma.</p>
<table><thead><tr><th>#</th><th>Min</th><th>Evento</th><th>Actor</th><th>Datos</th></tr></thead>{filas}</table>
<p class=chico>Registro completo: entrega/pruebas/cambio_turno/auditoria.jsonl.</p>""")
    rec = base / "pruebas" / "reclamo"
    if (rec / "plataforma.json").exists():
        pl = json.loads((rec / "plataforma.json").read_text(encoding="utf-8"))
        au = [json.loads(x) for x in (rec / "auditoria.jsonl").read_text(encoding="utf-8").splitlines()]
        filas = "".join(f"<tr><td>{a['n']}</td><td>{fmin(a['minuto'])}</td><td>{h(a['evento'])}</td><td>{h(a['actor'])}</td>"
                        f"<td>{h(json.dumps({k: v for k, v in a['datos'].items() if k in ('id', 'orden_id', 'proveedor', 'tipo', 'objetivo', 'valido', 'aceptado', 'motivo', 'estado')}, ensure_ascii=False))}</td></tr>"
                        for a in au if a["evento"] in ("modo_prueba_reclamos", "reclamo_recibido", "reclamo_verificado", "reclamo_decidido", "orden_levantada", "reenvio_pendiente", "reenvio_firmado")
                        or (a["evento"] == "orden_enviada" and "golazo" in json.dumps(a["datos"])))
        resumen = "".join(f"<li>{h(r['id'])} · {h(r['dominio'])}: {h(r['estado'])}. Levantadas: {h(', '.join(r.get('levantadas', [])) or '—')}. "
                          f"Reemplazos por dominio: {h(', '.join(r.get('reemplazos', [])) or '—')}.</li>" for r in pl["reclamos"])
        partes.append(f"""<h3>F.2 Reclamo resuelto con levantamiento firmado</h3>
<p>Como el partido principal no generó reclamos, se forzó un error a propósito (<span class=mono>--forzar-bloqueo-ip live.golazo-libre.test</span>):
se bloqueó por IP la CDN 198.51.100.20, que comparte la IP con sitios legítimos. Llegaron los reclamos, la plataforma los verificó contra el DNS pasivo
y el juez de turno levantó las órdenes con su firma y las reemplazó por un bloqueo por dominio de <span class=mono>live.golazo-libre.test</span>.</p>
<ul>{resumen or '<li>Sin reclamos.</li>'}</ul>
<table class=resumen><thead><tr><th>#</th><th>Min</th><th>Evento</th><th>Actor</th><th>Datos</th></tr></thead>{filas}</table>
<p class=chico>Registro completo: entrega/pruebas/reclamo/auditoria.jsonl.</p>""")
    if not partes:
        return ""
    return "<section class=exp><h2>Anexo F. Pruebas complementarias</h2>" + "".join(partes) + "</section>"


CONSIGNA = [
    ("Prueba de que es la señal oficial: la marca de agua extraída coincide con el partido y no corresponde a un licenciatario autorizado en su propio dominio.",
     "Sección 1 de cada expediente. Las detecciones del licenciatario en sus dominios y las de otra señal figuran como descartadas en el punto 3 del resumen."),
    ("El servidor que entrega el video (host e IP) y su proveedor (ASN). Bloquear la página que muestra el reproductor no corta el video.",
     "Sección 2: URL del stream, host, IP, ASN y organización. El pedido apunta al servidor del video, nunca a la página."),
    ("Riesgo colateral: qué otros sitios comparten esa IP. Si es una CDN o un hosting compartido, la plataforma recomienda bloquear el dominio en vez de la IP.",
     "Sección 3: dominios vistos en la IP (DNS pasivo), separados entre el propio sitio y terceros, con la recomendación IP o dominio."),
    ("Hashes de la captura y sellos de tiempo, para que cualquier alteración posterior se detecte.",
     "Sección 4: SHA-256 de cada captura y de la detección, hash encadenado, hash del expediente y verificación automática (resumen, punto 4)."),
    ("Dónde se promocionó el enlace (X, Discord, Telegram). (Extra.)", "Sección 5: red, URL y minuto de cada promoción."),
    ("Vencimiento propuesto.", "Sección 6: minuto y hora de vencimiento, con fundamento, junto al pedido de bloqueo para el juez."),
]


def cumplimiento() -> str:
    filas = "".join(f"<tr><td>{n}</td><td>{h(req)}</td><td>{h(donde)}</td><td class=ok>Cumplido</td></tr>"
                    for n, (req, donde) in enumerate(CONSIGNA, start=1))
    return f"""<section class=exp><h2>Qué pide el punto 1 y dónde se cumple</h2>
<p><b>Consigna:</b> «Armar el expediente de cada stream pirata, con evidencia verificable».</p>
<table><thead><tr><th style="width:4%">#</th><th style="width:40%">Requisito (texto de la consigna)</th><th>Dónde está en este informe</th><th style="width:10%">Estado</th></tr></thead>{filas}</table></section>"""


def capitulo(n: int, sitio: str, exps: list) -> str:
    filas = "".join(
        f"<tr><td>{h(e['expediente_id'])}</td><td>{e['fase_del_sitio']}</td><td class=mono>{h(e['servidor']['host_stream'])}</td>"
        f"<td class='mono nw'>{h(e['servidor']['ip'])}</td><td>AS{e['servidor']['asn']} {h(e['servidor']['organizacion_asn'] or '')}</td>"
        f"<td>{e['primera_deteccion_min']:g}–{e['ultima_deteccion_min']:g}</td><td><b>{h(e['pedido']['tipo'].upper())}</b> "
        f"<span class=mono>{h(e['pedido']['objetivo'])}</span></td></tr>" for e in exps)
    cambios = len(exps) - 1
    texto = (f"El sitio cambió de servidor {cambios} {'vez' if cambios == 1 else 'veces'} durante el partido; cada servidor tiene su propio expediente, vinculado al anterior."
             if cambios else "El sitio usó un único servidor durante todo el partido.")
    return f"""<section class=exp><h2>Stream pirata {n}: {h(sitio)}</h2>
<table class=kv><tr><td>Página del reproductor</td><td class=mono>{h(exps[0]['pagina'])}</td></tr>
<tr><td>Marca de agua</td><td class=mono>{h(exps[0]['verificacion_marca'].get('marca', ''))}</td></tr>
<tr><td>Detecciones</td><td>{sum(len(e['evidencia']) for e in exps)}</td></tr></table>
<p>{texto}</p>
<table><thead><tr><th>Expediente</th><th>Fase</th><th>Host</th><th>IP</th><th>ASN</th><th>Detectado (min)</th><th>Bloqueo pedido</th></tr></thead>{filas}</table></section>"""


def anexo_verificacion() -> str:
    return """<section class=exp><h2>Anexo G — Cómo verifica el juez la evidencia</h2>
<p>El juez o un perito pueden comprobar, sin confiar en la plataforma, que la evidencia es la misma que se capturó:</p>
<ol>
<li><b>Capturas:</b> en la carpeta <span class=mono>entrega/evidencia</span> ejecutar <span class=mono>sha256sum -c SHA256SUMS</span>. Cada archivo debe dar «OK» y su hash es el de la sección 4 del expediente.</li>
<li><b>Expedientes y sellos:</b> <span class=mono>python plataforma/expedientes.py --verificar entrega/expedientes.json</span> recalcula los hashes encadenados y el hash de cada expediente.</li>
<li><b>Auditoría:</b> <span class=mono>python plataforma/servidor.py --verificar-auditoria entrega/auditoria.jsonl</span> comprueba que nadie borró ni modificó pasos (Anexo D).</li>
<li><b>Firma:</b> la firma de la sección 7 es HMAC-SHA256 del texto firmado con la clave del juez; se recalcula con la misma clave.</li>
<li><b>Marca de agua:</b> la marca está en la detección original guardada en el expediente y se compara con los prefijos válidos del partido (sección 1).</li>
</ol></section>"""


def generar(entrada: Path, salida: Path) -> None:
    d = json.loads(entrada.read_text(encoding="utf-8"))
    import contextlib, io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        codigo = verificar_archivo(entrada)
    verificacion = buf.getvalue().strip() if codigo == 0 else "FALLÓ: " + buf.getvalue().strip()
    PARTIDO.update(d["partido"])
    CAPTURAS.update(exportar_capturas(d["expedientes"], entrada.parent))
    sitios: dict = {}
    for e in sorted(d["expedientes"], key=lambda x: x["primera_deteccion_min"]):
        sitios.setdefault(e["sitio"], []).append(e)
    rp = entrada.parent / "plataforma.json"
    tramites = {}
    if rp.exists():
        PLAT.update(json.loads(rp.read_text(encoding="utf-8")))
        tramites = {t["expediente_id"]: t for t in PLAT["tramites"]}
    cuerpo = portada(d, verificacion) + cumplimiento() + (circuito_resumen() + costo_resumen(d) if PLAT else "")
    for n, (sitio, exps) in enumerate(sitios.items(), start=1):
        cuerpo += capitulo(n, sitio, exps)
        cuerpo += "".join(expediente(e, f"Stream pirata {n}: {sitio} · servidor {i} de {len(exps)}", tramites.get(e["expediente_id"]))
                          for i, e in enumerate(exps, start=1))
    if PLAT:
        ra = entrada.parent / "auditoria.jsonl"
        auditoria = [json.loads(x) for x in ra.read_text(encoding="utf-8").splitlines()]
        from servidor import verificar_auditoria
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            verificar_auditoria(ra)
        re_ = entrada.parent / "evaluacion.txt"
        cuerpo += anexos(auditoria, buf.getvalue().strip(), re_.read_text(encoding="utf-8") if re_.exists() else "")
        cuerpo += anexo_pruebas(entrada.parent)
    cuerpo += anexo_verificacion()
    documento = f"<!doctype html><html lang=es><head><meta charset=utf-8><title>Informe de expedientes</title><style>{CSS}</style></head><body>{cuerpo}</body></html>"
    navegador = next((shutil.which(n) for n in ("google-chrome", "chromium", "chromium-browser", "chrome") if shutil.which(n)), None)
    if not navegador:
        sys.exit("No se encontró Chrome/Chromium para generar el PDF.")
    with tempfile.TemporaryDirectory() as tmp:
        fuente = Path(tmp) / "informe.html"
        fuente.write_text(documento, encoding="utf-8")
        subprocess.run([navegador, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={salida.resolve()}", fuente.as_uri()],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    print(f"PDF generado: {salida}")


def main() -> None:
    p = argparse.ArgumentParser(description="Informe PDF de expedientes")
    p.add_argument("--entrada", type=Path, default=REPO_DIR / "entrega" / "expedientes.json")
    p.add_argument("--salida", type=Path, default=REPO_DIR / "entrega" / "informe_expedientes.pdf")
    args = p.parse_args()
    generar(args.entrada, args.salida)


if __name__ == "__main__":
    main()
