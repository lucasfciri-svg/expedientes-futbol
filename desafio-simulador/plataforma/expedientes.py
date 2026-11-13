#!/usr/bin/env python3
"""Arma el expediente de cada stream pirata a partir de la API del simulador (stdlib, Python 3.9+).

Por cada detección: verifica la marca de agua contra GET /partido (señal oficial o licenciatario
fuera de sus dominios), identifica el servidor (host, IP, ASN), mide el riesgo colateral con
GET /dns-pasivo, sella la evidencia con hashes SHA-256 encadenados y propone tipo de bloqueo y
vencimiento. Agrupa las detecciones en un expediente por servidor (host + IP), de modo que un
cambio de servidor abre un expediente nuevo vinculado al anterior.

Uso:
  python plataforma/expedientes.py --servidor http://localhost:8080          # sigue el partido en vivo
  python plataforma/expedientes.py --servidor http://localhost:8080 --una-vez
  python plataforma/expedientes.py --verificar entrega/expedientes.json      # detecta alteraciones
"""
import argparse
import base64
import hashlib
import html
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

REPO_DIR = Path(__file__).resolve().parent.parent
ETIQUETAS = {"senal_oficial": "señal oficial", "senal_licenciatario_redistribuida": "señal de licenciatario redistribuida",
             "licenciatario_autorizado": "licenciatario autorizado", "otra_senal": "otra señal", "sin_marca": "sin marca de agua"}
PISTAS_INFRA_COMPARTIDA = ("cdn", "compartid", "shared", "cloud")


# --- utilidades ------------------------------------------------------------------------

def pedir(base: str, ruta: str) -> Any:
    try:
        with urllib.request.urlopen(base + ruta, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as err:
        return {"_http": err.code, **json.loads(err.read() or b"{}")}


def sha256(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def canonico(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ahora_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def dominio_base(host: str) -> str:
    """Dominio registrable aproximado (últimas dos etiquetas): s1.pelotaya.test -> pelotaya.test."""
    partes = host.lower().strip(".").split(".")
    return ".".join(partes[-2:])


def host_en(host: str, dominios: List[str]) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in (x.lower() for x in dominios))


def prefijo_coincide(marca: str, prefijo: str) -> bool:
    return marca == prefijo or marca.startswith(prefijo + "-")


# --- verificaciones ----------------------------------------------------------------------

def verificar_marca(det: dict, partido: dict) -> dict:
    marca = (det.get("marca_de_agua_extraida") or "").strip()
    host = det.get("host_stream") or ""
    pagina = urlparse(det.get("pagina") or "").hostname or ""
    if not marca:
        return {"resultado": "sin_marca", "es_senal_del_partido": False,
                "detalle": "No se extrajo marca de agua: no se puede probar que sea la señal del partido."}
    for lic in partido.get("licenciatarios", []):
        if prefijo_coincide(marca, lic["prefijo_marca"]):
            if host_en(host, lic["dominios_autorizados"]) and (not pagina or host_en(pagina, lic["dominios_autorizados"])):
                return {"resultado": "licenciatario_autorizado", "es_senal_del_partido": True, "marca": marca,
                        "licenciatario": lic["nombre"],
                        "detalle": f"Marca de {lic['nombre']} servida desde sus dominios autorizados "
                                   f"({', '.join(lic['dominios_autorizados'])}). Retransmisión legal."}
            return {"resultado": "senal_licenciatario_redistribuida", "es_senal_del_partido": True, "marca": marca,
                    "licenciatario": lic["nombre"],
                    "detalle": f"Marca de {lic['nombre']} pero servida desde {host}, fuera de sus dominios "
                               f"autorizados: redistribución no autorizada de la señal."}
    for valida in partido.get("marcas_de_agua_validas", []):
        if prefijo_coincide(marca, valida["prefijo"]):
            return {"resultado": "senal_oficial", "es_senal_del_partido": True, "marca": marca,
                    "prefijo": valida["prefijo"],
                    "detalle": f"La marca {marca} coincide con el prefijo {valida['prefijo']} "
                               f"({valida['origen']}) y no corresponde a ningún licenciatario."}
    return {"resultado": "otra_senal", "es_senal_del_partido": False, "marca": marca,
            "detalle": f"La marca {marca} no coincide con ningún prefijo válido del partido: es otro contenido."}


def evaluar_colateral(base: str, det: dict, cache: Dict[str, dict]) -> dict:
    ip, host = det["ip_servidor"], det["host_stream"]
    if ip not in cache:
        cache[ip] = pedir(base, "/dns-pasivo?ip=" + quote(ip))
    dns = cache[ip]
    dominios = dns.get("dominios", []) if "_http" not in dns else []
    propio = dominio_base(host)
    terceros = sorted(d for d in dominios if dominio_base(d) != propio)
    del_mismo_sitio = sorted(d for d in dominios if dominio_base(d) == propio)
    organizacion = dns.get("organizacion") or ""
    pista_infra = any(p in organizacion.lower() for p in PISTAS_INFRA_COMPARTIDA)
    if "_http" in dns:
        tipo, motivo = "dominio", "Sin datos de DNS pasivo para la IP: no se puede descartar que sea compartida."
    elif terceros:
        tipo, motivo = "dominio", (f"La IP {ip} es compartida con {len(terceros)} sitio(s) de terceros. "
                                   f"Bloquearla los dejaría sin servicio: se pide bloqueo por dominio ({host}).")
    elif pista_infra:
        tipo, motivo = "dominio", (f"El ASN pertenece a «{organizacion}», infraestructura compartida: "
                                   f"se pide bloqueo por dominio ({host}).")
    else:
        tipo, motivo = "ip", (f"La IP {ip} solo aloja dominios del propio sitio ({', '.join(del_mismo_sitio) or host}): "
                              f"bloqueo por IP sin daño colateral conocido; corta también subdominios espejo.")
    return {"ip": ip, "asn": dns.get("asn", det.get("asn")), "organizacion_asn": organizacion or None,
            "dominios_en_la_ip": dominios, "dominios_del_mismo_sitio": del_mismo_sitio,
            "dominios_de_terceros": terceros, "ip_compartida": bool(terceros) or pista_infra or "_http" in dns,
            "bloqueo_recomendado": tipo, "objetivo": ip if tipo == "ip" else host, "motivo": motivo}


def sellar(det: dict, previo: str, recibida_utc: str, inicio: Optional[datetime]) -> dict:
    captura = det.get("captura") or {}
    contenido = base64.b64decode(captura.get("contenido_b64") or "")
    minuto_captura = captura.get("capturada_min", det["minuto"])
    item = {
        "deteccion_id": det["id"],
        "minuto_partido": det["minuto"],
        "captura_min": minuto_captura,
        "captura_hora": (inicio + timedelta(minutes=minuto_captura)).isoformat() if inicio else None,
        "recibida_por_plataforma_utc": recibida_utc,
        "captura_formato": captura.get("formato"),
        "captura_duracion_seg": captura.get("duracion_seg"),
        "captura_bytes": len(contenido),
        "sha256_captura": sha256(contenido),
        "sha256_deteccion": sha256(canonico(det)),
        "hash_previo": previo,
        "deteccion_original": det,
    }
    item["hash_encadenado"] = sha256(canonico({k: v for k, v in item.items() if k != "hash_encadenado"}))
    return item


# --- armado de expedientes -----------------------------------------------------------

class Armador:
    def __init__(self, base: str):
        self.base = base
        self.partido = pedir(base, "/partido")
        self.fin_min = int(self.partido.get("fin_min", 105))
        inicio_iso = self.partido.get("inicio_iso")
        self.inicio = datetime.fromisoformat(inicio_iso) if inicio_iso else None
        self.dns_cache: Dict[str, dict] = {}
        self.expedientes: Dict[str, dict] = {}   # clave host|ip -> expediente
        self.descartadas: List[dict] = []
        self.ultimo_hash = "0" * 64

    def procesar(self, det: dict) -> None:
        recibida = ahora_utc()
        marca = verificar_marca(det, self.partido)
        if marca["resultado"] in ("licenciatario_autorizado", "otra_senal", "sin_marca"):
            self.descartadas.append({"deteccion_id": det["id"], "minuto": det["minuto"], "pagina": det["pagina"],
                                     "host_stream": det["host_stream"], "ip_servidor": det["ip_servidor"],
                                     "marca": det.get("marca_de_agua_extraida"), "motivo": marca["resultado"],
                                     "detalle": marca["detalle"]})
            return
        clave = f"{det['host_stream']}|{det['ip_servidor']}"
        exp = self.expedientes.get(clave)
        if exp is None:
            exp = self._abrir(det, marca)
            self.expedientes[clave] = exp
        item = sellar(det, self.ultimo_hash, recibida, self.inicio)
        self.ultimo_hash = item["hash_encadenado"]
        exp["evidencia"].append(item)
        exp["ultima_deteccion_min"] = det["minuto"]
        vistos = {p["url"] for p in exp["promocion"]}
        exp["promocion"] += [p for p in det.get("promocion", []) if p["url"] not in vistos]
        exp["hash_expediente"] = hash_expediente(exp)

    def _abrir(self, det: dict, marca: dict) -> dict:
        numero = len(self.expedientes) + 1
        sitio = dominio_base(urlparse(det["pagina"]).hostname or det["host_stream"])
        anteriores = [e["expediente_id"] for e in self.expedientes.values() if e["sitio"] == sitio]
        colateral = evaluar_colateral(self.base, det, self.dns_cache)
        historial = pedir(self.base, "/dns-pasivo?dominio=" + quote(det["host_stream"]))
        return {
            "expediente_id": f"EXP-2026-{numero:06d}",
            "abierto_utc": ahora_utc(),
            "partido": self.partido.get("id") or self.partido.get("nombre"),
            "titular_derechos": self.partido.get("titular_derechos"),
            "sitio": sitio,
            "pagina": det["pagina"],
            "fase_del_sitio": len(anteriores) + 1,
            "expedientes_previos_del_sitio": anteriores,
            "cambio_de_servidor": bool(anteriores),
            "verificacion_marca": marca,
            "servidor": {"stream_url": det["stream_url"], "host_stream": det["host_stream"],
                         "ip": det["ip_servidor"], "asn": det.get("asn"),
                         "organizacion_asn": colateral["organizacion_asn"],
                         "ips_vistas_para_el_host": historial.get("ips", []) if "_http" not in historial else [],
                         "nota": "Se bloquea el servidor que entrega el video, no la página del reproductor."},
            "riesgo_colateral": colateral,
            "pedido": {"tipo": colateral["bloqueo_recomendado"], "objetivo": colateral["objetivo"],
                       "vence_min": self.fin_min,
                       "vence_hora": (self.inicio + timedelta(minutes=self.fin_min)).isoformat() if self.inicio else None,
                       "fundamento_vencimiento": "Vence al terminar el partido (minuto "
                                                 f"{self.fin_min}); los bloqueos por IP no deben quedar activos después."},
            "primera_deteccion_min": det["minuto"],
            "ultima_deteccion_min": det["minuto"],
            "promocion": [],
            "evidencia": [],
            "estado": "pendiente_de_juez",
        }


def hash_expediente(exp: dict) -> str:
    return sha256(canonico({k: v for k, v in exp.items() if k not in ("hash_expediente", "abierto_utc")}))


def verificar_archivo(ruta: Path) -> int:
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    items = sorted((i for e in datos["expedientes"] for i in e["evidencia"]), key=lambda i: i["minuto_partido"])
    errores = []
    previo = "0" * 64
    for it in items:
        det = it["deteccion_original"]
        contenido = base64.b64decode((det.get("captura") or {}).get("contenido_b64") or "")
        if sha256(contenido) != it["sha256_captura"]:
            errores.append(f"{it['deteccion_id']}: la captura no coincide con su hash")
        if sha256(canonico(det)) != it["sha256_deteccion"]:
            errores.append(f"{it['deteccion_id']}: la detección fue modificada")
        if it["hash_previo"] != previo:
            errores.append(f"{it['deteccion_id']}: la cadena de hashes está rota")
        if sha256(canonico({k: v for k, v in it.items() if k != "hash_encadenado"})) != it["hash_encadenado"]:
            errores.append(f"{it['deteccion_id']}: el sello encadenado no coincide")
        previo = it["hash_encadenado"]
    for e in datos["expedientes"]:
        if hash_expediente(e) != e["hash_expediente"]:
            errores.append(f"{e['expediente_id']}: el expediente fue alterado")
    if datos.get("hash_cadena_final") != previo:
        errores.append("El hash final de la cadena no coincide")
    print("\n".join(errores) if errores else f"OK: {len(datos['expedientes'])} expedientes y {len(items)} evidencias íntegras.")
    return 1 if errores else 0


# --- salida --------------------------------------------------------------------------

def exportar_capturas(expedientes: list, salida: Path) -> Dict[str, str]:
    """Guarda cada captura como archivo propio (entrega/evidencia/EXP/D-xxxx.ext) y un SHA256SUMS
    para que el juez pueda abrirla y comprobar el hash con cualquier herramienta (sha256sum -c)."""
    base, rutas, lineas = salida / "evidencia", {}, []
    for e in expedientes:
        for it in e["evidencia"]:
            cap = it["deteccion_original"].get("captura") or {}
            contenido = base64.b64decode(cap.get("contenido_b64") or "")
            if not contenido:
                continue
            ext = {"mpegts": "ts"}.get(cap.get("formato") or "", cap.get("formato") or "bin")
            rel = f"{e['expediente_id']}/{it['deteccion_id']}.{ext}"
            destino = base / rel
            destino.parent.mkdir(parents=True, exist_ok=True)
            if not destino.exists() or sha256(destino.read_bytes()) != it["sha256_captura"]:
                destino.write_bytes(contenido)
            rutas[it["deteccion_id"]] = "evidencia/" + rel
            lineas.append(f"{it['sha256_captura']}  {rel}")
    if lineas:
        (base / "SHA256SUMS").write_text("\n".join(lineas) + "\n", encoding="utf-8")
    return rutas


def exportar(arm: Armador, salida: Path) -> dict:
    salida.mkdir(parents=True, exist_ok=True)
    estado = pedir(arm.base, "/estado")
    expedientes = sorted(arm.expedientes.values(), key=lambda e: e["expediente_id"])
    datos = {"generado_utc": ahora_utc(), "simulador": arm.base, "minuto_partido": estado.get("minuto_actual"),
             "partido": arm.partido, "expedientes": expedientes, "detecciones_descartadas": arm.descartadas,
             "hash_cadena_final": arm.ultimo_hash}
    (salida / "expedientes.json").write_text(json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8")
    for e in expedientes:
        (salida / "expedientes").mkdir(exist_ok=True)
        (salida / "expedientes" / f"{e['expediente_id']}.json").write_text(
            json.dumps(e, ensure_ascii=False, indent=2), encoding="utf-8")
    exportar_capturas(expedientes, salida)
    (salida / "informe_expedientes.html").write_text(informe_html(datos), encoding="utf-8")
    return datos


def informe_html(d: dict) -> str:
    h = html.escape
    exps, desc, partido = d["expedientes"], d["detecciones_descartadas"], d["partido"]
    sitios = sorted({e["sitio"] for e in exps})
    filas = "".join(
        f"<tr><td><a href='#{h(e['expediente_id'])}'>{h(e['expediente_id'])}</a></td><td>{h(e['sitio'])}"
        f"{' <span class=tag>cambio de servidor</span>' if e['cambio_de_servidor'] else ''}</td>"
        f"<td><code>{h(e['servidor']['host_stream'])}</code></td><td><code>{h(e['servidor']['ip'])}</code></td>"
        f"<td>AS{e['servidor']['asn']}<br><small>{h(e['servidor']['organizacion_asn'] or '')}</small></td>"
        f"<td>{len(e['riesgo_colateral']['dominios_de_terceros'])}</td>"
        f"<td><b class='{e['pedido']['tipo']}'>{h(e['pedido']['tipo'])}</b><br><code>{h(e['pedido']['objetivo'])}</code></td>"
        f"<td>{e['primera_deteccion_min']:g}–{e['ultima_deteccion_min']:g}</td><td>{len(e['evidencia'])}</td>"
        f"<td>min {e['pedido']['vence_min']}</td></tr>" for e in exps)
    tarjetas = []
    for e in exps:
        rc, srv, vm = e["riesgo_colateral"], e["servidor"], e["verificacion_marca"]
        evid = "".join(
            f"<tr><td>{h(i['deteccion_id'])}</td><td>{i['captura_min']:g}</td><td>{h(i['captura_hora'] or '')}</td>"
            f"<td>{i['captura_bytes']} B {h(i['captura_formato'] or '')}</td><td><code>{i['sha256_captura']}</code></td>"
            f"<td><code>{i['hash_encadenado'][:16]}…</code></td></tr>" for i in e["evidencia"])
        promo = "".join(f"<li>{h(p['red'])} · <code>{h(p['url'])}</code> (min {p['minuto']:g})</li>" for p in e["promocion"]) or "<li>Sin datos</li>"
        terceros = ", ".join(h(x) for x in rc["dominios_de_terceros"]) or "ninguno"
        previos = ", ".join(f"<a href='#{h(x)}'>{h(x)}</a>" for x in e["expedientes_previos_del_sitio"])
        tarjetas.append(f"""
<section class=card id='{h(e['expediente_id'])}'>
<h3>{h(e['expediente_id'])} · {h(e['sitio'])} <small>fase {e['fase_del_sitio']}{' (sigue a ' + previos + ')' if previos else ''}</small></h3>
<div class=grid>
<div><h4>1. Señal oficial</h4><p class=ok>✔ {h(ETIQUETAS.get(vm['resultado'], vm['resultado']))}</p><p>{h(vm['detalle'])}</p></div>
<div><h4>2. Servidor del video</h4><p>Página: <code>{h(e['pagina'])}</code><br>Stream: <code>{h(srv['stream_url'])}</code><br>
Host <code>{h(srv['host_stream'])}</code> · IP <code>{h(srv['ip'])}</code> · AS{srv['asn']} {h(srv['organizacion_asn'] or '')}</p></div>
<div><h4>3. Riesgo colateral</h4><p>Dominios en la IP: {len(rc['dominios_en_la_ip'])} · de terceros: <b>{len(rc['dominios_de_terceros'])}</b></p>
<p><small>{terceros}</small></p><p>{h(rc['motivo'])}</p></div>
<div><h4>Pedido al juez</h4><p>Bloqueo por <b class='{e['pedido']['tipo']}'>{h(e['pedido']['tipo'])}</b> a <code>{h(e['pedido']['objetivo'])}</code><br>
Vence: minuto {e['pedido']['vence_min']} ({h(e['pedido']['vence_hora'] or '')})</p>
<h4>Promoción del enlace</h4><ul>{promo}</ul></div>
</div>
<h4>4. Evidencia sellada (SHA-256, cadena de hashes)</h4>
<table><tr><th>Detección</th><th>Min</th><th>Hora de captura</th><th>Captura</th><th>SHA-256 captura</th><th>Sello encadenado</th></tr>{evid}</table>
<p><small>Hash del expediente: <code>{e['hash_expediente']}</code></small></p>
</section>""")
    filas_desc = "".join(
        f"<tr><td>{h(x['deteccion_id'])}</td><td>{x['minuto']:g}</td><td><code>{h(x['host_stream'])}</code></td>"
        f"<td><code>{h(x['ip_servidor'])}</code></td><td><code>{h(str(x['marca']))}</code></td>"
        f"<td>{h(ETIQUETAS.get(x['motivo'], x['motivo']))}</td><td>{h(x['detalle'])}</td></tr>" for x in desc)
    return f"""<!doctype html><html lang=es><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Informe de expedientes — {h(partido.get('nombre', ''))}</title><style>
body{{font-family:system-ui,sans-serif;margin:0;background:#f4f6f8;color:#1b2430}}main{{max-width:1200px;margin:auto;padding:24px}}
h1{{margin:0 0 4px}}.sub{{color:#5a6573}}.kpis{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.kpi{{background:#fff;border-radius:10px;padding:12px 18px;box-shadow:0 1px 3px #0002}}.kpi b{{font-size:26px;display:block}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin:8px 0}}th,td{{border-bottom:1px solid #e3e7eb;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#eef1f4}}code{{font-size:12px;word-break:break-all}}.card{{background:#fff;border-radius:10px;padding:16px 20px;margin:18px 0;box-shadow:0 1px 3px #0002}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}}h4{{margin:8px 0 4px;color:#33475b}}
.ok{{color:#13795b;font-weight:600}}.ip{{color:#b3261e}}.dominio{{color:#1a5fb4}}.tag{{background:#fff3cd;border-radius:6px;padding:1px 6px;font-size:11px}}
.aviso{{background:#fff3cd;padding:8px 12px;border-radius:8px;font-size:13px}}</style></head><body><main>
<h1>Informe de expedientes de streams piratas</h1>
<div class=sub>{h(partido.get('nombre', ''))} · Titular: {h(partido.get('titular_derechos', ''))} · Generado {h(d['generado_utc'])} (minuto {d['minuto_partido']})</div>
<p class=aviso>Datos ficticios del simulador del Desafío Fútbol (Hackathon Argentina Space 2026). No se bloquea nada real.</p>
<div class=kpis><div class=kpi><b>{len(sitios)}</b>sitios piratas</div><div class=kpi><b>{len(exps)}</b>expedientes (servidores)</div>
<div class=kpi><b>{sum(e['cambio_de_servidor'] for e in exps)}</b>cambios de servidor</div>
<div class=kpi><b>{sum(e['pedido']['tipo'] == 'ip' for e in exps)} / {sum(e['pedido']['tipo'] == 'dominio' for e in exps)}</b>pedidos por IP / dominio</div>
<div class=kpi><b>{len(desc)}</b>detecciones descartadas</div></div>
<h2>Resumen</h2><table><tr><th>Expediente</th><th>Sitio</th><th>Host del stream</th><th>IP</th><th>ASN</th><th>Sitios de terceros en la IP</th>
<th>Pedido</th><th>Detectado (min)</th><th>Evidencias</th><th>Vence</th></tr>{filas}</table>
<h2>Detecciones descartadas (no se pide bloqueo)</h2><table><tr><th>Detección</th><th>Min</th><th>Host</th><th>IP</th><th>Marca</th><th>Motivo</th><th>Detalle</th></tr>{filas_desc}</table>
<h2>Expedientes</h2>{''.join(tarjetas)}
<p class=sub>Hash final de la cadena de evidencia: <code>{d['hash_cadena_final']}</code>. Verificar con
<code>python plataforma/expedientes.py --verificar entrega/expedientes.json</code>.</p>
</main></body></html>"""


def main() -> None:
    p = argparse.ArgumentParser(description="Armado de expedientes de streams piratas")
    p.add_argument("--servidor", default="http://localhost:8080")
    p.add_argument("--salida", type=Path, default=REPO_DIR / "entrega")
    p.add_argument("--una-vez", action="store_true", help="procesa lo publicado hasta ahora y termina")
    p.add_argument("--intervalo", type=float, default=1.0, help="segundos entre consultas")
    p.add_argument("--verificar", type=Path, help="verifica la integridad de un expedientes.json exportado")
    args = p.parse_args()
    if args.verificar:
        sys.exit(verificar_archivo(args.verificar))
    base = args.servidor.rstrip("/")
    arm = Armador(base)
    desde = -1e9
    while True:
        r = pedir(base, f"/detecciones?desde={desde}")
        for det in r.get("detecciones", []):
            arm.procesar(det)
            print(f"[min {det['minuto']:6.1f}] {det['id']} {det['host_stream']:<32} -> "
                  f"{'descartada' if arm.descartadas and arm.descartadas[-1]['deteccion_id'] == det['id'] else 'expediente'}",
                  flush=True)
        desde = r.get("minuto_actual", desde)
        if r.get("detecciones"):
            exportar(arm, args.salida)
        if args.una_vez or pedir(base, "/estado").get("finalizado"):
            break
        time.sleep(args.intervalo)
    datos = exportar(arm, args.salida)
    print(f"{len(datos['expedientes'])} expedientes, {len(datos['detecciones_descartadas'])} descartadas -> {args.salida}")


if __name__ == "__main__":
    main()
