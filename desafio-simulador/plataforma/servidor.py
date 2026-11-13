#!/usr/bin/env python3
"""Plataforma de órdenes de bloqueo en vivo (núcleo obligatorio + extras).

Detección -> expediente -> juez de turno (login, firma) -> proveedores (reintentos, confirmación)
-> vencimiento -> auditoría encadenada. Extras: reclamos con levantamiento firmado, registro
público de transparencia e interfaz judicial para celular con notificaciones.

Solo biblioteca estándar de Python 3.9+.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import expedientes as ex  # noqa: E402

DIR = Path(__file__).resolve().parent
REPO_DIR = DIR.parent
RESERVAS_POR_ENVIO = 4
ESTADOS_ACTIVOS = ("recibida", "aplicada")


def ahora_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def http(base: str, ruta: str, cuerpo: Optional[dict] = None) -> Tuple[int, Any]:
    datos = json.dumps(cuerpo).encode() if cuerpo is not None else None
    req = urllib.request.Request(base + ruta, data=datos, method="POST" if datos else "GET",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except ValueError:
            return e.code, {"error": str(e)}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, {"error": f"sin conexión: {e}"}


def firmar(clave: str, mensaje: str) -> str:
    return hmac.new(clave.encode(), mensaje.encode(), hashlib.sha256).hexdigest()


def hash_clave(clave: str, sal: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", clave.encode(), bytes.fromhex(sal), 120_000).hex()


# --- auditoría ------------------------------------------------------------------------

class Auditoria:
    """Registro append-only: cada entrada incluye el hash de la anterior."""

    def __init__(self, ruta: Path):
        self.ruta = ruta
        ruta.parent.mkdir(parents=True, exist_ok=True)
        ruta.write_text("", encoding="utf-8")
        self.previo = "0" * 64
        self.n = 0
        self.lock = threading.Lock()

    def registrar(self, evento: str, minuto: Optional[float], actor: str, **datos: Any) -> dict:
        with self.lock:
            self.n += 1
            entrada = {"n": self.n, "utc": ahora_utc(), "minuto": minuto, "evento": evento, "actor": actor,
                       "datos": datos, "hash_previo": self.previo}
            entrada["hash"] = ex.sha256(ex.canonico(entrada))
            self.previo = entrada["hash"]
            with self.ruta.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
            return entrada


REDES = {"x": "X (ex Twitter)", "discord": "Discord", "telegram": "Telegram"}


def armar_avisos(exp: dict, decision: dict) -> List[dict]:
    """Avisos a quienes le dan servicio al pirata: el hosting dueño de la IP y las redes donde se promociona.
    No bloquean nada por sí solos; buscan que el servidor y las publicaciones se den de baja y que montar
    uno nuevo le cueste más al infractor."""
    srv, eid = exp["servidor"], exp["expediente_id"]
    firma = f"{decision['juez']} — {decision['juzgado']}. Orden {eid}, firma {decision['firma'][:16]}…"
    avisos = [{
        "id": f"{eid}-HOST", "tipo": "hosting", "destinatario": f"AS{srv['asn']} {srv.get('organizacion_asn') or ''}".strip(),
        "objetivo": f"{srv['host_stream']} ({srv['ip']})",
        "texto": (f"Por orden judicial ({firma}) se informa que el servidor {srv['ip']} de su red entrega la transmisión no autorizada "
                  f"{srv['stream_url']} del partido «{exp['partido']}», titular {exp.get('titular_derechos')}. "
                  f"Se solicita: 1) suspender el servicio al cliente que opera ese servidor; 2) preservar los registros de "
                  f"contratación, pago y acceso; 3) no reasignarle otra IP para el mismo uso. "
                  f"Evidencia: expediente {eid}, hash {exp['hash_expediente']}.")}]
    for i, pr in enumerate(exp["promocion"], start=1):
        red = REDES.get(pr["red"], pr["red"])
        avisos.append({
            "id": f"{eid}-RED{i}", "tipo": "publicacion", "destinatario": red, "objetivo": pr["url"],
            "texto": (f"Por orden judicial ({firma}) se solicita a {red} retirar la publicación {pr['url']} "
                      f"(minuto {pr['minuto']:g}), que promociona la transmisión no autorizada {exp['pagina']}, y preservar "
                      f"los datos de la cuenta que la publicó. Evidencia: expediente {eid}, hash {exp['hash_expediente']}.")})
    return avisos


def verificar_auditoria(ruta: Path) -> int:
    previo, errores, n = "0" * 64, [], 0
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        e = json.loads(linea)
        n += 1
        if e["hash_previo"] != previo:
            errores.append(f"entrada {e['n']}: cadena rota")
        if ex.sha256(ex.canonico({k: v for k, v in e.items() if k != "hash"})) != e["hash"]:
            errores.append(f"entrada {e['n']}: contenido alterado")
        previo = e["hash"]
    print("\n".join(errores) if errores else f"OK: {n} entradas de auditoría íntegras. Hash final {previo}")
    return 1 if errores else 0


# --- plataforma -----------------------------------------------------------------------

class Plataforma:
    def __init__(self, base: str, salida: Path, usuarios: Path, juzgados: Path):
        self.base, self.salida = base, salida
        self.lock = threading.RLock()
        self.audit = Auditoria(salida / "auditoria.jsonl")
        self.arm = ex.Armador(base)
        self.proveedores: List[dict] = http(base, "/proveedores")[1]
        jz = json.loads(juzgados.read_text(encoding="utf-8"))
        self.jueces: Dict[str, dict] = {}
        for j in jz["juzgados"]:
            for juez in j["jueces"]:
                self.jueces[juez["id"]] = {"id": juez["id"], "nombre": juez["nombre"], "juzgado_id": j["id"],
                                           "juzgado": j["nombre"], "_clave": juez["clave_firma_demo"]}
        self.usuarios: Dict[str, dict] = json.loads(usuarios.read_text(encoding="utf-8"))["usuarios"]
        self.sesiones: Dict[str, str] = {}
        self.fallos_login: Dict[str, List[float]] = {}
        self.minuto, self.de_turno, self.finalizado = 0.0, [], False
        self.tramites: Dict[str, dict] = {}
        self.reenvios: Dict[str, dict] = {}
        self.reclamos: Dict[str, dict] = {}
        self.seq_orden = 0
        self.desde_det = self.desde_rec = -1e9
        self.vencimiento_verificado = False
        self.forzar_ip: set = set()
        self.audit.registrar("plataforma_iniciada", None, "sistema", simulador=base,
                             proveedores=[p["id"] for p in self.proveedores], jueces=list(self.jueces))

    # -- utilidades
    def juez_de_turno(self) -> Optional[str]:
        return self.de_turno[0] if self.de_turno else None

    def nuevo_orden_id(self) -> str:
        self.seq_orden += 1
        return f"ORD-{self.seq_orden:05d}"

    def mensaje_orden(self, o: dict) -> str:
        return f"{o['orden_id']}|{o['tipo']}|{o['objetivo']}|{o['vence_min']}|{o['juez_id']}"

    def expediente(self, exp_id: str) -> Optional[dict]:
        return next((e for e in self.arm.expedientes.values() if e["expediente_id"] == exp_id), None)

    # -- ciclo principal
    def ciclo(self) -> None:
        cod, est = http(self.base, "/estado")
        if cod != 200:
            return
        with self.lock:
            cambio_turno = set(est["jueces_de_turno"]) != set(self.de_turno)
            self.minuto, self.de_turno, self.finalizado = est["minuto_actual"], est["jueces_de_turno"], est["finalizado"]
            if cambio_turno:
                self.audit.registrar("turno_vigente", self.minuto, "simulador", jueces_de_turno=self.de_turno)
        self.leer_detecciones()
        with self.lock:
            self.reasignar()
        self.seguir_ordenes()
        self.leer_reclamos()
        with self.lock:
            self.controlar_vencimiento()
            self.exportar()

    def leer_detecciones(self) -> None:
        cod, r = http(self.base, f"/detecciones?desde={self.desde_det}")
        if cod != 200:
            return
        with self.lock:
            for det in r.get("detecciones", []):
                antes = set(self.arm.expedientes)
                n_desc = len(self.arm.descartadas)
                self.arm.procesar(det)
                if len(self.arm.descartadas) > n_desc:
                    d = self.arm.descartadas[-1]
                    self.audit.registrar("deteccion_descartada", det["minuto"], "sistema", deteccion_id=det["id"],
                                         host=det["host_stream"], motivo=d["motivo"], detalle=d["detalle"])
                    continue
                clave = f"{det['host_stream']}|{det['ip_servidor']}"
                exp = self.arm.expedientes[clave]
                ev = exp["evidencia"][-1]
                self.audit.registrar("evidencia_agregada", det["minuto"], "sistema", deteccion_id=det["id"],
                                     expediente_id=exp["expediente_id"], sha256_captura=ev["sha256_captura"],
                                     hash_encadenado=ev["hash_encadenado"])
                if clave not in antes:
                    self.abrir_tramite(exp, det["minuto"])
            self.desde_det = r.get("minuto_actual", self.desde_det)

    def abrir_tramite(self, exp: dict, minuto: float) -> None:
        juez = self.juez_de_turno()
        t = {"expediente_id": exp["expediente_id"], "sitio": exp["sitio"], "estado": "pendiente",
             "abierto_min": minuto, "juez_asignado": juez,
             "asignaciones": [{"juez_id": juez, "minuto": self.minuto, "motivo": "juez de turno al abrir"}],
             "decision": None, "envios": [], "reincidente": bool(exp["expedientes_previos_del_sitio"]),
             "avisos": []}
        self.tramites[exp["expediente_id"]] = t
        self.audit.registrar("expediente_abierto", minuto, "sistema", expediente_id=exp["expediente_id"],
                             sitio=exp["sitio"], pedido=exp["pedido"]["tipo"], objetivo=exp["pedido"]["objetivo"],
                             hash_expediente=exp["hash_expediente"], reincidente=t["reincidente"],
                             expedientes_previos=exp["expedientes_previos_del_sitio"])
        self.audit.registrar("juez_notificado", self.minuto, "sistema", expediente_id=exp["expediente_id"], juez_id=juez,
                             prioridad="alta: el sitio cambió de servidor" if t["reincidente"] else "normal")

    def pendientes_de(self) -> List[Tuple[str, dict]]:
        exps = sorted((t for t in self.tramites.values() if t["estado"] == "pendiente"),
                      key=lambda t: (not t.get("reincidente"), t["abierto_min"]))
        return ([("expediente", t) for t in exps]
                + [("reenvio", r) for r in self.reenvios.values() if r["estado"] == "pendiente"]
                + [("reclamo", r) for r in self.reclamos.values() if r["estado"] == "pendiente"])

    def reasignar(self) -> None:
        juez = self.juez_de_turno()
        if not juez:
            return
        for tipo, item in self.pendientes_de():
            if item["juez_asignado"] != juez:
                previo = item["juez_asignado"]
                item["juez_asignado"] = juez
                item.setdefault("asignaciones", []).append({"juez_id": juez, "minuto": self.minuto,
                                                             "motivo": f"cambio de turno (antes {previo})"})
                ref = item.get("expediente_id") or item.get("id")
                self.audit.registrar("pendiente_reasignado", self.minuto, "sistema", tipo=tipo, ref=ref,
                                     juez_saliente=previo, juez_entrante=juez)
                self.audit.registrar("juez_notificado", self.minuto, "sistema", tipo=tipo, ref=ref, juez_id=juez)

    # -- decisiones judiciales
    def puede_firmar(self, juez_id: str, item: dict) -> Optional[str]:
        if juez_id not in self.de_turno:
            return "El juez no está de turno: no puede firmar."
        if item.get("juez_asignado") != juez_id:
            return "Este pendiente no está asignado a este juez."
        if item.get("estado") != "pendiente":
            return "Ya fue resuelto."
        return None

    def decidir_expediente(self, juez_id: str, exp_id: str, aprobar: bool, motivo: str) -> Tuple[int, dict]:
        with self.lock:
            t, exp = self.tramites.get(exp_id), self.expediente(exp_id)
            if not t or not exp:
                return 404, {"error": "Expediente inexistente"}
            error = self.puede_firmar(juez_id, t)
            if error:
                self.audit.registrar("firma_rechazada", self.minuto, juez_id, expediente_id=exp_id, motivo=error)
                return 403, {"error": error}
            juez = self.jueces[juez_id]
            decision = "aprobado" if aprobar else "rechazado"
            texto = f"DECISION|{exp_id}|{exp['hash_expediente']}|{decision}|{juez_id}"
            t["decision"] = {"decision": decision, "juez_id": juez_id, "juez": juez["nombre"],
                             "juzgado_id": juez["juzgado_id"], "juzgado": juez["juzgado"], "minuto": self.minuto,
                             "utc": ahora_utc(), "motivo": motivo, "hash_expediente_firmado": exp["hash_expediente"],
                             "texto_firmado": texto, "firma": firmar(juez["_clave"], texto)}
            t["estado"] = decision
            self.audit.registrar("decision_firmada", self.minuto, juez_id, expediente_id=exp_id, decision=decision,
                                 motivo=motivo, hash_expediente=exp["hash_expediente"], firma=t["decision"]["firma"])
            if aprobar:
                self.preparar_envios(t, exp, juez)
                self.emitir_avisos(t, exp)
            return 200, {"ok": True, "decision": decision}

    def emitir_avisos(self, t: dict, exp: dict) -> None:
        t["avisos"] = armar_avisos(exp, t["decision"])
        carpeta = self.salida / "avisos"
        carpeta.mkdir(parents=True, exist_ok=True)
        for a in t["avisos"]:
            a["minuto"] = self.minuto
            (carpeta / f"{a['id']}.txt").write_text(f"Para: {a['destinatario']}\nObjetivo: {a['objetivo']}\n\n{a['texto']}\n",
                                                    encoding="utf-8")
            self.audit.registrar("aviso_emitido", self.minuto, "sistema", expediente_id=t["expediente_id"], aviso_id=a["id"],
                                 tipo=a["tipo"], destinatario=a["destinatario"], objetivo=a["objetivo"],
                                 sha256_texto=ex.sha256(a["texto"].encode()))

    def objetivos_para(self, prov: dict, exp: dict) -> Tuple[List[Tuple[str, str]], str]:
        pedido, col = exp["pedido"], exp["riesgo_colateral"]
        host = exp["servidor"]["host_stream"]
        if host in self.forzar_ip:
            pedido = {"tipo": "ip", "objetivo": exp["servidor"]["ip"]}
        if pedido["tipo"] in prov["capacidades"]:
            return [(pedido["tipo"], pedido["objetivo"])], "tipo pedido"
        if pedido["tipo"] == "ip" and "dominio" in prov["capacidades"]:
            dominios = sorted(set(col["dominios_del_mismo_sitio"]) | {host})
            return [("dominio", d) for d in dominios], "solo acepta dominio: se piden los dominios del sitio en esa IP"
        return [], "solo acepta IP y la IP es compartida: no se envía para evitar daño colateral"

    def preparar_envios(self, t: dict, exp: dict, juez: dict) -> None:
        vence = exp["pedido"]["vence_min"]
        for prov in self.proveedores:
            objetivos, nota = self.objetivos_para(prov, exp)
            if not objetivos:
                t["envios"].append({"proveedor": prov["id"], "tipo": None, "objetivo": None, "estado": "no_aplicable",
                                    "nota": nota, "intentos": []})
                self.audit.registrar("envio_no_aplicable", self.minuto, "sistema", expediente_id=exp["expediente_id"],
                                     proveedor=prov["id"], nota=nota)
                continue
            for tipo, objetivo in objetivos:
                reservas = []
                for _ in range(RESERVAS_POR_ENVIO):
                    o = {"orden_id": self.nuevo_orden_id(), "expediente_id": exp["expediente_id"], "tipo": tipo,
                         "objetivo": objetivo, "vence_min": vence, "juzgado_id": juez["juzgado_id"], "juez_id": juez["id"]}
                    o["firma"] = firmar(juez["_clave"], self.mensaje_orden(o))
                    reservas.append(o)
                envio = {"proveedor": prov["id"], "tipo": tipo, "objetivo": objetivo, "vence_min": vence, "nota": nota,
                         "estado": "por_enviar", "intentos": [], "_reservas": reservas}
                t["envios"].append(envio)
                self.enviar(t, envio)

    def enviar(self, t: dict, envio: dict, orden: Optional[dict] = None) -> None:
        if orden is None:
            orden = envio["_reservas"].pop(0)
        cod, resp = http(self.base, f"/proveedores/{envio['proveedor']}/ordenes", orden)
        intento = {"orden_id": orden["orden_id"], "firmado_por": orden["juez_id"], "enviado_min": self.minuto,
                   "http": cod, "respuesta": resp, "estado": resp.get("estado", "error") if cod == 202 else "rechazada"}
        envio["intentos"].append(intento)
        envio["estado"] = intento["estado"]
        self.audit.registrar("orden_enviada", self.minuto, "sistema", expediente_id=t["expediente_id"],
                             proveedor=envio["proveedor"], orden_id=orden["orden_id"], tipo=orden["tipo"],
                             objetivo=orden["objetivo"], vence_min=orden["vence_min"], firmado_por=orden["juez_id"],
                             http=cod, respuesta=resp)
        if cod == 0 or cod >= 500:
            intento["estado"] = envio["estado"] = "fallida"
            self.reintentar(t, envio)

    def reintentar(self, t: dict, envio: dict) -> None:
        firmante = envio["intentos"][-1]["firmado_por"]
        if envio["_reservas"] and firmante in self.de_turno:
            self.audit.registrar("reintento", self.minuto, "sistema", expediente_id=t["expediente_id"],
                                 proveedor=envio["proveedor"], intento=len(envio["intentos"]) + 1)
            self.enviar(t, envio)
            return
        rid = f"RE-{len(self.reenvios) + 1:03d}"
        juez = self.juez_de_turno()
        self.reenvios[rid] = {"id": rid, "expediente_id": t["expediente_id"], "envio_idx": t["envios"].index(envio),
                              "proveedor": envio["proveedor"], "tipo": envio["tipo"], "objetivo": envio["objetivo"],
                              "estado": "pendiente", "juez_asignado": juez, "creado_min": self.minuto,
                              "motivo": "El juez que firmó ya no está de turno" if envio["_reservas"] else "Sin reservas"}
        envio["estado"] = "reenvio_pendiente_de_firma"
        self.audit.registrar("reenvio_pendiente", self.minuto, "sistema", id=rid, expediente_id=t["expediente_id"],
                             proveedor=envio["proveedor"], juez_id=juez)

    def firmar_reenvio(self, juez_id: str, rid: str) -> Tuple[int, dict]:
        with self.lock:
            r = self.reenvios.get(rid)
            if not r:
                return 404, {"error": "Reenvío inexistente"}
            error = self.puede_firmar(juez_id, r)
            if error:
                return 403, {"error": error}
            t = self.tramites[r["expediente_id"]]
            envio, juez = t["envios"][r["envio_idx"]], self.jueces[juez_id]
            o = {"orden_id": self.nuevo_orden_id(), "expediente_id": r["expediente_id"], "tipo": envio["tipo"],
                 "objetivo": envio["objetivo"], "vence_min": envio["vence_min"], "juzgado_id": juez["juzgado_id"],
                 "juez_id": juez_id}
            o["firma"] = firmar(juez["_clave"], self.mensaje_orden(o))
            envio["_reservas"] = []
            r.update(estado="firmado", firmado_por=juez_id, firmado_min=self.minuto)
            self.audit.registrar("reenvio_firmado", self.minuto, juez_id, id=rid, orden_id=o["orden_id"])
            self.enviar(t, envio, o)
            return 200, {"ok": True}

    # -- seguimiento de confirmaciones
    def seguir_ordenes(self) -> None:
        with self.lock:
            activos = [(t, e) for t in self.tramites.values() for e in t["envios"]
                       if e["intentos"] and e["intentos"][-1]["estado"] in ESTADOS_ACTIVOS]
        for t, envio in activos:
            it = envio["intentos"][-1]
            cod, o = http(self.base, f"/proveedores/{envio['proveedor']}/ordenes/{it['orden_id']}")
            if cod != 200 or o.get("estado") == it["estado"]:
                continue
            with self.lock:
                it["estado"] = envio["estado"] = o["estado"]
                for k in ("aplicada_min", "finalizada_min", "motivo"):
                    if k in o:
                        it[k] = o[k]
                evento = {"aplicada": "confirmacion_aplicada", "fallida": "orden_fallida",
                          "vencida": "orden_vencida", "levantada": "orden_levantada"}.get(o["estado"], "orden_estado")
                self.audit.registrar(evento, o.get("aplicada_min") if o["estado"] == "aplicada" else
                                     o.get("finalizada_min", self.minuto), "proveedor:" + envio["proveedor"],
                                     expediente_id=t["expediente_id"], orden_id=it["orden_id"], estado=o["estado"],
                                     motivo=o.get("motivo"))
                if o["estado"] == "fallida":
                    self.reintentar(t, envio)

    def controlar_vencimiento(self) -> None:
        if self.vencimiento_verificado or not self.finalizado:
            return
        activas = [(t["expediente_id"], e["proveedor"], e["intentos"][-1]["orden_id"]) for t in self.tramites.values()
                   for e in t["envios"] if e["tipo"] == "ip" and e["intentos"] and e["intentos"][-1]["estado"] in ESTADOS_ACTIVOS]
        if not activas:
            self.vencimiento_verificado = True
            self.audit.registrar("vencimiento_verificado", self.minuto, "sistema",
                                 detalle="Ningún bloqueo por IP sigue activo después del partido.")

    # -- reclamos
    def leer_reclamos(self) -> None:
        cod, r = http(self.base, f"/reclamos?desde={self.desde_rec}")
        if cod != 200:
            return
        with self.lock:
            for rec in r.get("reclamos", []):
                if rec["id"] in self.reclamos:
                    continue
                self.reclamos[rec["id"]] = rec = dict(rec, verificacion=self.verificar_reclamo(rec),
                                                      estado="pendiente", juez_asignado=self.juez_de_turno(),
                                                      recibido_min=self.minuto)
                self.audit.registrar("reclamo_recibido", rec["minuto"], "sitio:" + rec["dominio"], id=rec["id"],
                                     proveedor=rec["proveedor"], mensaje=rec["mensaje"])
                self.audit.registrar("reclamo_verificado", self.minuto, "sistema", id=rec["id"], **rec["verificacion"])
                self.audit.registrar("juez_notificado", self.minuto, "sistema", tipo="reclamo", ref=rec["id"],
                                     juez_id=rec["juez_asignado"])
            self.desde_rec = r.get("minuto_actual", self.desde_rec)

    def verificar_reclamo(self, rec: dict) -> dict:
        dominio = rec["dominio"]
        afectan = set()
        for t in self.tramites.values():
            for e in t["envios"]:
                if not e["intentos"] or e["tipo"] is None:
                    continue
                if e["tipo"] == "dominio" and e["objetivo"] == dominio:
                    afectan.add((t["expediente_id"], e["tipo"], e["objetivo"]))
                elif e["tipo"] == "ip":
                    dns = self.arm.dns_cache.get(e["objetivo"]) or http(self.base, f"/dns-pasivo?ip={e['objetivo']}")[1]
                    if dominio in (dns or {}).get("dominios", []):
                        afectan.add((t["expediente_id"], e["tipo"], e["objetivo"]))
        afectan = sorted(afectan)
        sitios_piratas = {ex.dominio_base(e["servidor"]["host_stream"]) for e in self.arm.expedientes.values()}
        licenciatario = any(ex.host_en(dominio, l.get("dominios_autorizados", [])) for l in self.arm.partido.get("licenciatarios", []))
        legitimo = ex.dominio_base(dominio) not in sitios_piratas
        valido = bool(afectan) and legitimo
        motivo = ("Licenciatario autorizado bloqueado. " if licenciatario else "") + (
            f"{dominio} comparte la IP bloqueada y no pertenece a un sitio pirata: corresponde levantar y reemplazar por dominio."
            if valido else "El dominio pertenece a un sitio pirata o no lo afecta ninguna orden nuestra.")
        return {"valido": valido, "licenciatario": licenciatario, "afectado_por": afectan, "motivo": motivo}

    def decidir_reclamo(self, juez_id: str, rid: str, aceptar: bool) -> Tuple[int, dict]:
        with self.lock:
            rec = self.reclamos.get(rid)
            if not rec:
                return 404, {"error": "Reclamo inexistente"}
            error = self.puede_firmar(juez_id, rec)
            if error:
                return 403, {"error": error}
            juez = self.jueces[juez_id]
            rec.update(estado="aceptado" if aceptar else "rechazado", decidido_por=juez_id, decidido_min=self.minuto)
            self.audit.registrar("reclamo_decidido", self.minuto, juez_id, id=rid, aceptado=aceptar)
            if not aceptar:
                return 200, {"ok": True}
            levantadas, reemplazos = [], []
            for exp_id, tipo, objetivo in {tuple(a) for a in rec["verificacion"]["afectado_por"]}:
                t, exp = self.tramites[exp_id], self.expediente(exp_id)
                for e in t["envios"]:
                    if e["tipo"] != tipo or e["objetivo"] != objetivo or not e["intentos"]:
                        continue
                    it = e["intentos"][-1]
                    if it["estado"] in ESTADOS_ACTIVOS:
                        firma = firmar(juez["_clave"], f"LEVANTAR|{it['orden_id']}|{juez_id}")
                        cod, resp = http(self.base, f"/proveedores/{e['proveedor']}/ordenes/{it['orden_id']}/levantar",
                                         {"juez_id": juez_id, "firma": firma, "motivo": f"Reclamo {rid}"})
                        self.audit.registrar("orden_levantada", self.minuto, juez_id, orden_id=it["orden_id"],
                                             proveedor=e["proveedor"], http=cod, reclamo=rid)
                        if cod == 200:
                            it["estado"] = e["estado"] = "levantada"
                            levantadas.append(it["orden_id"])
                    host = exp["servidor"]["host_stream"]
                    ya = any(x["proveedor"] == e["proveedor"] and x["tipo"] == "dominio" and x["objetivo"] == host
                             for x in t["envios"])
                    if tipo == "ip" and not ya:
                        o = {"orden_id": self.nuevo_orden_id(), "expediente_id": exp_id, "tipo": "dominio",
                             "objetivo": host, "vence_min": exp["pedido"]["vence_min"],
                             "juzgado_id": juez["juzgado_id"], "juez_id": juez_id}
                        o["firma"] = firmar(juez["_clave"], self.mensaje_orden(o))
                        nuevo = {"proveedor": e["proveedor"], "tipo": "dominio", "objetivo": host,
                                 "vence_min": o["vence_min"], "nota": f"reemplazo por reclamo {rid}", "estado": "por_enviar",
                                 "intentos": [], "_reservas": []}
                        t["envios"].append(nuevo)
                        self.enviar(t, nuevo, o)
                        reemplazos.append(o["orden_id"])
            rec.update(levantadas=levantadas, reemplazos=reemplazos)
            return 200, {"ok": True, "levantadas": levantadas, "reemplazos": reemplazos}

    # -- vistas
    def transparencia(self) -> List[dict]:
        filas = []
        for t in sorted(self.tramites.values(), key=lambda x: x["expediente_id"]):
            d = t["decision"] or {}
            for e in t["envios"]:
                for it in e["intentos"]:
                    filas.append({"expediente_id": t["expediente_id"], "sitio": t["sitio"], "proveedor": e["proveedor"],
                                  "tipo": e["tipo"], "objetivo": e["objetivo"], "orden_id": it["orden_id"],
                                  "juzgado": d.get("juzgado"), "juez": self.jueces[it["firmado_por"]]["nombre"],
                                  "enviada_min": it["enviado_min"], "aplicada_min": it.get("aplicada_min"),
                                  "finalizada_min": it.get("finalizada_min"), "vence_min": e["vence_min"],
                                  "estado": it["estado"]})
        return filas

    def resumen_item(self, tipo: str, item: dict) -> dict:
        if tipo == "expediente":
            e = self.expediente(item["expediente_id"])
            return {"tipo": tipo, "id": item["expediente_id"], "sitio": item["sitio"], "abierto_min": item["abierto_min"],
                    "reincidente": item.get("reincidente", False),
                    "host": e["servidor"]["host_stream"], "ip": e["servidor"]["ip"], "asn": e["servidor"]["asn"],
                    "marca": e["verificacion_marca"].get("marca"), "marca_detalle": e["verificacion_marca"]["detalle"],
                    "pedido": e["pedido"], "colateral": e["riesgo_colateral"]["motivo"],
                    "terceros": e["riesgo_colateral"]["dominios_de_terceros"], "evidencias": len(e["evidencia"]),
                    "promocion": e["promocion"], "hash_expediente": e["hash_expediente"],
                    "ultimo_sha256": e["evidencia"][-1]["sha256_captura"] if e["evidencia"] else None,
                    "stream_url": e["servidor"]["stream_url"], "organizacion_asn": e["servidor"].get("organizacion_asn"),
                    "prefijo": e["verificacion_marca"].get("prefijo"), "previos": e["expedientes_previos_del_sitio"],
                    "primera_min": e["primera_deteccion_min"], "ultima_min": e["ultima_deteccion_min"],
                    "capturas": [{"id": i["deteccion_id"], "min": i["captura_min"], "sha256": i["sha256_captura"]}
                                 for i in e["evidencia"]]}
        if tipo == "reenvio":
            return {"tipo": tipo, "id": item["id"], "expediente_id": item["expediente_id"], "proveedor": item["proveedor"],
                    "tipo_bloqueo": item["tipo"], "objetivo": item["objetivo"], "motivo": item["motivo"]}
        return {"tipo": tipo, "id": item["id"], "dominio": item["dominio"], "proveedor": item["proveedor"],
                "mensaje": item["mensaje"], "verificacion": item["verificacion"]}

    def vista_juez(self, juez_id: str) -> dict:
        with self.lock:
            pendientes = [self.resumen_item(tp, it) for tp, it in self.pendientes_de() if it["juez_asignado"] == juez_id]
            decididos = [{"expediente_id": t["expediente_id"], "sitio": t["sitio"], "decision": t["decision"]["decision"],
                          "minuto": t["decision"]["minuto"],
                          "envios": [{"proveedor": e["proveedor"], "tipo": e["tipo"], "objetivo": e["objetivo"],
                                      "estado": e["estado"], "intentos": len(e["intentos"])} for e in t["envios"]]}
                         for t in self.tramites.values() if t["decision"] and t["decision"]["juez_id"] == juez_id]
            j = self.jueces[juez_id]
            return {"juez": {"id": juez_id, "nombre": j["nombre"], "juzgado": j["juzgado"]},
                    "de_turno": juez_id in self.de_turno, "minuto": self.minuto, "pendientes": pendientes,
                    "decididos": decididos}

    def exportar(self) -> None:
        ex.exportar(self.arm, self.salida)
        limpio = lambda t: dict(t, envios=[{k: v for k, v in e.items() if not k.startswith("_")} for e in t["envios"]])
        datos = {"generado_utc": ahora_utc(), "minuto": self.minuto, "finalizado": self.finalizado,
                 "jueces": {k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")} for k, v in self.jueces.items()},
                 "proveedores": self.proveedores, "tramites": [limpio(t) for t in self.tramites.values()],
                 "reenvios": list(self.reenvios.values()), "reclamos": list(self.reclamos.values()),
                 "transparencia": self.transparencia(), "vencimiento_verificado": self.vencimiento_verificado,
                 "auditoria": {"archivo": "auditoria.jsonl", "entradas": self.audit.n, "hash_final": self.audit.previo}}
        tmp = self.salida / "plataforma.json.tmp"
        tmp.write_text(json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.salida / "plataforma.json")

    # -- login
    def login(self, usuario: str, clave: str, ip: str) -> Optional[str]:
        ahora = time.time()
        fallos = [f for f in self.fallos_login.get(usuario, []) if ahora - f < 60]
        u = self.usuarios.get(usuario)
        if len(fallos) >= 5:
            self.audit.registrar("login_bloqueado", self.minuto, usuario, ip=ip)
            return None
        if not u or not hmac.compare_digest(hash_clave(clave, u["sal"]), u["hash"]):
            self.fallos_login[usuario] = fallos + [ahora]
            self.audit.registrar("login_fallido", self.minuto, usuario, ip=ip)
            return None
        token = secrets.token_urlsafe(32)
        self.sesiones[token] = u["juez_id"]
        self.audit.registrar("login", self.minuto, u["juez_id"], ip=ip)
        return token


# --- HTTP -----------------------------------------------------------------------------

class Manejador(BaseHTTPRequestHandler):
    plat: Plataforma

    def log_message(self, *a: Any) -> None:
        pass

    def _enviar(self, cod: int, cuerpo: bytes, tipo: str, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(cod)
        self.send_header("Content-Type", tipo)
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(cuerpo)

    def _json(self, cod: int, datos: Any, extra: Optional[Dict[str, str]] = None) -> None:
        self._enviar(cod, json.dumps(datos, ensure_ascii=False).encode(), "application/json; charset=utf-8", extra)

    def _juez(self) -> Optional[str]:
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return self.plat.sesiones.get(c["sid"].value) if "sid" in c else None

    def _cuerpo(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def do_GET(self) -> None:
        ruta = urlparse(self.path).path
        p = self.plat
        if ruta in ("/", "/juez"):
            return self._enviar(200, (DIR / "web" / "juez.html").read_bytes(), "text/html; charset=utf-8")
        if ruta == "/publico":
            return self._enviar(200, (DIR / "web" / "publico.html").read_bytes(), "text/html; charset=utf-8")
        if ruta == "/api/publico":
            with p.lock:
                return self._json(200, {"minuto": p.minuto, "partido": p.arm.partido.get("nombre"),
                                        "ordenes": p.transparencia(),
                                        "reclamos": [{k: r.get(k) for k in ("id", "dominio", "estado", "minuto")}
                                                     for r in p.reclamos.values()]})
        juez = self._juez()
        if not juez:
            return self._json(401, {"error": "Iniciá sesión"})
        if ruta == "/api/yo":
            return self._json(200, p.vista_juez(juez))
        if ruta.startswith("/api/evidencia/"):
            partes = ruta.split("/")
            if len(partes) != 5:
                return self._json(404, {"error": "No existe"})
            exp_id, det_id = partes[3], partes[4]
            with p.lock:
                t, e = p.tramites.get(exp_id), p.expediente(exp_id)
                autorizado = t and (t["juez_asignado"] == juez or (t["decision"] or {}).get("juez_id") == juez)
                item = next((i for i in (e or {}).get("evidencia", []) if i["deteccion_id"] == det_id), None)
                if not autorizado or not item:
                    return self._json(403, {"error": "No le corresponde esta evidencia"})
                contenido = base64.b64decode(item["deteccion_original"]["captura"]["contenido_b64"])
                p.audit.registrar("evidencia_consultada", p.minuto, juez, expediente_id=exp_id,
                                   deteccion_id=det_id, sha256=item["sha256_captura"])
            return self._enviar(200, contenido, "video/mp2t",
                                {"Content-Disposition": f'attachment; filename="{exp_id}_{det_id}.ts"'})
        if ruta.startswith("/api/expedientes/"):
            exp_id = ruta.rsplit("/", 1)[1]
            with p.lock:
                t, e = p.tramites.get(exp_id), p.expediente(exp_id)
                autorizado = t and (t["juez_asignado"] == juez or (t["decision"] or {}).get("juez_id") == juez)
                if not autorizado or not e:
                    return self._json(403, {"error": "No le corresponde este expediente"})
                return self._json(200, {"expediente": e, "tramite": {k: v for k, v in t.items() if k != "envios"}})
        self._json(404, {"error": "No existe"})

    def do_POST(self) -> None:
        ruta, p, cuerpo = urlparse(self.path).path, self.plat, self._cuerpo()
        if ruta == "/api/login":
            token = p.login(str(cuerpo.get("usuario", "")), str(cuerpo.get("clave", "")), self.client_address[0])
            if not token:
                return self._json(401, {"error": "Usuario o contraseña incorrectos"})
            return self._json(200, {"ok": True}, {"Set-Cookie": f"sid={token}; HttpOnly; SameSite=Strict; Path=/"})
        juez = self._juez()
        if not juez:
            return self._json(401, {"error": "Iniciá sesión"})
        partes = ruta.strip("/").split("/")
        if ruta == "/api/logout":
            c = SimpleCookie(self.headers.get("Cookie", ""))
            p.sesiones.pop(c["sid"].value, None)
            p.audit.registrar("logout", p.minuto, juez)
            return self._json(200, {"ok": True}, {"Set-Cookie": "sid=; Max-Age=0; Path=/"})
        if len(partes) == 4 and partes[1] == "expedientes" and partes[3] == "decision":
            return self._json(*p.decidir_expediente(juez, partes[2], cuerpo.get("decision") == "aprobar",
                                                    str(cuerpo.get("motivo", ""))[:500]))
        if len(partes) == 4 and partes[1] == "reenvios" and partes[3] == "firmar":
            return self._json(*p.firmar_reenvio(juez, partes[2]))
        if len(partes) == 4 and partes[1] == "reclamos" and partes[3] == "decision":
            return self._json(*p.decidir_reclamo(juez, partes[2], cuerpo.get("decision") == "aceptar"))
        self._json(404, {"error": "No existe"})


def main() -> None:
    a = argparse.ArgumentParser(description="Plataforma de órdenes de bloqueo en vivo")
    a.add_argument("--simulador", default="http://localhost:8080")
    a.add_argument("--puerto", type=int, default=8090)
    a.add_argument("--salida", type=Path, default=REPO_DIR / "entrega")
    a.add_argument("--usuarios", type=Path, default=DIR / "usuarios_demo.json")
    a.add_argument("--juzgados", type=Path, default=REPO_DIR / "datos" / "juzgados.json")
    a.add_argument("--intervalo", type=float, default=0.5)
    a.add_argument("--verificar-auditoria", type=Path)
    a.add_argument("--forzar-bloqueo-ip", action="append", default=[], metavar="HOST",
                   help="solo para probar reclamos: pide IP para este host aunque la IP sea compartida")
    a.add_argument("--supabase-url", default=os.environ.get("SUPABASE_URL"),
                   help="publica expedientes y toma las firmas de la app (clave en SUPABASE_SERVICE_KEY)")
    args = a.parse_args()
    if args.verificar_auditoria:
        sys.exit(verificar_auditoria(args.verificar_auditoria))
    plat = Plataforma(args.simulador.rstrip("/"), args.salida, args.usuarios, args.juzgados)
    plat.forzar_ip = set(args.forzar_bloqueo_ip)
    if plat.forzar_ip:
        plat.audit.registrar("modo_prueba_reclamos", None, "sistema", forzar_bloqueo_ip=sorted(plat.forzar_ip))
    Manejador.plat = plat
    puente = None
    if args.supabase_url:
        from supabase_puente import Puente
        puente = Puente(plat, args.supabase_url, os.environ["SUPABASE_SERVICE_KEY"], plat.usuarios,
                        json.loads(args.juzgados.read_text(encoding="utf-8")))
        puente.preparar()
        print(f"Supabase conectado: {args.supabase_url}", flush=True)

    def bucle() -> None:
        while True:
            try:
                plat.ciclo()
                if puente:
                    puente.sincronizar()
            except Exception as e:  # noqa: BLE001 - el ciclo no debe morir durante el partido
                plat.audit.registrar("error_interno", plat.minuto, "sistema", error=repr(e))
                print("error:", repr(e), flush=True)
            time.sleep(args.intervalo)

    threading.Thread(target=bucle, daemon=True).start()
    print(f"Plataforma en http://0.0.0.0:{args.puerto}  (juez: /  ·  transparencia: /publico)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", args.puerto), Manejador).serve_forever()


if __name__ == "__main__":
    main()
