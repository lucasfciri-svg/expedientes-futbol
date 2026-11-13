"""Puente entre la plataforma (motor que habla con el simulador) y Supabase.

Supabase es el centro compartido con la app web del equipo:
- el motor publica cada expediente en `expedientes` (estado `en_cola_juez`) y la app lo muestra en vivo;
- los turnos del simulador se copian a `turnos`, así la RLS solo deja firmar al juez de turno;
- cuando el juez firma o rechaza desde la app, el motor toma la decisión y manda las órdenes a los proveedores
  del simulador con la firma HMAC que el simulador exige;
- el estado de cada orden en cada proveedor se escribe en `ordenes`;
- los reclamos del simulador van a `reclamos` y el juez los resuelve desde la app;
- cada evento de la auditoría local se replica en `auditoria`.

Requiere la clave service_role en la variable de entorno SUPABASE_SERVICE_KEY (nunca en el repositorio).
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import expedientes as ex

NS = uuid.UUID("4f1c9a52-6a43-4f43-9d7e-0a5b7f6c2e10")
CLAVES_DEMO = {"laura": "laura-demo-2026", "martin": "martin-demo-2026"}
DOMINIO_USUARIOS = "jueces.test"


def normalizar(v: Any) -> Any:
    """Floats enteros como int, para que el hash coincida con JSON.stringify de la app."""
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, dict):
        return {k: normalizar(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [normalizar(x) for x in v]
    return v


def estable(v: Any) -> str:
    """Igual que `stable()` de app.js: claves ordenadas, sin espacios."""
    if isinstance(v, list):
        return "[" + ",".join(estable(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + estable(v[k]) for k in sorted(v)) + "}"
    return json.dumps(v, ensure_ascii=False)


class Supabase:
    def __init__(self, url: str, clave: str):
        self.url, self.clave = url.rstrip("/"), clave

    def req(self, metodo: str, ruta: str, cuerpo: Any = None, prefer: str = "") -> Any:
        h = {"apikey": self.clave, "Authorization": f"Bearer {self.clave}", "Content-Type": "application/json"}
        if prefer:
            h["Prefer"] = prefer
        datos = json.dumps(cuerpo, ensure_ascii=False).encode() if cuerpo is not None else None
        r = urllib.request.Request(self.url + ruta, data=datos, method=metodo, headers=h)
        try:
            with urllib.request.urlopen(r, timeout=15) as x:
                txt = x.read()
                return json.loads(txt) if txt else None
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Supabase {metodo} {ruta.split('?')[0]}: {e.code} {e.read()[:300]!r}") from None

    def select(self, tabla: str, **filtros: str) -> List[dict]:
        return self.req("GET", f"/rest/v1/{tabla}?" + urllib.parse.urlencode(filtros))

    def insert(self, tabla: str, filas: Any) -> List[dict]:
        return self.req("POST", f"/rest/v1/{tabla}", filas, "return=representation")

    def upsert(self, tabla: str, filas: Any, conflicto: str) -> List[dict]:
        return self.req("POST", f"/rest/v1/{tabla}?on_conflict={conflicto}", filas,
                        "resolution=merge-duplicates,return=representation")

    def update(self, tabla: str, filtro: str, datos: dict) -> None:
        self.req("PATCH", f"/rest/v1/{tabla}?{filtro}", datos, "return=minimal")


class Puente:
    def __init__(self, plat: Any, url: str, clave: str, usuarios: Dict[str, dict], juzgados: dict):
        self.plat, self.sb = plat, Supabase(url, clave)
        self.usuarios, self.jz = usuarios, juzgados
        self.jurisdiccion = juzgados["juzgados"][0]["jurisdiccion"]
        with urllib.request.urlopen(plat.base + "/estado", timeout=10) as r:
            self.acelerar = float(json.loads(r.read()).get("acelerar") or 1)
        self.uuid_juez: Dict[str, str] = {}      # juez del simulador -> usuario de Supabase
        self.juez_sim: Dict[str, str] = {}       # inverso
        self.filas: Dict[str, str] = {}          # EXP-…/RE-… -> id de la fila en expedientes
        self.cache_ordenes: Dict[str, str] = {}
        self.resumen_publicado: Dict[str, str] = {}
        self.reclamos_publicados: Dict[str, str] = {}
        self.ultimos_turnos: Dict[str, tuple] = {}
        self.cola_audit: List[dict] = []
        self.errores: Dict[str, str] = {}
        registrar = plat.audit.registrar

        def registrar_y_replicar(evento: str, minuto: Optional[float], actor: str, **datos: Any) -> dict:
            e = registrar(evento, minuto, actor, **datos)
            self.cola_audit.append(e)
            return e
        plat.audit.registrar = registrar_y_replicar

    # -- tiempo de partido -> hora real (para turnos, kickoff y vencimientos que usa la app)
    def hora(self, minuto: float) -> str:
        t = datetime.now(timezone.utc) + timedelta(minutes=(minuto - self.plat.minuto) / self.acelerar)
        return t.isoformat(timespec="seconds")

    # -- alta de jueces (una vez)
    def preparar(self) -> None:
        existentes = {u["email"]: u["id"] for u in self.sb.req("GET", "/auth/v1/admin/users?per_page=200")["users"]}
        for usuario, u in self.usuarios.items():
            juez = self.plat.jueces[u["juez_id"]]
            email = f"{usuario}@{DOMINIO_USUARIOS}"
            uid = existentes.get(email)
            if not uid:
                uid = self.sb.req("POST", "/auth/v1/admin/users", {"email": email, "password": CLAVES_DEMO[usuario],
                                                                    "email_confirm": True})["id"]
            self.sb.upsert("jueces", {"id": uid, "nombre": juez["nombre"], "juzgado": juez["juzgado"],
                                      "contacto": email, "juez_sim_id": juez["id"]}, "id")
            self.uuid_juez[juez["id"]], self.juez_sim[uid] = uid, juez["id"]
        self.sincronizar_turnos()

    def sincronizar_turnos(self) -> None:
        filas = []
        for t in self.jz["turnos"]:
            desde, hasta = self.hora(t["desde_min"]), self.hora(t["hasta_min"])
            previo = self.ultimos_turnos.get(t["juez_id"])
            if previo and abs((datetime.fromisoformat(previo[0]) - datetime.fromisoformat(desde)).total_seconds()) < 5:
                continue
            self.ultimos_turnos[t["juez_id"]] = (desde, hasta)
            filas.append({"id": str(uuid.uuid5(NS, "turno|" + t["juez_id"])), "juez_id": self.uuid_juez[t["juez_id"]],
                          "jurisdiccion": self.jurisdiccion, "desde": desde, "hasta": hasta})
        if filas:
            self.sb.upsert("turnos", filas, "id")

    # -- ciclo
    def sincronizar(self) -> None:
        for paso in (self.sincronizar_turnos, self.publicar_expedientes, self.publicar_reenvios, self.leer_decisiones,
                     self.publicar_ordenes, self.publicar_reclamos, self.leer_reclamos, self.replicar_auditoria):
            try:
                paso()
                self.errores.pop(paso.__name__, None)
            except Exception as e:  # noqa: BLE001 - un corte de Supabase no frena el envío de órdenes
                if self.errores.get(paso.__name__) != str(e):
                    self.errores[paso.__name__] = str(e)
                    print("supabase:", paso.__name__, e, flush=True)

    def partido(self) -> dict:
        p = self.plat.arm.partido
        local, visita = p["nombre"].split("—")[-1].split(" vs. ")
        return {"id": p["id"], "home": local.strip(), "away": visita.strip(), "kickoff": self.hora(0),
                "nombre": p["nombre"], "titular": p["titular_derechos"]}

    def fila_expediente(self, numero: str, contenido: dict, objetivo: str, host: Optional[str], checks: List[dict],
                        reincidente: bool) -> dict:
        contenido = normalizar(contenido)
        partido = self.partido()
        return {"numero": numero, "exp_sim_id": numero, "partido": partido, "kickoff": partido["kickoff"],
                "jurisdiccion": self.jurisdiccion, "objetivo": objetivo, "host_video": host, "estado": "en_cola_juez",
                "consenso": {"checks": checks}, "contenido": contenido,
                "sha256": ex.sha256(estable(contenido).encode("utf-8")), "reincidente": reincidente}

    def publicar_expedientes(self) -> None:
        with self.plat.lock:
            nuevos = [(t, self.plat.resumen_item("expediente", t)) for t in self.plat.tramites.values()
                      if t["expediente_id"] not in self.filas or t["estado"] == "pendiente"]
        for t, r in nuevos:
            clave = estable(r)
            if self.resumen_publicado.get(t["expediente_id"]) == clave:
                continue
            exp = self.plat.expediente(t["expediente_id"])
            r = dict(r, juez_asignado=t["juez_asignado"])
            contenido = {"origen": "motor", "tipo": "expediente", "resumen": r,
                         "medida": {"tipo": r["pedido"]["tipo"], "objetivo": r["pedido"]["objetivo"],
                                    "vence_min": r["pedido"]["vence_min"], "hasta": self.hora(r["pedido"]["vence_min"])}}
            checks = [
                {"ok": True, "t": f"Marca de agua {r['marca']} del partido: {r['marca_detalle']}"},
                {"ok": True, "t": f"{exp['sitio']} no figura entre los licenciatarios autorizados"},
                {"ok": True, "t": f"Servidor {r['host']} → {r['ip']} (AS{r['asn']})"},
                {"ok": not r["terceros"], "t": f"Riesgo colateral: {r['colateral']}"},
                {"ok": True, "t": f"{r['evidencias']} capturas con SHA-256 encadenado"},
            ]
            fila = self.fila_expediente(t["expediente_id"], contenido, r["stream_url"], r["host"], checks,
                                        bool(t.get("reincidente")))
            if t["expediente_id"] in self.filas:
                # evidencia nueva mientras espera firma: el juez firma siempre la versión vigente (RLS compara sha256)
                self.sb.update("expedientes", f"id=eq.{self.filas[t['expediente_id']]}&estado=eq.en_cola_juez",
                               {k: fila[k] for k in ("contenido", "consenso", "sha256", "objetivo", "host_video")})
            else:
                self.filas[t["expediente_id"]] = self.sb.upsert("expedientes", fila, "numero")[0]["id"]
            self.resumen_publicado[t["expediente_id"]] = clave

    def publicar_reenvios(self) -> None:
        with self.plat.lock:
            nuevos = [r for r in self.plat.reenvios.values() if r["estado"] == "pendiente" and r["id"] not in self.filas]
        for r in nuevos:
            res = self.plat.resumen_item("reenvio", r)
            contenido = {"origen": "motor", "tipo": "reenvio", "resumen": res}
            checks = [{"ok": True, "t": f"Reenvío a {r['proveedor']}: {r['motivo']}"}]
            fila = self.fila_expediente(r["id"], contenido, r["objetivo"], None, checks, False)
            self.filas[r["id"]] = self.sb.upsert("expedientes", fila, "numero")[0]["id"]

    def leer_decisiones(self) -> None:
        with self.plat.lock:
            pend = [t["expediente_id"] for t in self.plat.tramites.values() if t["estado"] == "pendiente"]
            pend += [r["id"] for r in self.plat.reenvios.values() if r["estado"] == "pendiente"]
        pend = [p for p in pend if p in self.filas and self.errores.get("decision|" + p) != "definitivo"]
        if not pend:
            return
        filas = self.sb.select("expedientes", select="exp_sim_id,estado,firmas(juez_id,ts)",
                               exp_sim_id=f"in.({','.join(pend)})")
        for f in filas:
            ref, firmas = f["exp_sim_id"], sorted(f.get("firmas") or [], key=lambda x: x["ts"])
            if firmas:
                juez = self.juez_sim.get(firmas[0]["juez_id"])
                if ref.startswith("RE-"):
                    cod, resp = self.plat.firmar_reenvio(juez, ref)
                else:
                    cod, resp = self.plat.decidir_expediente(juez, ref, True, "Firmado por el juez desde la app")
            elif f["estado"] == "rechazado" and not ref.startswith("RE-"):
                juez = self.plat.tramites[ref]["juez_asignado"]
                cod, resp = self.plat.decidir_expediente(juez, ref, False, "Rechazado por el juez desde la app")
            else:
                continue
            if cod != 200:
                self.errores["decision|" + ref] = "definitivo"
                self.plat.audit.registrar("firma_app_no_aplicada", self.plat.minuto, "sistema", ref=ref, http=cod,
                                          error=resp.get("error"))

    def publicar_ordenes(self) -> None:
        filas = []
        with self.plat.lock:
            for t in self.plat.tramites.values():
                d = t["decision"]
                if not d or d["decision"] != "aprobado" or t["expediente_id"] not in self.filas:
                    continue
                for e in t["envios"]:
                    it = e["intentos"][-1] if e["intentos"] else {}
                    fila = {"numero": f"{t['expediente_id']}-{e['proveedor']}-{e['objetivo'] or 'no-aplica'}",
                            "expediente_id": self.filas[t["expediente_id"]], "objetivo": e["objetivo"] or "—",
                            "tipo": e["tipo"] or "ninguno", "juzgado": d["juzgado"], "proveedor": e["proveedor"],
                            "orden_sim_id": it.get("orden_id"), "vence_min": e.get("vence_min"),
                            "hasta": self.hora(e["vence_min"]) if e.get("vence_min") else None,
                            "estado_proveedor": e["estado"], "intentos": len(e["intentos"]),
                            "aplicada_min": it.get("aplicada_min"), "firmada_por": it.get("firmado_por"),
                            "levantada_at": datetime.now(timezone.utc).isoformat() if e["estado"] == "levantada" else None,
                            "origen": "motor"}
                    clave = estable({k: v for k, v in fila.items() if k not in ("hasta", "levantada_at")})
                    if self.cache_ordenes.get(fila["numero"]) != clave:
                        self.cache_ordenes[fila["numero"]] = clave
                        filas.append(fila)
        filas = list({f["numero"]: f for f in filas}.values())
        if filas:
            try:
                self.sb.upsert("ordenes", normalizar(filas), "numero")
            except Exception:
                for f in filas:
                    self.cache_ordenes.pop(f["numero"], None)
                raise

    def publicar_reclamos(self) -> None:
        with self.plat.lock:
            nuevos = [r for r in self.plat.reclamos.values() if r["id"] not in self.reclamos_publicados]
        for r in nuevos:
            fila = {"rec_sim_id": r["id"], "dominio": r["dominio"], "contacto": f"proveedor:{r['proveedor']}",
                    "motivo": r["mensaje"], "verificacion": normalizar(r["verificacion"]), "estado": "pendiente"}
            self.reclamos_publicados[r["id"]] = self.sb.upsert("reclamos", fila, "rec_sim_id")[0]["id"]

    def leer_reclamos(self) -> None:
        with self.plat.lock:
            pend = [r["id"] for r in self.plat.reclamos.values() if r["estado"] == "pendiente"]
        pend = [p for p in pend if p in self.reclamos_publicados and self.errores.get("reclamo|" + p) != "definitivo"]
        if not pend:
            return
        for f in self.sb.select("reclamos", select="rec_sim_id,estado,decidido_por", rec_sim_id=f"in.({','.join(pend)})",
                                estado="in.(aceptado,rechazado)"):
            juez = self.juez_sim.get(f["decidido_por"])
            cod, resp = self.plat.decidir_reclamo(juez, f["rec_sim_id"], f["estado"] == "aceptado")
            if cod != 200:
                self.errores["reclamo|" + f["rec_sim_id"]] = "definitivo"
                self.plat.audit.registrar("reclamo_app_no_aplicado", self.plat.minuto, "sistema", ref=f["rec_sim_id"],
                                          http=cod, error=resp.get("error"))

    def replicar_auditoria(self) -> None:
        if not self.cola_audit:
            return
        lote, self.cola_audit = self.cola_audit[:200], self.cola_audit[200:]
        filas = []
        for e in lote:
            ref = e["datos"].get("expediente_id") or e["datos"].get("ref") or e["datos"].get("id")
            filas.append({"accion": e["evento"], "expediente_id": self.filas.get(ref),
                          "detalle": json.dumps({"n": e["n"], "minuto": e["minuto"], "actor": e["actor"],
                                                 "hash_local": e["hash"], **e["datos"]}, ensure_ascii=False)})
        try:
            self.sb.insert("auditoria", filas)
        except Exception:
            self.cola_audit = lote + self.cola_audit
            raise
