#!/usr/bin/env python3
"""Solo para pruebas: hace de juez contra Supabase igual que la app web (clave anon + login + RLS).

Firma los expedientes que la RLS le muestra (solo si está de turno), verificando antes que el hash
del contenido coincida, y resuelve los reclamos según la verificación del motor.
"""
import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plataforma"))
from supabase_puente import CLAVES_DEMO, DOMINIO_USUARIOS, estable  # noqa: E402


class Juez:
    def __init__(self, url, anon, usuario):
        self.url, self.anon, self.usuario = url, anon, usuario
        tok = self.req("POST", "/auth/v1/token?grant_type=password",
                       {"email": f"{usuario}@{DOMINIO_USUARIOS}", "password": CLAVES_DEMO[usuario]}, auth=False)
        self.token, self.uid = tok["access_token"], tok["user"]["id"]

    def req(self, metodo, ruta, cuerpo=None, auth=True):
        h = {"apikey": self.anon, "Content-Type": "application/json", "Prefer": "return=representation"}
        h["Authorization"] = f"Bearer {self.token if auth else self.anon}"
        r = urllib.request.Request(self.url + ruta, method=metodo, headers=h,
                                   data=json.dumps(cuerpo).encode() if cuerpo is not None else None)
        try:
            with urllib.request.urlopen(r, timeout=10) as x:
                t = x.read()
                return json.loads(t) if t else None
        except urllib.error.HTTPError as e:
            return {"error": e.code, "detalle": e.read().decode()[:200]}

    def trabajar(self, reclamos=True):
        cola = self.req("GET", "/rest/v1/expedientes?estado=eq.en_cola_juez&select=id,numero,sha256,contenido")
        for e in cola if isinstance(cola, list) else []:
            calc = hashlib.sha256(estable(e["contenido"]).encode()).hexdigest()
            if calc != e["sha256"]:
                print(self.usuario, e["numero"], "HASH NO COINCIDE", flush=True)
                continue
            f = self.req("POST", "/rest/v1/firmas", {"expediente_id": e["id"], "juez_id": self.uid, "sha256": calc,
                                                     "alg": "prueba", "firma": "firma-de-prueba"})
            if isinstance(f, dict) and f.get("error"):
                print(self.usuario, e["numero"], "firma rechazada por RLS", f, flush=True)
                continue
            self.req("PATCH", f"/rest/v1/expedientes?id=eq.{e['id']}", {"estado": "firmado"})
            self.req("POST", "/rest/v1/auditoria", {"accion": "firma", "expediente_id": e["id"],
                                                    "detalle": f"{e['numero']} firmado por {self.usuario}"})
            print(self.usuario, "firmó", e["numero"], flush=True)
        if not reclamos:
            return
        recs = self.req("GET", "/rest/v1/reclamos?estado=eq.pendiente&rec_sim_id=not.is.null&select=id,rec_sim_id,verificacion")
        for r in recs if isinstance(recs, list) else []:
            estado = "aceptado" if (r["verificacion"] or {}).get("valido") else "rechazado"
            self.req("PATCH", f"/rest/v1/reclamos?id=eq.{r['id']}", {"estado": estado, "decidido_por": self.uid,
                                                                    "decidido_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            print(self.usuario, "reclamo", r["rec_sim_id"], estado, flush=True)


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--supabase-url", required=True)
    a.add_argument("--anon", required=True)
    a.add_argument("--simulador", default="http://localhost:8080")
    a.add_argument("--demora", type=float, default=0.5, help="segundos reales antes de firmar")
    a.add_argument("--sin-reclamos", action="store_true", help="deja los reclamos para resolver desde la app")
    args = a.parse_args()
    jueces = [Juez(args.supabase_url, args.anon, u) for u in ("laura", "martin")]
    while True:
        for j in jueces:
            j.trabajar(not args.sin_reclamos)
        try:
            with urllib.request.urlopen(args.simulador + "/estado", timeout=5) as x:
                if json.loads(x.read())["finalizado"]:
                    time.sleep(5)
                    for j in jueces:
                        j.trabajar(not args.sin_reclamos)
                    return
        except OSError:
            pass
        time.sleep(args.demora)


if __name__ == "__main__":
    main()
