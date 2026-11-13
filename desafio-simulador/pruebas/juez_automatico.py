#!/usr/bin/env python3
"""Solo para pruebas: simula a los jueces usando la misma API que la interfaz web.

Cada juez inicia sesión con su usuario y contraseña y aprueba lo que tiene pendiente.
También intenta firmar fuera de turno para comprobar que la plataforma lo rechaza.
"""
import argparse
import http.cookiejar
import json
import time
import urllib.error
import urllib.request

USUARIOS = {"laura": "laura-demo-2026", "martin": "martin-demo-2026"}


class Sesion:
    def __init__(self, base, usuario, clave):
        self.base = base
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        print(usuario, "login:", self.post("/api/login", {"usuario": usuario, "clave": clave}))

    def req(self, ruta, cuerpo=None):
        r = urllib.request.Request(self.base + ruta, data=json.dumps(cuerpo).encode() if cuerpo is not None else None,
                                   headers={"Content-Type": "application/json"})
        try:
            with self.op.open(r, timeout=10) as x:
                return x.status, json.loads(x.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    post = req


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--plataforma", default="http://localhost:8090")
    a.add_argument("--demora", type=float, default=1.0, help="segundos reales que tarda el juez en revisar")
    a.add_argument("--ausente", help="usuario que no atiende sus pendientes (para probar el cambio de turno)")
    args = a.parse_args()
    print("login con clave incorrecta:", Sesion(args.plataforma, "laura", "mal").req("/api/yo")[0])
    s = {u: Sesion(args.plataforma, u, c) for u, c in USUARIOS.items()}
    probado_fuera = False
    while True:
        for u, ses in s.items():
            cod, yo = ses.req("/api/yo")
            if cod != 200:
                continue
            for p in ([] if u == args.ausente else yo["pendientes"]):
                time.sleep(args.demora)
                if p["tipo"] == "expediente":
                    r = ses.post(f"/api/expedientes/{p['id']}/decision", {"decision": "aprobar",
                                 "motivo": "Señal oficial verificada; pedido proporcional según riesgo colateral."})
                elif p["tipo"] == "reenvio":
                    r = ses.post(f"/api/reenvios/{p['id']}/firmar", {})
                else:
                    r = ses.post(f"/api/reclamos/{p['id']}/decision",
                                 {"decision": "aceptar" if p["verificacion"]["valido"] else "rechazar"})
                print(f"[min {yo['minuto']}] {u} {p['tipo']} {p['id']}: {r}", flush=True)
            if not yo["de_turno"] and not probado_fuera and u == "laura":
                otro = s["martin"].req("/api/yo")[1]["pendientes"]
                if otro:
                    print("laura fuera de turno intenta firmar:",
                          ses.post(f"/api/expedientes/{otro[0]['id']}/decision", {"decision": "aprobar"}), flush=True)
                    probado_fuera = True
        time.sleep(0.5)


if __name__ == "__main__":
    main()
