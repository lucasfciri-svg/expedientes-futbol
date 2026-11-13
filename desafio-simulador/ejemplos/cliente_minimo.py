#!/usr/bin/env python3
"""Minimal client: shows how to read detections and send one signed order (stdlib only).

This is NOT a solution. It blocks blindly: it does not check the watermark, the licensees,
the collateral risk or the expiry policy, and it skips the judge's login and review. It only
shows the mechanics of the simulator API.
"""
import argparse
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

REPO_DIR = Path(__file__).resolve().parent.parent


def pedir(base: str, ruta: str, cuerpo: Optional[dict] = None) -> Any:
    datos = json.dumps(cuerpo).encode("utf-8") if cuerpo is not None else None
    req = urllib.request.Request(base + ruta, data=datos, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as err:
        return json.loads(err.read())


def firmar(clave: str, mensaje: str) -> str:
    return hmac.new(clave.encode("utf-8"), mensaje.encode("utf-8"), hashlib.sha256).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--servidor", default="http://localhost:8080")
    args = parser.parse_args()
    base = args.servidor.rstrip("/")

    partido = pedir(base, "/partido")
    print(f"Partido: {partido['nombre']} (termina en el minuto {partido['fin_min']})")

    # 1. Poll detections until the first one shows up.
    desde = -1.0
    while True:
        lote = pedir(base, f"/detecciones?desde={desde}")
        if lote["detecciones"]:
            deteccion = lote["detecciones"][0]
            break
        desde = lote["minuto_actual"]
        time.sleep(1)
    print(f"Detección {deteccion['id']} en el minuto {deteccion['minuto']}: "
          f"{deteccion['host_stream']} ({deteccion['ip_servidor']}), marca {deteccion['marca_de_agua_extraida']}")

    # 2. Sign an order as the judge on duty. Keys live only in datos/juzgados.json.
    # A real platform signs only after that judge has logged in and approved the order.
    juzgados = json.loads((REPO_DIR / "datos" / "juzgados.json").read_text(encoding="utf-8"))
    juez_id = pedir(base, "/estado")["jueces_de_turno"][0]
    juzgado, juez = next((jz, j) for jz in juzgados["juzgados"] for j in jz["jueces"] if j["id"] == juez_id)

    orden = {
        "orden_id": f"demo-{int(time.time())}",
        "expediente_id": "EXP-DEMO-1",
        "tipo": "ip",
        "objetivo": deteccion["ip_servidor"],
        "vence_min": int(partido["fin_min"]),
        "juzgado_id": juzgado["id"],
        "juez_id": juez_id,
    }
    mensaje = f"{orden['orden_id']}|{orden['tipo']}|{orden['objetivo']}|{orden['vence_min']}|{orden['juez_id']}"
    orden["firma"] = firmar(juez["clave_firma_demo"], mensaje)

    # 3. Send it to every provider and show each answer.
    for proveedor in pedir(base, "/proveedores"):
        respuesta = pedir(base, f"/proveedores/{proveedor['id']}/ordenes", orden)
        print(f"  {proveedor['nombre']}: {respuesta}")


if __name__ == "__main__":
    main()
