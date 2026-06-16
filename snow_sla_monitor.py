#!/usr/bin/env python3
"""
snow_sla_monitor.py — Surveillance SLA ServiceNow
Alerte Teams quand un ticket ITASK du groupe OPS-APP-FUTURMASTER-WW-RC
dépasse 50 % de SLA consommé sur l'incident parent.

Secrets GitHub Actions requis :
  SNOW_USER              → username ServiceNow (ex: ar259797)
  SNOW_PASS              → password ServiceNow
  SNOW_TEAMS_WEBHOOK_URL → URL Power Automate webhook (canal SLA Alerts)
"""

import json
import os
import time
from datetime import datetime, timezone

import requests

# ── Configuration ────────────────────────────────────────────────────────────
SNOW_BASE_URL  = os.environ.get("SNOW_BASE_URL", "https://marsprod.service-now.com")
SNOW_USER      = os.environ["SNOW_USER"]
SNOW_PASS      = os.environ["SNOW_PASS"]
TEAMS_WEBHOOK  = os.environ["SNOW_TEAMS_WEBHOOK_URL"]

ASSIGNMENT_GROUP_SYS_ID = "d21611fcdbc177c878c93978f496193f"  # OPS-APP-FUTURMASTER-WW-RC
SLA_THRESHOLD  = 50.0   # % à partir duquel on alerte
STATE_FILE     = "snow_sla_state.json"

# ── Session ServiceNow ───────────────────────────────────────────────────────
_session = requests.Session()
_session.auth = (SNOW_USER, SNOW_PASS)
_session.headers.update({
    "Accept": "application/json",
    "Content-Type": "application/json",
})


def snow_get(table: str, params: dict) -> list:
    """GET sur /api/now/table/<table> — lève une exception si erreur HTTP."""
    url = f"{SNOW_BASE_URL}/api/now/table/{table}"
    r = _session.get(url, params=params, timeout=30)
    r.raise_for_status()
    return r.json().get("result", [])


# ── Récupération des tickets ─────────────────────────────────────────────────

def get_active_itasks() -> list:
    """Retourne les ITASKs actifs du groupe avec sys_id du parent INC."""
    return snow_get("u_incident_task", {
        "sysparm_query": (
            f"active=true"
            f"^assignment_group={ASSIGNMENT_GROUP_SYS_ID}"
        ),
        "sysparm_fields": "number,sys_id,parent,short_description,priority,subcategory",
        "sysparm_display_value": "all",  # value = sys_id, display_value = texte
        "sysparm_limit": "100",
    })


def get_slas_for_inc(inc_sys_id: str) -> list:
    """Retourne les SLAs actifs d'un incident donné (par son sys_id)."""
    return snow_get("task_sla", {
        "sysparm_query": f"task={inc_sys_id}^type=sla^active=true",
        "sysparm_fields": "percentage,stage,has_breached,sla.name",
        "sysparm_display_value": "true",
        "sysparm_limit": "10",
    })


# ── Extraction des valeurs (format display_value=all) ───────────────────────

def _val(field) -> str:
    """Extrait la valeur brute (sys_id) d'un champ display_value=all."""
    if isinstance(field, dict):
        return field.get("value", "") or ""
    return str(field) if field else ""


def _disp(field) -> str:
    """Extrait la valeur affichable d'un champ display_value=all."""
    if isinstance(field, dict):
        return field.get("display_value", "") or ""
    return str(field) if field else ""


# ── State (évite les doublons d'alertes) ────────────────────────────────────

def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {"alerted": {}}


def save_state(state: dict) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


# ── Envoi Teams (Power Automate webhook) ────────────────────────────────────

def send_teams_alert(
    itask_number: str,
    task_sys_id: str,
    inc_number: str,
    short_desc: str,
    priority: str,
    subcategory: str,
    percentage: float,
    sla_name: str,
) -> bool:
    """Envoie une carte d'alerte SLA dans Teams via Power Automate webhook."""
    # Lien direct vers l'ITASK (ouverture immédiate du ticket)
    itask_url = f"{SNOW_BASE_URL}/u_incident_task.do?sys_id={task_sys_id}"

    # Format texte compatible Power Automate webhook
    subcat_line = f"Sous-catégorie : {subcategory}\n" if subcategory else ""
    text = (
        f"🚨 Alerte SLA — {itask_number}\n\n"
        f"Incident parent : {inc_number}\n"
        f"Description : {short_desc[:200]}\n"
        f"{subcat_line}"
        f"Priorité : {priority}\n"
        f"SLA consommé : {percentage:.1f}% — {sla_name}\n\n"
        f"👉 Ouvrir l'ITASK : {itask_url}"
    )

    try:
        r = requests.post(TEAMS_WEBHOOK, json={"text": text}, timeout=15)
        ok = r.status_code in (200, 201, 202, 204)
        print(
            f"  Teams {'OK' if ok else 'ERR'} ({r.status_code}) — {itask_number}",
            flush=True,
        )
        return ok
    except Exception as exc:
        print(f"  Teams ERR — {itask_number} : {exc}", flush=True)
        return False


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print(
        f"[{datetime.now(timezone.utc).isoformat()}] Démarrage snow_sla_monitor",
        flush=True,
    )

    state   = load_state()
    alerted = state.setdefault("alerted", {})

    itasks = get_active_itasks()
    print(f"  {len(itasks)} ITASK(s) actif(s) trouvé(s)", flush=True)

    alerts_sent = 0

    for task in itasks:
        number       = _disp(task.get("number"))
        task_sys_id  = _val(task.get("sys_id"))
        parent_sys   = _val(task.get("parent"))
        inc_number   = _disp(task.get("parent"))
        short_desc   = _disp(task.get("short_description"))
        priority     = _disp(task.get("priority"))
        subcategory  = _disp(task.get("subcategory"))

        if not number:
            continue

        if number in alerted:
            print(f"  {number}: déjà alerté le {alerted[number]}, skip", flush=True)
            continue

        if not parent_sys:
            print(f"  {number}: aucun incident parent, skip", flush=True)
            continue

        # Récupère les SLAs de l'incident parent
        slas = get_slas_for_inc(parent_sys)
        time.sleep(0.5)  # Rate limiting léger

        # Trouve le SLA avec le pourcentage le plus élevé
        worst_pct  = 0.0
        worst_name = ""
        for sla in slas:
            try:
                pct = float(sla.get("percentage", 0) or 0)
            except (ValueError, TypeError):
                pct = 0.0
            if pct > worst_pct:
                worst_pct  = pct
                worst_name = sla.get("sla.name", "")

        print(
            f"  {number} ({inc_number}): SLA max = {worst_pct:.1f}%",
            flush=True,
        )

        if worst_pct >= SLA_THRESHOLD:
            sent = send_teams_alert(
                number, task_sys_id, inc_number, short_desc,
                priority, subcategory, worst_pct, worst_name
            )
            if sent:
                alerted[number] = datetime.now(timezone.utc).isoformat()
                alerts_sent += 1

    # Nettoie les tickets qui ne sont plus dans la liste active
    # (ticket clôturé → reset pour future alerte si réouvert)
    active_numbers = {_disp(t.get("number")) for t in itasks}
    closed = [n for n in list(alerted) if n not in active_numbers]
    for n in closed:
        print(f"  {n}: plus actif, reset état", flush=True)
        del alerted[n]

    save_state(state)
    print(f"  Terminé. {alerts_sent} alerte(s) envoyée(s).", flush=True)


if __name__ == "__main__":
    main()
