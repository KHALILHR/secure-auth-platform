"""Configuration de l'infrastructure vérifiée sans conteneur (T22, T23, T24 côté fichiers, ENF-08, ENF-09).

Ces tests lisent nginx.conf, docker-compose.yml, le Dockerfile et .gitignore : ils garantissent
que la configuration LIVRÉE respecte le cahier des charges. La vérification du serveur en marche
(openssl s_client, curl -I, docker compose ps) est décrite dans docs/tests-securite.md.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
NGINX = (ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
DOCKERFILE = (ROOT / "app" / "Dockerfile").read_text(encoding="utf-8")
GITIGNORE = (ROOT / ".gitignore").read_text(encoding="utf-8")


# --- Nginx : TLS et en-têtes ---------------------------------------------------------------------

def test_only_modern_tls_versions():
    """T22 : TLS 1.1 et inférieurs refusés (la directive n'autorise que 1.2 et 1.3)."""
    directives = re.findall(r"^\s*ssl_protocols\s+([^;]+);", NGINX, re.M)
    assert directives == ["TLSv1.2 TLSv1.3"]


def test_http_redirects_to_https():
    assert re.search(r"listen 80;.*?return 301 https://", NGINX, re.S)


@pytest.mark.parametrize("header", ["X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
                                    "Content-Security-Policy", "Strict-Transport-Security"])
def test_security_headers_are_declared(header):
    """T23 : tous les en-têtes de sécurité sont présents (et pas seulement en commentaire)."""
    assert re.search(rf'^\s*add_header {header} ".+" always;', NGINX, re.M)


def test_csp_forbids_inline_and_framing():
    csp = re.search(r'add_header Content-Security-Policy "([^"]+)"', NGINX).group(1)
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


def test_server_tokens_off_and_real_ip_forwarded_without_spoofing():
    assert "server_tokens off;" in NGINX
    assert "proxy_set_header X-Forwarded-For   $remote_addr;" in NGINX  # jamais $proxy_add_x_forwarded_for


def test_nginx_rate_limits_the_login_form():
    assert "limit_req_zone" in NGINX and "limit_req_status 429;" in NGINX


def test_nginx_body_limit_is_raised_only_for_the_upload_page():
    """2 Mo partout ; 10 Mo (> 8 Mo de fichier + formulaire côté application) pour le seul dépôt de fichier."""
    from secureauth.documents.uploads import REQUEST_MAX_BYTES

    assert re.findall(r"^\s*client_max_body_size\s+(\S+);", NGINX, re.M) == ["2m", "10m"]
    block = re.search(r"location = /documents/upload \{(.*?)\n    \}", NGINX, re.S).group(1)
    assert "client_max_body_size 10m;" in block and "proxy_pass http://app:8000;" in block
    assert REQUEST_MAX_BYTES < 10 * 1024 * 1024


# --- Docker : ports, réseaux, privilèges ------------------------------------------------------------------

SERVICES = COMPOSE["services"]


def test_only_nginx_publishes_ports():
    """T24 : MariaDB (3306) et Redis (6379) ne sont joignables ni depuis l'hôte ni depuis Internet."""
    assert set(SERVICES["nginx"]["ports"]) == {"80:80", "443:443"}
    for name in ("app", "db", "redis"):
        assert "ports" not in SERVICES[name], f"{name} ne doit publier aucun port"


def test_backend_network_is_internal_and_holds_data_services():
    assert COMPOSE["networks"]["backend"]["internal"] is True
    assert SERVICES["db"]["networks"] == ["backend"] and SERVICES["redis"]["networks"] == ["backend"]
    assert set(SERVICES["app"]["networks"]) == {"frontend", "backend"}
    assert SERVICES["nginx"]["networks"] == ["frontend"]


def test_app_never_receives_the_database_root_password():
    env = SERVICES["app"]["environment"]
    assert "DB_ROOT_PASSWORD" not in str(env) and "MARIADB_ROOT_PASSWORD" not in str(env)


def test_no_secret_is_hardcoded_in_compose():
    for service in SERVICES.values():
        for value in (service.get("environment") or {}).values():
            assert str(value).startswith("${") or "${" in str(value), f"valeur en dur : {value}"


def test_app_container_is_hardened():
    app = SERVICES["app"]
    assert "no-new-privileges:true" in app["security_opt"]
    assert app["cap_drop"] == ["ALL"] and app["read_only"] is True
    assert "USER appuser" in DOCKERFILE and "--workers" in DOCKERFILE


def test_every_service_has_a_healthcheck_or_depends_on_one():
    for name in ("app", "db", "redis"):
        assert "healthcheck" in SERVICES[name], name


# --- Dépôt : secrets --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("entry", [".env", "pki/", "nginx/certs/"])
def test_secrets_and_pki_are_gitignored(entry):
    assert entry in GITIGNORE.splitlines()
