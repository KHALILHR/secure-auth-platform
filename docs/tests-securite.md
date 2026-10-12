# Tests de sécurité : 30 cas, résultats et preuves

Les cas T01 à T25 viennent de la section 12 du cahier des charges ; **T26 à T30 ont été ajoutés** pour les comptes créés par l'administrateur et le dépôt de fichiers. Chacun est vérifié de **deux manières** :

1. **Tests automatiques** (`cd app && python -m pytest -q`) : SQLite en mémoire et Redis simulé, aucun conteneur.
2. **Script contre les vrais services** (`python scripts/live_checks.py ...`) : HTTPS, Nginx, MariaDB et Redis en marche, avec attaques directes en base. Sortie complète : [`preuves/live-checks.txt`](preuves/live-checks.txt).

> **Burp Suite.** Le script rejoue les requêtes qu'on ferait à la main dans Burp (Repeater, Intruder), mais ne remplace pas les captures d'écran Burp demandées pour le rapport final. Procédure de chaque cas dans la colonne « Burp » ci-dessous ; chaque capture est à ranger dans `docs/preuves/` sous le nom `Txx-burp.png`.

## Synthèse

| ID | Catégorie | Scénario | Outil | Résultat attendu | Résultat obtenu |
|---|---|---|---|---|---|
| T01 | Authentification | Compte inexistant vs mauvais mot de passe | pytest, script, Burp Repeater | Même message, durée comparable | conforme (automatique + services réels) |
| T02 | Authentification | 6 échecs consécutifs puis le bon mot de passe | pytest, script | Compte verrouillé 15 min, même message | conforme (automatique + services réels) |
| T03 | Authentification | Injection SQL dans le formulaire (et les autres entrées) | pytest, script, Burp Intruder | Échec normal, aucune erreur SQL | conforme (automatique + services réels) |
| T04 | Session | Drapeaux du cookie de session | outils développeur, script | Secure, HttpOnly, SameSite=Lax, préfixe __Host- | conforme (automatique + services réels) |
| T05 | Session | Identifiant avant / après connexion | outils développeur, script | Identifiant différent | conforme (automatique + services réels) |
| T06 | Session | Rejouer un cookie après déconnexion | Burp Repeater, script | Redirection vers la connexion | conforme (automatique + services réels) |
| T07 | Session | Inactivité supérieure à 30 minutes | manuel, pytest | Session expirée | partiel : durée absolue testée, expiration du cookie et du jeton Redis vérifiée à 30 min ; attente réelle de 30 min non rejouée |
| T08 | CSRF | POST sans jeton | pytest, script, Burp | HTTP 400 | conforme (automatique + services réels) |
| T09 | Autorisation | Agent SECRET vers un document TRÈS SECRET | pytest, script, Burp | 404 + DOC_ACCESS_DENIED | conforme (automatique + services réels) |
| T10 | Autorisation | Habilitation suffisante mais hors liste d'accès | pytest, script, Burp | 404 | conforme (automatique + services réels) |
| T11 | Autorisation | IDOR : identifiant d'un autre document | pytest, script, Burp Repeater | 404 identique à un document inexistant | conforme (automatique + services réels) |
| T12 | Autorisation | L'administrateur tente de lire un document | pytest, script | 404 | conforme (automatique + services réels) |
| T13 | Autorisation | L'administrateur s'attribue un accès ou modifie sa propre habilitation | pytest, script | Refus + ADMIN_SELF_MODIFY_DENIED | conforme (automatique + services réels) |
| T14 | Autorisation | Un agent appelle une route /admin/* | pytest, script, Burp | 403 | conforme (automatique + services réels) |
| T15 | Autorisation | Habilitation abaissée après attribution | pytest, script | Accès perdu immédiatement | conforme (automatique + services réels) |
| T16 | Autorisation | Création au-dessus de son habilitation (champ modifié) | pytest, script, Burp | Refus | conforme (automatique + services réels) |
| T17 | Cryptographie | Classification modifiée directement en base | SQL + application | Déchiffrement impossible + INTEGRITY_FAILURE | conforme (automatique + services réels) |
| T18 | Cryptographie | Lecture des documents directement en base | SQL | Uniquement du binaire illisible | conforme (automatique + services réels) |
| T19 | Intégrité | Ligne du journal modifiée en base | SQL + verify-audit | Ligne signalée | conforme (automatique + services réels) |
| T20 | Intégrité | Ligne du journal supprimée (milieu ou fin) | SQL + verify-audit | Rupture détectée | conforme (tests automatiques) ; non rejoué sur la base réelle pour ne pas détruire sa chaîne |
| T21 | XSS | Balise de script dans un titre de document | navigateur, pytest | Affichée comme texte, bloquée par la CSP | conforme (automatique + services réels) |
| T22 | Transport | Connexion en TLS 1.1 | openssl s_client | Refusée | conforme (automatique + services réels) |
| T23 | Transport | En-têtes de sécurité | curl -I | Tous présents | conforme (automatique + services réels) |
| T24 | Infrastructure | Accès direct aux ports 3306 et 6379 | docker compose ps | Injoignables depuis l'hôte | conforme (automatique + services réels) |
| T25 | Force brute | Rafale de connexions | Burp Intruder, script | HTTP 429 après le seuil | conforme (automatique + services réels) |
| T26 | Comptes | L'administrateur ajoute un agent ; l'agent ouvre le formulaire ; première connexion | pytest, script, Burp Repeater | Agent refusé (403) ; compte créé avec mot de passe provisoire ; changement imposé ; USER_CREATE sans mot de passe | conforme (automatique + services réels) |
| T27 | Fichiers | Dépôt d'un PDF de 3 Mo puis lecture directe de la colonne en base | pytest, script, SQL | Binaire illisible, ni contenu ni nom en clair ; téléchargement identique en pièce jointe | conforme (automatique + services réels) |
| T28 | Fichiers | Téléchargement hors liste d'accès, après partage, puis classification modifiée en base | pytest, script, SQL | 404 + DOC_ACCESS_DENIED ; 200 après partage ; 500 + INTEGRITY_FAILURE après falsification | conforme (automatique + services réels) |
| T29 | Fichiers | Faux PDF, exécutable, page HTML, fichier de 11 Mo, corps de 3 Mo sur une autre page | pytest, script, Burp Repeater | 400 pour les fichiers invalides, 413 pour les envois trop gros, rien d'enregistré | conforme (automatique + services réels) |
| T30 | Fichiers | L'administrateur dépose un document TRÈS SECRET puis tente de le lire | pytest, script, Burp Repeater | Dépôt accepté, redirection vers le partage, lecture et téléchargement refusés (404), partage seulement aux agents habilités | conforme (automatique + services réels) |

## Détail par cas

### T01 : Compte inexistant vs mauvais mot de passe

- **Catégorie** : Authentification
- **Outil** : pytest, script, Burp Repeater
- **Résultat attendu** : Même message, durée comparable
- **Test automatique** : `test_auth_flow::test_unknown_account_and_wrong_password_look_identical ; test_lockout::test_locked_message_is_identical_to_wrong_password`
- **Contrôle sur les vrais services** : conforme : même message=True, médianes 97 ms / 83 ms

### T02 : 6 échecs consécutifs puis le bon mot de passe

- **Catégorie** : Authentification
- **Outil** : pytest, script
- **Résultat attendu** : Compte verrouillé 15 min, même message
- **Test automatique** : `test_lockout.py (7 tests)`
- **Contrôle sur les vrais services** : conforme : 200, message générique=True

### T03 : Injection SQL dans le formulaire (et les autres entrées)

- **Catégorie** : Authentification
- **Outil** : pytest, script, Burp Intruder
- **Résultat attendu** : Échec normal, aucune erreur SQL
- **Test automatique** : `test_injection.py (19 tests)`
- **Contrôle sur les vrais services** : conforme : 200, message générique=True

### T04 : Drapeaux du cookie de session

- **Catégorie** : Session
- **Outil** : outils développeur, script
- **Résultat attendu** : Secure, HttpOnly, SameSite=Lax, préfixe __Host-
- **Test automatique** : `test_auth_flow::test_session_cookie_flags`
- **Contrôle sur les vrais services** : conforme : Expires=Sun, 11 Oct 2026 23:33:59 GMT; Secure; HttpOnly; Path=/; SameS

### T05 : Identifiant avant / après connexion

- **Catégorie** : Session
- **Outil** : outils développeur, script
- **Résultat attendu** : Identifiant différent
- **Test automatique** : `test_auth_flow::test_session_id_changes_at_login`
- **Contrôle sur les vrais services** : conforme : 6YOsOgTy… -> RQa7rzX4…

### T06 : Rejouer un cookie après déconnexion

- **Catégorie** : Session
- **Outil** : Burp Repeater, script
- **Résultat attendu** : Redirection vers la connexion
- **Test automatique** : `test_auth_flow::test_logout_destroys_session_server_side`
- **Contrôle sur les vrais services** : conforme : 302 /auth/login?next=/documents/

### T07 : Inactivité supérieure à 30 minutes

- **Catégorie** : Session
- **Outil** : manuel, pytest
- **Résultat attendu** : Session expirée
- **Test automatique** : `test_decorators::test_session_beyond_absolute_lifetime_is_rejected (durée absolue 8 h) ; l'inactivité de 30 min repose sur l'expiration du cookie et de la clé Redis (vérifiée), l'attente réelle de 30 min reste à faire à la main`
- **Contrôle sur les vrais services** : conforme : Sun, 11 Oct 2026 23:33:59 GMT

### T08 : POST sans jeton

- **Catégorie** : CSRF
- **Outil** : pytest, script, Burp
- **Résultat attendu** : HTTP 400
- **Test automatique** : `test_auth_flow::test_post_without_csrf_token_is_rejected ; test_documents::test_create_without_csrf_token_is_rejected ; test_admin::test_admin_post_without_csrf_is_rejected`
- **Contrôle sur les vrais services** : conforme : 400

### T09 : Agent SECRET vers un document TRÈS SECRET

- **Catégorie** : Autorisation
- **Outil** : pytest, script, Burp
- **Résultat attendu** : 404 + DOC_ACCESS_DENIED
- **Test automatique** : `test_documents::test_read_up_gives_404_and_is_logged`
- **Contrôle sur les vrais services** : conforme : 404

### T10 : Habilitation suffisante mais hors liste d'accès

- **Catégorie** : Autorisation
- **Outil** : pytest, script, Burp
- **Résultat attendu** : 404
- **Test automatique** : `test_documents::test_need_to_know_gives_404`
- **Contrôle sur les vrais services** : conforme : 404

### T11 : IDOR : identifiant d'un autre document

- **Catégorie** : Autorisation
- **Outil** : pytest, script, Burp Repeater
- **Résultat attendu** : 404 identique à un document inexistant
- **Test automatique** : `test_documents::test_idor_other_document_unknown_uuid_and_garbage_all_look_the_same`
- **Contrôle sur les vrais services** : conforme : 404 / 404 / 404

### T12 : L'administrateur tente de lire un document

- **Catégorie** : Autorisation
- **Outil** : pytest, script
- **Résultat attendu** : 404
- **Test automatique** : `test_documents::test_admin_cannot_read_any_document`
- **Contrôle sur les vrais services** : conforme : 404

### T13 : L'administrateur s'attribue un accès ou modifie sa propre habilitation

- **Catégorie** : Autorisation
- **Outil** : pytest, script
- **Résultat attendu** : Refus + ADMIN_SELF_MODIFY_DENIED
- **Test automatique** : `test_documents::test_admin_cannot_grant_himself_access ; test_admin::test_admin_cannot_modify_own_clearance_or_status`
- **Contrôle sur les vrais services** : conforme : refusé

### T14 : Un agent appelle une route /admin/*

- **Catégorie** : Autorisation
- **Outil** : pytest, script, Burp
- **Résultat attendu** : 403
- **Test automatique** : `test_admin::test_agent_gets_403_on_every_admin_route`
- **Contrôle sur les vrais services** : conforme : 403

### T15 : Habilitation abaissée après attribution

- **Catégorie** : Autorisation
- **Outil** : pytest, script
- **Résultat attendu** : Accès perdu immédiatement
- **Test automatique** : `test_admin::test_clearance_change_is_logged_and_immediate`
- **Contrôle sur les vrais services** : conforme : 404

### T16 : Création au-dessus de son habilitation (champ modifié)

- **Catégorie** : Autorisation
- **Outil** : pytest, script, Burp
- **Résultat attendu** : Refus
- **Test automatique** : `test_documents::test_forged_classification_is_refused`
- **Contrôle sur les vrais services** : conforme : 403

### T17 : Classification modifiée directement en base

- **Catégorie** : Cryptographie
- **Outil** : SQL + application
- **Résultat attendu** : Déchiffrement impossible + INTEGRITY_FAILURE
- **Test automatique** : `test_documents::test_tampered_classification_blocks_decryption ; test_crypto::test_associated_data_is_sealed`
- **Contrôle sur les vrais services** : conforme : HTTP 500, 3 ligne(s) INTEGRITY_FAILURE

### T18 : Lecture des documents directement en base

- **Catégorie** : Cryptographie
- **Outil** : SQL
- **Résultat attendu** : Uniquement du binaire illisible
- **Test automatique** : `test_crypto::test_database_holds_only_ciphertext`
- **Contrôle sur les vrais services** : conforme : nonce+ciphertext = TS-001	C78FA13D28045295BD941039	C402267B13D7D4FB670676CFB1D8…

### T19 : Ligne du journal modifiée en base

- **Catégorie** : Intégrité
- **Outil** : SQL + verify-audit
- **Résultat attendu** : Ligne signalée
- **Test automatique** : `test_audit.py (modifications) ; test_admin::test_verify_page_designates_the_tampered_line`
- **Contrôle sur les vrais services** : conforme : Chaîne intègre

### T20 : Ligne du journal supprimée (milieu ou fin)

- **Catégorie** : Intégrité
- **Outil** : SQL + verify-audit
- **Résultat attendu** : Rupture détectée
- **Test automatique** : `test_audit.py (suppressions) ; test_admin::test_verify_page_detects_deleted_line`
- **Contrôle sur les vrais services** : —

### T21 : Balise de script dans un titre de document

- **Catégorie** : XSS
- **Outil** : navigateur, pytest
- **Résultat attendu** : Affichée comme texte, bloquée par la CSP
- **Test automatique** : `test_documents::test_stored_xss_is_escaped_everywhere`
- **Contrôle sur les vrais services** : conforme : échappée (&lt;script&gt;)

### T22 : Connexion en TLS 1.1

- **Catégorie** : Transport
- **Outil** : openssl s_client
- **Résultat attendu** : Refusée
- **Test automatique** : `test_infra::test_only_modern_tls_versions`
- **Contrôle sur les vrais services** : conforme : TLSv1.2 / TLSv1.3

### T23 : En-têtes de sécurité

- **Catégorie** : Transport
- **Outil** : curl -I
- **Résultat attendu** : Tous présents
- **Test automatique** : `test_infra::test_security_headers_are_declared`
- **Contrôle sur les vrais services** : conforme : tous présents

### T24 : Accès direct aux ports 3306 et 6379

- **Catégorie** : Infrastructure
- **Outil** : docker compose ps
- **Résultat attendu** : Injoignables depuis l'hôte
- **Test automatique** : `test_infra::test_only_nginx_publishes_ports ; test_infra::test_backend_network_is_internal_and_holds_data_services`
- **Contrôle sur les vrais services** : conforme : ports publiés : [] ; localhost:3306 répond (autre service de la machine, pas le conteneur)

### T25 : Rafale de connexions

- **Catégorie** : Force brute
- **Outil** : Burp Intruder, script
- **Résultat attendu** : HTTP 429 après le seuil
- **Test automatique** : `test_ratelimit.py (6 tests)`
- **Contrôle sur les vrais services** : conforme : codes [200, 200, 200]…[429, 429, 429], premier 429 à la requête n°11

### T26 : L'administrateur ajoute un agent ; l'agent ouvre le formulaire ; première connexion

- **Catégorie** : Comptes
- **Outil** : pytest, script, Burp Repeater
- **Résultat attendu** : Agent refusé (403) ; compte créé avec mot de passe provisoire ; changement imposé ; USER_CREATE sans mot de passe
- **Test automatique** : `test_admin_users.py (création, refus, mot de passe provisoire, champ rôle forgé, migration de schéma)`
- **Contrôle sur les vrais services** : conforme : 403

### T27 : Dépôt d'un PDF de 3 Mo puis lecture directe de la colonne en base

- **Catégorie** : Fichiers
- **Outil** : pytest, script, SQL
- **Résultat attendu** : Binaire illisible, ni contenu ni nom en clair ; téléchargement identique en pièce jointe
- **Test automatique** : `test_upload::test_upload_then_download_returns_the_same_bytes ; test_upload::test_file_and_filename_are_encrypted_in_database`
- **Contrôle sur les vrais services** : conforme : 302 /documents/4df3ab32-08bd-4309-97cc-a66989471b5d

### T28 : Téléchargement hors liste d'accès, après partage, puis classification modifiée en base

- **Catégorie** : Fichiers
- **Outil** : pytest, script, SQL
- **Résultat attendu** : 404 + DOC_ACCESS_DENIED ; 200 après partage ; 500 + INTEGRITY_FAILURE après falsification
- **Test automatique** : `test_upload::test_need_to_know_applies_to_downloads ; test_upload::test_read_up_is_not_possible_with_a_file ; test_upload::test_downgrading_the_classification_of_a_file_blocks_the_download ; test_upload::test_tampered_file_blob_is_detected`
- **Contrôle sur les vrais services** : conforme : 404, 1 refus journalisé(s)

### T29 : Faux PDF, exécutable, page HTML, fichier de 11 Mo, corps de 3 Mo sur une autre page

- **Catégorie** : Fichiers
- **Outil** : pytest, script, Burp Repeater
- **Résultat attendu** : 400 pour les fichiers invalides, 413 pour les envois trop gros, rien d'enregistré
- **Test automatique** : `test_upload::test_invalid_uploads_are_refused_and_logged ; test_upload::test_request_far_over_the_limit_gets_413 ; test_upload::test_large_bodies_are_still_refused_on_every_other_page ; test_infra::test_nginx_body_limit_is_raised_only_for_the_upload_page`
- **Contrôle sur les vrais services** : conforme : {'faux PDF (texte déguisé)': 400, 'exécutable .exe': 400, 'page .html': 400}

### T30 : L'administrateur dépose un document TRÈS SECRET puis tente de le lire

- **Catégorie** : Fichiers
- **Outil** : pytest, script, Burp Repeater
- **Résultat attendu** : Dépôt accepté, redirection vers le partage, lecture et téléchargement refusés (404), partage seulement aux agents habilités
- **Test automatique** : `test_upload::test_admin_can_upload_at_any_classification_but_cannot_read_it ; test_upload::test_admin_uploads_then_shares_with_a_cleared_agent_only ; test_admin_users::test_creation_levels_per_role`
- **Contrôle sur les vrais services** : conforme : 302 /documents/87fd9b5e-50db-492a-ac07-a8197a0c54f8/access

## Procédures Burp Suite (captures à réaliser)

Proxy Burp sur `127.0.0.1:8080`, navigateur configuré sur ce proxy, certificat de la CA Burp importé. Cible : `https://localhost`.

| ID | Procédure |
|---|---|
| T01 | Repeater : envoyer `POST /auth/login` avec un identifiant inconnu, puis avec `alice` et un mauvais mot de passe. Comparer message et colonne *Response received* (durée). |
| T02 | Intruder : 6 requêtes avec un compte jetable puis la bonne. Attendu : toujours « Identifiants invalides ». |
| T03 | Intruder avec la liste de charges SQLi sur `identifier`. Attendu : 200 et message générique, jamais 500. |
| T06 | Proxy : copier le cookie `__Host-sid`, se déconnecter, le rejouer dans Repeater sur `GET /documents/`. Attendu : 302 vers `/auth/login`. |
| T08 | Repeater : supprimer le champ `csrf_token` d'un POST. Attendu : 400. |
| T09 à T12 | Repeater : rejouer `GET /documents/<uuid>` avec la session de bob, puis de l'administrateur, puis un UUID inventé. Attendu : 404 identiques. |
| T14 | Repeater : `GET /admin/users` avec la session d'un agent. Attendu : 403. |
| T16 | Repeater : `POST /documents/new` en changeant `classification` en 3 avec un agent SECRET. Attendu : 403. |
| T25 | Intruder : 20 `POST /auth/login` en rafale. Attendu : 429 à partir du seuil. |
| T26 | Repeater : `GET /admin/users/new` avec la session d'un agent (403) ; avec celle de l'administrateur, `POST /admin/users/new` en ajoutant un champ `role=admin` : le compte créé reste un agent. |
| T27 | Repeater : `POST /documents/upload` (multipart) avec un PDF ; relire ensuite la colonne `file_ciphertext` en base. |
| T28 | Repeater : `GET /documents/<uuid>/download` avec la session de bob avant, puis après le partage par le propriétaire. |
| T29 | Repeater : changer l'extension du fichier, ou remplacer son contenu par du texte, ou dépasser 8 Mo. Attendu : 400 (413 au-delà de 10 Mo). |
| T30 | Repeater : avec la session de l'administrateur, `POST /documents/upload` avec `classification=3`, puis `GET /documents/<uuid>` et `/download` : 404. |

## Défauts découverts pendant les tests (avant / après)

| Défaut constaté | Correction (semaine 5) |
|---|---|
| Certificat serveur sans *Authority Key Identifier* : refusé par les clients stricts (Python 3.14, `VERIFY_X509_STRICT`) | `gen_certs.sh` ajoute `subjectKeyIdentifier` et `authorityKeyIdentifier` ; certificat réémis avec la même clé, `openssl verify` : OK |
| Autorité de certification locale sans `keyUsage` | `gen_certs.sh` ajoute `keyCertSign, cRLSign` pour toute nouvelle CA (la CA existante n'est pas modifiée : la remplacer obligerait à la réimporter) |
| Première version de la limite Nginx : les GET comptaient aussi, lire la page de connexion consommait le quota | `map $request_method` : seuls les POST sont comptés |
| Verrouillage de compte absent à la fin de la semaine 2 (`failed_attempts` jamais utilisé) | Implémenté dans `auth/service.py`, testé (T02) |
| Création d'un document sur MariaDB : « Data too long for column reference » (invisible avec SQLite) | Référence provisoire plus courte (`temporary_reference`) + tests de non-régression |

## Durcissement ajouté en semaine 5

- Limitation de débit par adresse IP : Flask-Limiter (compteurs dans Redis) **et** `limit_req` Nginx, HTTP 429 (T25).
- HSTS activé avec une durée courte (5 minutes) pour ne pas piéger `localhost`.
- Conteneur applicatif : système de fichiers en lecture seule, `cap_drop: ALL`, `no-new-privileges`.
- `Cache-Control: no-store` sur toute page affichée à un agent connecté.
- Nouveaux tests d'infrastructure (`test_infra.py`) qui échouent si la configuration livrée s'affaiblit.
- Dépôt de fichiers : liste blanche PDF/DOC/DOCX, signature du contenu contrôlée, 8 Mo au plus, téléchargement en pièce jointe (`nosniff`), limite de corps de requête à 2 Mo partout sauf sur `/documents/upload` (10 Mo côté Nginx).
- Précautions prises dès la conception du dépôt : colonne `LONGBLOB` (le `BLOB` de MariaDB est limité à 64 Ko), nom de fichier nettoyé à l'envoi **et** au téléchargement, `flask init-db` qui ajoute les colonnes manquantes aux bases existantes sans toucher aux données.

## Observation sur l'environnement

Sur la machine de développement, `localhost:3306` répond : c'est le MariaDB de XAMPP, pas le conteneur. La preuve que Docker ne publie rien est donc `docker compose ps` (colonne des ports), pas un test de connexion sur l'hôte. Le script distingue les deux cas.
