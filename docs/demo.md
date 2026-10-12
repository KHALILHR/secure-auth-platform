# Démonstration finale (environ 5 minutes)

Scénario du cahier des charges, section 13. Chaque étape donne la commande ou l'action, le résultat
attendu et la preuve à montrer. Les mêmes étapes sont rejouées automatiquement par le test
`test_final_demonstration_scenario` (`app/tests/test_demo.py`).

## Préparation (une seule fois)

```bash
bash scripts/gen_secrets.sh                 # crée .env (clés AES et HMAC distinctes, 256 bits)
bash scripts/gen_certs.sh                   # mini-PKI : CA locale + certificat serveur
docker compose up -d --build
docker compose exec app flask --app wsgi init-db

# Jeu de données : alice (TRÈS SECRET), bob (SECRET) et 4 documents chiffrés
docker compose exec app flask --app wsgi seed-demo        # demande un mot de passe commun (saisie masquée)
# Premier administrateur : uniquement en ligne de commande
docker compose exec app flask --app wsgi create-admin     # demande nom, e-mail, mot de passe
```

Avant de commencer, ouvrir trois fenêtres de navigation privée (alice, bob, admin) sur `https://localhost`.
Si le navigateur affiche un avertissement, importer `pki/ca.crt` dans le magasin de confiance.

## 1. Infrastructure

```bash
docker compose ps                                         # 4 services ; seul nginx expose des ports
openssl verify -CAfile pki/ca.crt nginx/certs/server.crt  # attendu : OK
curl.exe --cacert pki/ca.crt -I https://localhost/auth/login   # en-têtes de sécurité (PowerShell : curl.exe)
```

Preuve : `docker compose ps` (colonne PORTS : 80 et 443 uniquement pour nginx), cadenas HTTPS, en-têtes.

## 2. alice (TRÈS SECRET) voit TS-001, SEC-001 et PUB-001

Se connecter en `alice`, ouvrir **Documents**. Ouvrir TS-001 : le bandeau orange « TRÈS SECRET » encadre la page.

## 3. bob (SECRET) ne voit pas TS-001

Se connecter en `bob`. TS-001 est absent de la liste. Copier l'adresse du document dans la fenêtre d'alice et la
coller dans celle de bob : **404**. Montrer ensuite le refus dans le journal (étape 8).

## 4. alice tente de partager TS-001 avec bob

Sur TS-001, **Gérer les accès**, ajouter `bob` : refus « habilitation du destinataire insuffisante » (journalisé).

## 5. L'administrateur baisse l'habilitation de bob à CONFIDENTIEL

Se connecter en `admin`, **Administration → Comptes et habilitations**, mettre bob à CONFIDENTIEL.
Sans que bob se reconnecte, actualiser sa liste : SEC-001 et SEC-002 ont disparu, PUB-001 reste.

## 6. L'administrateur essaie d'ouvrir TS-001

Coller l'adresse de TS-001 dans la fenêtre de l'administrateur : **404**. Il gère les comptes mais ne lit pas.
Dans **Administration → Documents**, il voit référence, classification et propriétaire, jamais le titre.

## 7. Attaque en base : TS-001 déclassé en PUBLIC

```bash
docker compose exec db sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" secureauth \
  -e "SELECT reference, HEX(LEFT(ciphertext,16)) FROM secure_documents"'      # que du binaire illisible
docker compose exec db sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" secureauth \
  -e "UPDATE secure_documents SET classification = 0 WHERE reference = '"'"'TS-001'"'"'"'
```

Recharger TS-001 chez alice : page d'incident, **aucun contenu**, et une ligne `INTEGRITY_FAILURE` dans le journal.
Restaurer ensuite : `... SET classification = 3 WHERE reference = 'TS-001'`.

## 8. Attaque sur le journal

```bash
docker compose exec app flask --app wsgi verify-audit      # « Chaîne intègre : N ligne(s) vérifiée(s). »
docker compose exec db sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" secureauth \
  -e "UPDATE audit_logs SET outcome = '"'"'SUCCESS'"'"' WHERE event = '"'"'LOGIN_FAILURE'"'"' ORDER BY id LIMIT 1"'
docker compose exec app flask --app wsgi verify-audit      # « CHAÎNE CORROMPUE à la ligne N », code de sortie 1
```

La même vérification est disponible dans **Administration → Journal d'audit → Vérifier l'intégrité**.
Pour réparer une démonstration, remettre la valeur d'origine de la ligne (la chaîne redevient valide).

## Bonus : ajouter un utilisateur et déposer un fichier

**Ajouter un utilisateur.** Dans la fenêtre de l'administrateur : **Administration → Comptes et habilitations → Ajouter un utilisateur**.
Saisir un nom, une adresse e-mail, une **habilitation** (PUBLIC à TRÈS SECRET) et un mot de passe provisoire. Le compte apparaît avec la
mention « Mot de passe provisoire ». Se connecter avec ce compte dans une quatrième fenêtre : toute page renvoie vers le changement de mot
de passe, et rien d'autre n'est accessible tant qu'il n'est pas fait. La création est dans le journal (`USER_CREATE`), sans le mot de passe.

**Déposer un fichier.** Dans la fenêtre d'alice : **Documents → Déposer un fichier**, choisir un PDF, DOC ou DOCX, une classification
(limitée à son habilitation), un titre facultatif. La fiche du document affiche le nom du fichier et le bouton **Télécharger**.
Montrer ensuite la base :

```bash
docker compose exec db sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" secureauth \
  -e "SELECT reference, file_size, HEX(LEFT(file_ciphertext,16)) FROM secure_documents WHERE file_size IS NOT NULL"'
```

Le fichier est du binaire illisible, son nom n'apparaît nulle part. Un fichier `.exe`, un faux PDF ou un fichier de plus de 8 Mo est refusé.

**Classification choisie par l'administrateur.** Dans la fenêtre de l'administrateur : **Documents → Déposer un fichier**, classification
TRÈS SECRET. Il est redirigé vers **Gérer les accès** (il ne peut pas lire ce niveau) et confie le document à alice ; un partage à bob (SECRET)
est refusé. Alice télécharge le fichier, l'administrateur reçoit un 404 s'il essaie.

## Tests automatiques et preuves

```bash
cd app && python -m pytest -q                                  # tests sans conteneur
python scripts/live_checks.py --demo-password '...' --admin-password '...'   # tests contre les vrais services
```

Résultats archivés dans `docs/preuves/` ; tableau complet des cas dans `docs/tests-securite.md`.
