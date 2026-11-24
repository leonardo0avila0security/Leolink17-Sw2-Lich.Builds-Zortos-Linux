# Orbitals — diagnostic du crash memcpy (dump 16952)

Date d'analyse : 2026-11-24  
Source : release [analysis-data](https://github.com/sinedgiveaways/tool/releases/tag/analysis-data), asset `orbitals-recomp.exe.16952.dmp.zip`  
SHA-256 de l'archive : `1046109831d1fa9451e3d8a047bbb07fd286a289c12035bebaf786f7b51f7dbd`  
Dump décompressé : 8,798,186,414 octets ; minidump AMD64 ; 94 threads ; 3,487 plages mémoire.

## Résumé exécutif

Le crash observé est une lecture invalide pendant une copie mémoire dans `ucrtbase.dll`. Les arguments invalides sont déjà présents dans le descripteur consommé par le helper de copie de `orbitals-recomp.exe`. Les données du dump ne justifient pas de modifier le chargeur d'imports.

Le qword source invalide `0x01460149013D0140` correspond exactement aux huit premiers octets du contenu trouvé à `0x11C51F700` (`40 01 3D 01 49 01 46 01`, quatre unités little-endian de 16 bits). Le pointeur attendu vers ce contenu pourrait donc avoir été remplacé par les octets du contenu lui-même. C'est une piste solide, mais l'instruction qui effectue cette confusion n'est pas encore identifiée.

## Faits établis par le dump

- Exception : `0xC0000005`, thread `0x5B10` (23312).
- RIP : `ucrtbase.dll+0xEE44D`.
- Instruction fautive : `vmovdqu ymm0, ymmword ptr [rdx]`.
- Registres au point de faute :
  - destination RCX : `0x12E1A8000C`
  - source RDX : `0x01460149013D0140`
  - taille R8 : `0x05240500` = 86,246,656 octets
  - RSI : `0x1C92EAB0540`
- Le bloc à RSI est capturé sur 0x400 octets :
  - `+0x00 = 0x12E1A8000C` (destination)
  - `+0x08 = 0x01460149013D0140` (source)
  - `+0x10 = 0x05240500` (taille)
  - `+0x40 = 0x01460149013D0140` (copie du qword source)
  - `+0x48 = 0x11C51F6F0`
  - `+0x50 = 0xFF`
  - `+0xD0 = 0x11C51F8A8`
  - `+0xD8 = 0xCE01F2C00`
- Le buffer candidat commence à `0x11C51F700`. Le pointeur `RSI+0x48 = 0x11C51F6F0` se trouve 0x10 octets avant le début du contenu candidat. Cette relation est compatible avec une structure contenant des métadonnées immédiatement avant un buffer, mais son layout exact n'est pas encore démontré.
- Le bloc capturé à `RSI+0x100 = 0x11C51F680` contient lui aussi la séquence source à son offset `+0x80`, soit à l'adresse `0x11C51F700`. Dans ce même bloc, les qwords `+0x70` et `+0x78` sont respectivement `8` et `0x0E40012810`, suivis à `+0x80` des octets `40 01 3D 01 49 01 46 01`. Cela ressemble à une zone de données UTF-16 avec métadonnées proches ; l'interprétation de ces champs reste à valider.
- Le pointeur candidat `0x11C51F700` n'a pas de référence directe trouvée par le scan des qwords. Il a été localisé par recherche du motif source, pas par une référence pointeur.
- Le helper natif à `orbitals-recomp.exe+0x40CE0` lit le descripteur via `[rcx]`, `[rcx+8]`, `[rcx+0x10]`, puis transmet destination/source/taille au thunk à `orbitals-recomp.exe+0x70C430`. Il reçoit donc déjà une source non canonique.
- Le chemin natif de l'appelant contient un retour à `orbitalgame.dll+0x1B5A939F`, après l'appel du wrapper `orbitalgame.dll+0x1C11DF00` à `+0x1B5A939A`. Le wrapper interne revient à `orbitalgame.dll+0x1C11DF58`. Ce sont des points d'ancrage de pile ; il faut encore faire l'unwind et le raccordement précis au code guest.

## Import memcpy : conclusion

Le dump montre :
- GOT guest `0x700900A008 = 0x7020002CD0`
- slow-dispatch lookup : clé `0x7020002CD0` trouvée à l'index `0x7B3`
- entrée hostfn `memcpy`, slot `0x2CD`, cible `orbitals-recomp.exe+0x40CE0`

Cela confirme que `0x7020002CD0` est un identifiant/adresse synthétique du runtime et que le chemin hostfn aboutit au helper de copie. Ne pas modifier le chargeur des imports pour ce crash.

## Structure candidate et valeur -3 : lien causal non confirmé

Le champ `RSI+0xD8` contient le pointeur `0x0CE01F2C00`. L'objet pointé a été extrait dans `descriptor_ptr_0D8_0000000CE01F2C00.bin`. À l'offset `+0xD8` de cet objet, les octets sont `FD FF FF FF 03 00 00 00` : le premier DWORD signé vaut `-3`, le DWORD adjacent vaut `3`.

Le probe de la table candidate `x21=0x0E40012810` retrouve `x21+0x158=0x0CE01F2C00` et une limite de 10 enregistrements. Pour l'enregistrement 0, `+0xD0=0`, `+0xD8=-3`. En appliquant le calcul guest correspondant avec le fallback `x27+0x10`, on lit actuellement le qword `0x013C013D0139013C` à `0x0CE01F2B48), dont le DWORD bas ne correspond pas à `x25=0x01490140`. Les enregistrements suivants capturés ne correspondent pas non plus.

**Conclusion :** `-3` est un champ réel dans un objet candidat, mais les octets actuels ne reproduisent pas la taille observée. Il n'est donc pas démontré que ce `-3` a produit le `0x01490140` de ce crash. Le pointeur/enregistrement utilisé au moment du chargement peut différer de l'état capturé au moment du crash, ou le chemin exact peut être différent. Ne pas patcher ce champ à l'aveugle.

## Points non démontrés

- La relation causale entre le champ signé `-3` de l'objet `0x0CE01F2C00` et la source invalide n'est pas établie.
- Les noms guest `f_7001759b20` et `f_70017508e0` ne sont pas encore reliés de façon certaine à ce chemin natif. Le workflow de recherche de source C n'a trouvé aucun fichier C contenant ces noms ; l'archive setup-work contient surtout des objets compilés et les sources générées correspondantes ne sont pas présentes.
- La cause racine pourrait impliquer un mauvais offset, un mauvais type/layout, une confusion pointeur/contenu, une corruption antérieure ou une durée de vie invalide. Le dump seul ne permet pas encore de choisir entre ces possibilités.

## Prochaines analyses requises

1. Identifier le type/layout de l'objet `0x0CE01F2C00`, en particulier les champs autour de `+0xD0..+0xF0`, et rechercher les usages du DWORD signé `-3`.
2. Reconstituer la structure autour de `0x11C51F6F0` et le buffer à `0x11C51F700`. Vérifier si `+0x48` dans le descripteur correspond à un pointeur vers un conteneur/une chaîne et si le source correct devait être `0x11C51F700`.
3. Désassembler/unwinder le chemin depuis `orbitalgame.dll+0x1B5A939A` à travers `+0x1C11DF00`, le dispatcher et `orbitals-recomp.exe+0x40CE0`.
4. Reconstituer l'origine des champs du descripteur `[+0]`, `[+8]`, `[+0x10]`. Trouver l'instruction qui a écrit le contenu `0x01460149013D0140` dans le champ source au lieu de l'adresse du buffer.
5. Raccorder le chemin natif aux fonctions guest `f_7001759b20` et `f_70017508e0` avec les symboles et objets compilés exacts.
6. Préparer un correctif minimal uniquement après preuve de la cause, puis un test de non-régression. Éviter toute régénération/recompilation complète pour chaque expérience.

## Artefacts d'analyse

- Workflow dump analysis : https://github.com/sinedgiveaways/tool/actions/runs/45455492238
- Workflow d'inventaire du C généré (aucun fichier source correspondant trouvé) : https://github.com/sinedgiveaways/tool/actions/runs/45455524457
- Release des données : https://github.com/sinedgiveaways/tool/releases/tag/analysis-data
- Archive de rapports runtime : artefact `orbitals-dump-analysis` du premier workflow.


## Analyse de l'objet compilé exact (24 novembre, suite)

L'archive `setup-work.zip` contient `setup-work/obj/main_main_0184.o` (412,812 octets). Cet objet est un fichier COFF x86-64 généré par la recompilation, pas du code ARM64 brut. Il définit réellement les symboles :
- `f_7001759b20` à l'offset objet `0x18980`
- `f_70017508e0` à l'offset objet `0x147C0`
- `f_7001750480` à l'offset objet `0x13AC0`

La pile du dump contient `0x7001759B20` deux fois et `0x700175053C`, qui se situe dans la plage de la fonction guest `f_7001750480` (entrée `0x7001750480`). La pile contient aussi `0x70070C1DE0` suivi d'un retour guest `0x700175A130`. Cela donne un lien concret entre `f_7001759b20` et le wrapper guest `f_70070c1de0`, mais la correspondance exacte entre le PC guest de retour et l'un des callsites natifs reste à vérifier.

Les relocations COFF de `f_7001759b20` identifient ces appels externes :
- objet `0x18B6A` -> `rt_dispatch`
- objet `0x191B0` -> `f_70070c1df0`
- objet `0x19843` -> `f_70070c1de0`
- objet `0x198AB` -> `f_70070c1de0`

Le code autour des deux appels à `f_70070c1de0` prépare deux descripteurs différents :
- premier chemin : `[rsi]=rdx`, `[rsi+0x10]=r13 & 0x78`, puis appel de `f_70070c1de0` ; `[rsi+8]` n'est pas réécrit dans ce bloc, il peut donc provenir d'un état antérieur du contexte.
- second chemin (si `r13 & 4)) : `[rsi+8]=r9`, `[rsi+0x10]=r13`, `[rsi]=rdx+rax), puis appel de `f_70070c1de0`.

Le crash capture `[rsi]=0x12E1A8000C`, `[rsi+8]=0x01460149013D0140`, `[rsi+0x10]=0x05240500`. Ces valeurs ne correspondent pas directement aux constantes et opérations visibles dans les deux callsites ci-dessus. Il faut donc examiner la définition de `f_70070c1de0` et remonter au bloc exact qui alimente son contexte ; ne pas conclure que le problème est déjà identifié dans `f_7001759b20`.

Un workflow ciblé a été ajouté pour scanner les objets compilés et retrouver les définitions de `f_70070c1de0` / `f_70070c1df0`, sans recompiler ni régénérer le jeu :
- workflow : https://github.com/sinedgiveaways/tool/actions/workflows/orbitals-copy-callee-analysis.yml
- commit du workflow : `d7e5e452b39525c23090e323d3191a20c12de485`
- analyse de l'objet `main_main_0184.o` : https://github.com/sinedgiveaways/tool/actions/runs/45464966158

La prochaine étape est d'identifier le ou les objets qui définissent `f_70070c1de0` et `f_70070c1df0`, puis de lire leurs instructions et relocations autour des appels au helper host. Ce sera le point de preuve nécessaire pour déterminer si le mauvais pointeur est créé dans le wrapper, dans son appelant guest, ou plus tôt.


## Appel guest exact du memcpy fautif — comparaison des arguments

La désassemblage AArch64 de l'exécutable `exefs/main` confirme le retour de pile `0x700175A130` : il suit immédiatement le deuxième appel `BL 0x70C1DE0` à `main+0x175A12C`. Le stub guest `main+0x70C1DE0` saute par le slot GOT `0x900A008), celui du `memcpy` identifié dans le dump.

Les instructions autour des deux copies sont :

```asm
main+0x175A100: mov x25, x1
main+0x175A104: mov x19, x2
main+0x175A108: mov x2, x27
main+0x175A10C: bl  0x70C1DE0       ; memcpy #1
main+0x175A110: mov x2, x19
main+0x175A114: mov x0, x26
main+0x175A118: mov x26, x28
main+0x175A11C: tbz w2, #2, 0x175A130
main+0x175A120: add x1, x25, x27
main+0x175A124: and x2, x2, #4
main+0x175A128: add x0, x0, x27
main+0x175A12C: bl  0x70C1DE0       ; memcpy #2
main+0x175A130: ldp w0, w8, [x26, #8]
```

Le dump donne `RSI+0xF0 = 0x700175A130`, donc le contexte fautif correspond au deuxième appel, pas au premier.

Au deuxième appel, les arguments guest sont explicitement calculés comme :
- destination : `x0 + x27`
- source : `x25 + x27`
- taille : `x2 & 4`, donc seulement `0` ou `4` octets.

Mais le descripteur consommé par le helper host contient :
- destination : `0x12E1A8000C`
- source : `0x01460149013D0140`
- taille : `0x05240500` (86,246,656 octets)

La taille host capturée est donc incompatible avec l'argument guest du deuxième appel. Elle est en revanche compatible avec une valeur conservée de la première copie, qui utilise `x2 = x27`. Le source host est également le contenu du buffer à `0x11C51F700`, et non l'adresse du buffer elle-même. C'est un indice fort d'un argument de copie périmé/mal transmis ou d'une corruption du contexte entre l'appel guest et la lecture du descripteur. La cause exacte (mauvais marshalling, réutilisation/race du contexte, ou autre écriture concurrente) n'est pas encore prouvée.

## Helper host exact et correction d'offset

Le symbole hostfn `memcpy` a été localisé à `orbitals-recomp.exe+0x40CE0` (VA du dump `0x7FF6C82A0CE0`). Son prologue est :

```asm
mov rsi, rcx
mov rdi, [rcx]       ; destination
mov rbx, [rcx+8]     ; source
mov r14, [rcx+0x10]  ; taille
...
mov rcx, rdi
mov rdx, rbx
mov r8,  r14
call 0x7FF6C896C430
```

L'adresse appelée `0x7FF6C896C430` correspond à `orbitals-recomp.exe+0x70A430` (base du module `0x7FF6C8260000`). Le précédent offset `+0x70C430` indiqué plus haut était une erreur de transcription ; la cible exacte observée dans le dump est `+0x70A430`.

Le helper lit les trois champs du descripteur tels quels. Il ne transforme pas la source en contenu et ne remplace pas la taille. Les mauvais arguments sont donc déjà présents dans le descripteur au moment où le helper démarre.

## Conclusion mise à jour

La preuve la plus forte à ce stade n'est pas une faute de l'implémentation de `memcpy` elle-même : c'est le désaccord entre le deuxième appel guest (`source=x25+x27`, `size=x2&4`) et le descripteur reçu par le helper (`source=0x01460149013D0140`, `size=0x05240500`). Le diagnostic se concentre maintenant sur la construction et la durée de vie du contexte d'appel de `f_7001759b20`, en particulier sur le passage du premier `memcpy` au deuxième et sur une éventuelle réutilisation concurrente du même contexte.

Artefacts :
- scan des définitions des wrappers `f_70070c1de0` / `f_70070c1df0` dans les 832 objets compilés : https://github.com/sinedgiveaways/tool/actions/runs/45465324639
- désassemblage AArch64 du callsite exact et des stubs PLT : https://github.com/sinedgiveaways/tool/actions/runs/45465692468


## Correction de provenance du pointeur source

Précision importante : l'adresse `0x11C51F700` est l'endroit où le qword invalide est présent comme DONNÉE. Ce n'est pas encore l'adresse source attendue par le code guest ; il ne faut pas traiter ce buffer comme la destination de la correction.

Le code hôte généré pour le deuxième appel à `memcpy` calcule le champ source à partir des champs du contexte :
`source = [context+0xD8] + [context+0xC8]`.
Dans le dump, ces champs valent respectivement `0x0CE01F2C00` et `0x01490140`. L'adresse source attendue selon cette instruction est donc `0x0CE16E2D40`, sous réserve que le contexte observé soit bien celui consommé par le helper (le PC `+0xF0=0x700175A130` et la pile soutiennent cette association).

Le helper reçoit à la place `0x01460149013D0140`, qui est le contenu trouvé à `0x11C51F700`. Le désaccord est donc encore plus précis : le champ source ne contient ni le pointeur attendu `0x0CE16E2D40`, ni l'adresse du buffer où son contenu a été retrouvé ; il contient les octets de données eux-mêmes. Le workflow `orbitals-memcpy-context-probe` vérifie maintenant si `0x0CE16E2D40` est présent dans les plages mémoire du dump et si le descripteur `0x1C92EAB0540` est référencé depuis les piles d'autres threads.

Le `setup-state.json` inclus dans la release indique le port `0.2.0-g50f4ec8`. Les conclusions de code machine de cette note se rapportent donc aux assets de cette release précise ; ne pas les transposer automatiquement au runtime `0.2.0-g84b2e62` sans vérifier que le dump et ses objets compilés correspondent à ce dernier.


## Résultat du probe de contexte (run 45467398410)

Le probe a été exécuté avec succès sur le dump original. Correction arithmétique : `0x0CE01F2C00 + 0x01490140 = 0x0CE1682D40` (et non `0x0CE16E2D40`, qui était une erreur de calcul dans la note précédente).

- Source calculée par le callsite compilé : `0x0CE1682D40`.
- Cette adresse n'est pas présente dans les plages mémoire capturées du dump. Cela ne prouve pas à elle seule qu'elle n'était pas mappée au runtime ; le dump peut ne pas l'avoir capturée.
- Le qword source invalide reste présent comme contenu à `0x11C51F700`. Les octets qui suivent forment une séquence de valeurs 16 bits (`0x0140, 0x013D, 0x0149, 0x0146, 0x0140, 0x0149, 0x013A, 0x013B...`) : c'est manifestement une donnée, pas une adresse source exploitable.
- Le pointeur de contexte `0x1C92EAB0540` apparaît dans la pile du thread fautif `0x5B10` uniquement ; aucune autre pile de thread capturée ne le référence. Cela affaiblit l'hypothèse d'un partage évident de ce même contexte entre plusieurs threads, sans exclure une corruption intra-thread ou une réutilisation de contexte.
- Le mismatch reste établi : le callsite guest de retour `0x700175A130` doit passer une taille `0` ou `4`, alors que le helper reçoit `0x05240500`. Le source reçu est aussi différent du résultat d'addition attendu `0x0CE1682D40`.

Probe : https://github.com/sinedgiveaways/tool/actions/runs/45467398410


## PDB et chemin réel de dispatch — vérification supplémentaire

Le PDB exact du DLL de la release mappe les symboles générés vers ces RVA (section `.text`, base de section +0x1000) :
- `f_7001759b20` -> `orbitalgame.dll+0x1B5A8470`
- `f_7001750480` -> `orbitalgame.dll+0x1B5A35B0`
- `f_70070c1de0` -> `orbitalgame.dll+0x1C11DF00`
- `f_70070c1df0` -> `orbitalgame.dll+0x1C11DF60`
- thunk import `rt_dispatch` -> `orbitalgame.dll+0x1C7ED0E0`

Le callsite hôte `orbitalgame.dll+0x1B5A939A` est donc bien dans `f_7001759b20` et son appel à `f_70070c1de0` correspond au retour guest `0x700175A130`.

Le wrapper `f_70070c1de0` à `+0x1C11DF00` possède deux chemins :
- le chemin normal charge le GOT `0x700900A008`, écrit les métadonnées d'import dans le contexte (`+0x80`, `+0x88`, `+0x108`) puis passe à `rt_dispatch` via le thunk `+0x1C7ED0E0) ;
- le chemin profilé appelle d'abord `fnprof_hit` via le thunk `+0x1C7ED0C0`, restaure ensuite `RCX) au contexte d'appel et rejoint le chemin normal.

Le retour de pile `orbitalgame.dll+0x1C11DF58` prouve que le chemin profilé a été pris pour le memcpy fautif. Le thunk `+0x1C7ED0C0` est `fnprof_hit`, pas `rt_dispatch` ; le vrai thunk `rt_dispatch` est `+0x1C7ED0E0`. Cela corrige l'interprétation initiale du wrapper.

Dans l'exécutable hôte, `fnprof_hit` :
- appelle `impcensus_hit` lorsque `impcensus_on` est actif ;
- possède un cas spécial qui appelle `rt_patch_record_entry` si son premier argument est `0x7001759b20), et `rt_patch_free_entry` pour `0x70000bf040`.
Pour l'appel de memcpy observé, le premier argument de `fnprof_hit` est l'adresse du wrapper `0x70070c1de0`, donc ce passage précis ne déclenche pas le cas spécial `f_7001759b20`. Il reste à lire le flag `g_orbitals_entry_probe` et à vérifier si un probe a patché l'entrée de `f_7001759b20` au moment de son invocation.

Le dispatch hostfn `+0x36E50` transmet le contexte au slot `memcpy` `+0x40CE0`. Le helper copie directement `[context]`, `[context+8]), `[context+0x10]) dans RCX/RDX/R8. Le wrapper hostfn de tracking `+0x37C10` ne fait qu'incrémenter/décrémenter le compteur de contexte autour de l'appel ; il ne réécrit pas les arguments. Le chemin effectif et les flags `kern_host_track` / `g_orbitals_entry_probe` sont encore en cours de vérification.

Artefacts :
- PDB map : https://github.com/sinedgiveaways/tool/actions/runs/45468282799
- résolution et désassemblage dispatch/profiling : https://github.com/sinedgiveaways/tool/actions/runs/45469242197


## Nouvelle piste prioritaire : entry-probe sur la fonction fautive

Le désassemblage du vrai objet compilé montre que `f_7001759b20` possède, dès son prologue, un chemin d'instrumentation spécial :
- après `mov rcx -> rsi` et le chargement de l'identifiant guest `0x7001759b20`, il teste un marqueur patchable à `f_7001759b20+0x29) ;
- si le marqueur est actif, il saute à `f_7001759b20+0x110E), appelle `fnprof_hit(0x7001759b20, [context+0xF0], [context])`, puis revient au corps normal ;
- `fnprof_hit` contient précisément un cas spécial pour `0x7001759b20` qui appelle `rt_patch_record_entry` lorsque `g_orbitals_entry_probe` est activé.

Dans le dump, `impcensus_on = 1` : la collecte de profiling est active. Le wrapper de memcpy a également pris son chemin profilé (retour `+0x1C11DF58`). Il reste à vérifier si le marqueur d'entrée de `f_7001759b20` et le flag `g_orbitals_entry_probe` sont actifs. Si oui, l'instrumentation de cette fonction devient le premier suspect à isoler, avant de modifier le code guest.

Cette piste n'établit pas encore que `fnprof_hit` corrompt les arguments : le callback ne reçoit pas directement le pointeur du contexte dans ses arguments standard. Il faut examiner `rt_patch_record_entry` et les valeurs du flag, puis faire un essai contrôlé avec le probe désactivé. Aucun patch de jeu n'est proposé avant cette vérification.


## Reconstitution des deux memcpy dans f_7001759b20

La correspondance des registres guest avec les champs sauvegardés est maintenant clarifiée par les instructions du callsite :
- `[context+0xD8] = x25 = 0x0CE01F2C00` : base source.
- `[context+0xC8] = x27 = 0x01490140` : offset / taille du premier appel.
- Le premier appel guest `memcpy(x0, x25, x27)` devait donc copier `0x01490140` octets depuis `0x0CE01F2C00` vers `0x12E05EFECC`.
- Le deuxième appel guest calcule `dest=x0+x27=0x12E1A8000C`, `source=x25+x27=0x0CE1682D40`, puis `size=x2 & 4 = 4`.

Le dump montre que la destination du deuxième appel est correcte, mais que les deux autres champs lus par le helper sont `source=0x01460149013D0140` et `size=0x05240500`. Le source invalide est une valeur de données (présente à `0x11C51F700`), et la taille correspond à aucune des deux tailles attendues (`0x01490140` pour le premier appel ou `4` pour le second).

Cela ressemble à une corruption partielle ou à une réutilisation/réentrance du descripteur : le champ destination reflète le deuxième appel, tandis que source et taille reflètent d'autres données. La cause de cette incohérence reste à établir ; le prochain probe recherche toutes les références mémoire au descripteur `0x1C92EAB0540` et à son objet tracker, pas seulement les références dans les piles de threads.


## Vérification des mécanismes d'instrumentation et de dispatch (run 45469678070 / artefact 45469700588)

Les flags runtime lus dans le dump exact sont :
- `impcensus_on = 1`
- `g_orbitals_entry_probe = 0`
- `kern_host_track = 0`

Conséquences :
1. Le probe d'entrée spécial de `f_7001759b20` n'est pas actif dans ce dump. Le saut vers `rt_patch_record_entry` ne peut donc pas expliquer cette panne.
2. `kern_host_track` étant désactivé, `hostfn_entry` prend le chemin direct vers le pointeur de fonction du slot ; il ne passe pas par `hostfn_tracked`. Le wrapper de suivi de contexte ne réécrit donc pas les arguments de memcpy dans ce cas.
3. Le chemin profilé du wrapper est bien exécuté parce que `impcensus_on=1`. `fnprof_hit` appelle `impcensus_hit` avec l'identifiant de fonction et le PC de retour. Le code désassemblé de `impcensus_hit` enregistre des clés/compteurs de profiling et, si le mode live est actif, capture des informations de pile. Il ne reçoit pas le pointeur de contexte comme argument et ne contient pas d'écriture vers les champs `context+0`, `+8` ou `+0x10`. `fnprof_hit` conserve le contexte dans un registre non volatile puis le restaure avant de poursuivre le dispatch.

Le pointeur tracker `[context+0x138] = 0x1C92EB90780` a son premier qword à zéro dans les octets déjà capturés. Le test de préemption de `rt_dispatch` lit ce premier qword ; dans cet état capturé, il ne prend donc pas le chemin `dispatch_preempt`.

**Conclusion de cette vérification :** les chemins entry-probe et hostfn tracking sont désactivés ; le profilage `impcensus` est actif mais son code observé n'écrit pas dans les arguments de copie. Il ne faut plus traiter l'entry-probe ou le wrapper `hostfn_tracked` comme suspects principaux. Une corruption concurrente/réutilisation du descripteur, ou une autre écriture entre la préparation du contexte guest et la lecture par le helper, reste à investiguer.

Le probe de références mémoire a aussi trouvé 87 références au descripteur `0x1C92EAB0540`, 11 références au tracker `0x1C92EB90780` et 2 références à l'objet pointé par `context+0x48` (`0x11C51F6F0`). Ces références ne prouvent pas à elles seules un partage concurrent : il faut examiner les fenêtres mémoire autour de chacune pour distinguer les copies de pile, les structures propriétaires et les références actives.

Artefacts :
- flags et premier scan des références : https://github.com/sinedgiveaways/tool/actions/runs/45471122636
- comparaison des valeurs de registres sauvegardées : https://github.com/sinedgiveaways/tool/actions/runs/45471415428
- désassemblage de `fnprof_hit`, `impcensus_hit`, `hostfn_entry`, `hostfn_tracked` : https://github.com/sinedgiveaways/tool/actions/runs/45469700588

## Probe enrichi des propriétaires du descripteur

Le script `tools/nx2/probe_orbitals_memcpy_context.py` a été enrichi pour exporter les fenêtres qword autour de chaque référence mémoire au descripteur, au tracker et à l'objet guest voisin. Il exporte également les 0x200 premiers octets du tracker. Ce probe reste en lecture seule : il ne modifie ni le dump, ni les archives de jeu, ni les sources compilées.

Commit du script : `dc6d642ca5f316236bc6fbdb8f6e422d5c22959b`. Le workflow ciblé correspondant est en cours d'exécution ; ses résultats doivent être ajoutés ici avant de tirer une conclusion sur le partage ou la réutilisation du descripteur.


## Résultat du scan des références mémoire — run 45478450618

Le probe enrichi a terminé avec succès sur le dump exact. Il confirme :
- 87 occurrences du pointeur de contexte `0x1C92EAB0540` dans les plages mémoire capturées ;
- 11 références au tracker `0x1C92EB90780` ;
- 2 références à l'objet guest `0x11C51F6F0` (à partir de `context+0x48)).

Interprétation :
1. La grande majorité des 87 références au contexte se trouve dans la pile du thread fautif `0x5B10` (plage `0x19AFFF...`). Cela correspond à des variables locales, sauvegardes de registres et structures d'appel de ce même thread ; ce n'est pas une preuve de partage entre threads.
2. Deux références supplémentaires au contexte se trouvent dans la zone heap `0x1C9B6F82...`. L'une conserve une copie des arguments fautifs (destination `0x12E1A8000C`, source `0x01460149013D0140`, taille `0x05240500`) ; l'autre conserve le PC guest `0x7001759B20`, le retour `orbitalgame.dll+0x1B5A939F` et un pointeur de frame. Cela ressemble à des enregistrements runtime/diagnostic autour de l'appel. Leur existence ne prouve pas qu'un autre thread ait écrit dans le contexte.
3. Le pointeur `context+0x48 = 0x11C51F6F0` est confirmé comme un objet guest référencé aussi depuis `0x11C51F6B8`. À l'adresse `0x11C51F700` (objet +0x10) se trouvent les unités UTF-16 dont les octets forment précisément le qword source invalide. La source fautive correspond donc au contenu inline de cet objet guest, pas à une adresse.
4. Le tracker `0x1C92EB90780` contient le pointeur du contexte dans ses champs `+0x18` et `+0x20`. Son premier qword vaut zéro, cohérent avec le fait que `rt_dispatch` ne prend pas le chemin de préemption dans ce snapshot. Le tracker n'identifie pas encore un écrivain concurrent.

### Validation des offsets de registres du probe précédent

Après confrontation avec le prologue AArch64 de `f_7001759b20`, les offsets du probe sont cohérents :
- `context+0x100 = 0x11C51F680` correspond au pointeur de pile guest avant la réservation du frame ;
- la fonction réserve `0x120` octets, puis sauvegarde `x28/x27` à `SP+0xD0` et `x26/x25` à `SP+0xE0` ;
- donc `x27) sauvegardé à l'entrée se lit à `base-0x48`, et `x25) à `base-0x38`.

Les valeurs lues (`x27 entrée = 0x1800000001`, `x25 entrée = 0x7001759F74`) sont donc bien les sauvegardes des valeurs callee-saved du caller. Elles ne sont pas les valeurs courantes de x27/x25 utilisées par les deux copies. Les valeurs courantes sont corroborées séparément par les champs du contexte généré : `[context+0xD8] = 0x0CE01F2C00` pour x25 et `[context+0xC8] = 0x01490140` pour x27. La structure à `0x11C51F680` est bien la zone de pile guest ; son contenu à l'adresse SP pré-prologue n'est pas censé ressembler à un frame pointer.

### Ce que le nouveau résultat élimine — et ce qu'il laisse ouvert

- Le scan des piles ne montre pas que le contexte soit activement partagé avec un autre thread.
- Le chemin de préemption de `rt_dispatch` est inactif dans le snapshot (premier qword du tracker = 0).
- Les flags entry-probe et hostfn tracking sont à zéro.
- Le chemin profilé `impcensus` est actif, mais les fonctions désassemblées ne montrent pas d'écriture dans les champs d'arguments.

Cette hypothèse de corruption/réutilisation est désormais secondaire : le désassemblage complet révèle un chemin fallback qui atteint le wrapper sans rafraîchir le champ source. Il reste à reconstruire la valeur guest `x1` attendue à ce point et à confirmer le correctif minimal.

Artefact du scan complet : https://github.com/sinedgiveaways/tool/actions/runs/45478450618


## Propriétaire de la source et objet guest voisin

L'extraction mémoire déjà présente dans `orbitals_memcpy_runtime_corrige.zip` précise le lien entre le contexte et les objets guest :
- `[context+0x48] = 0x11C51F6F0` : pointeur vers un objet guest situé sur la pile ;
- `0x11C51F700` (objet +0x10) contient les unités UTF-16 dont les octets forment le qword source invalide ;
- `[context+0x98] = 0x0E40012C10` et `[context+0xA8] = 0x0E40012810` : deux objets guest associés ;
- l'objet `0x0CE01F2C00` contient notamment un pointeur vers `0x0E40012810` à `+0x38), ainsi que le champ signé `-3` à `+0xD8) (DWORD bas ; DWORD haut = 3) ;
- l'objet `0x0E40012810` référence `0x0CE01F2C00` à son offset `+0x158`). Ces structures sont liées, mais leur rôle exact reste à établir.

Le champ `-3` est donc localisé dans un objet de données réel, mais sa signification reste inconnue. Il ne faut pas le transformer en correctif tant qu'on n'a pas retrouvé son usage dans le code guest.

Le scan étendu a retrouvé cinq références au pointeur `0x0CE01F2C00`, huit à `0x11C51F8A8`, douze à `0x0E40012C10` et quinze à `0x0E40012810`. Aucune référence directe à `0x0CE1682D40` n'est présente dans les plages capturées. Le probe suivant se concentre donc sur les variables locales de pile qui alimentent `x8), `x9) et `x19) dans le chemin fallback.

## Correction de l'interprétation du callsite : chemin fallback

L'analyse complète du désassemblage guest a révélé deux chemins distincts vers l'instruction `memcpy` de retour `main+0x175A130`. L'analyse précédente qui interprétait systématiquement cet appel comme une copie finale de 4 octets ne s'applique qu'au chemin aligné ; ce n'est pas le chemin du dump.

Chemin réel dans le dump :
- `main+0x175A0E8: cmp x2, #8`
- `main+0x175A0EC: b.lo #0x175A12C`
- `main+0x175A0F0: orr w8, w1, w0`
- `main+0x175A0F4: tbnz w8, #3, #0x175A12C`
- la branche saute directement à `main+0x175A12C: bl memcpy`, sans passer par la préparation du chemin aligné à `0x175A0F8..0x175A128`.

Le chemin aligné, lui, prépare une première copie, puis éventuellement une copie de 4 octets. Il ne faut pas utiliser ses calculs `base+offset` pour interpréter le crash fallback.

Le dump montre `R8 = 0x05240500`. Cette taille est cohérente avec le chemin fallback : dans le code guest, `x2 = x25 << 2` à `main+0x175A0F7C`; avec `x25 = 0x01490140`, on obtient exactement `0x05240500`. La taille du memcpy fautif est donc probablement correcte dans ce chemin. La destination `0x12E1A8000C` est également celle préparée par le code guest.

Le problème restant est la source : le helper reçoit `RDX = 0x01460149013D0140`, qui n'est pas un pointeur. Le chemin fallback doit transmettre le registre guest `x1` sélectionné par `csel x1, x9, x8, eq` à `main+0x1759F94`. Le code x86 généré qui correspond à cette branche aboutit au bloc `1988E..198AA` ; ce bloc écrit la destination dans `[context+0]`, puis appelle le wrapper avec retour guest `0x700175A130`, mais ne met pas à jour `[context+8]` (source). Le champ source reste donc une ancienne valeur du contexte. C'est une omission très forte candidate dans la préparation des arguments du chemin fallback, pas une panne du chargeur d'import ni une corruption aléatoire démontrée.

Le correctif candidat consiste à sauvegarder le registre source courant `x1` dans `[context+8]` avant le dispatch. Le probe de pile a ensuite établi que `x1 = 0x11C51F8A8` sur ce chemin. Ce correctif ne traite toutefois pas la taille guest invalide, découverte ensuite.


## Raccordement des deux branches AArch64 et x86

Le chemin fallback AArch64 est désormais visible grâce à la fenêtre complète `main+0x1759E8C..0x175A130`. La condition de branchement est précise : taille inférieure à 8 octets ou bit 3 de `x1 | x0` actif (alignement non conforme) mène à `memcpy` à `0x175A12C`. Le chemin aligné passe par `0x175A0F8..0x175A128` et effectue une première copie avant l'éventuelle copie de 4 octets.

Le code hôte généré contient le test correspondant :
- `cmp r13, 8; jb 1988e`
- `or r9, rdx` puis `test al, 8; jne 1988e`
- le bloc `1988e..198aa` positionne le PC guest de retour à `0x700175A130`, écrit `rdx` (destination) dans le contexte, puis appelle le wrapper ;
- contrairement au chemin aligné, ce bloc ne stocke pas `r9` (source guest x1) dans `[context+8]`.

Le dump présente exactement la signature attendue d'un champ source non rafraîchi : destination correcte, taille cohérente avec `x2`, source égale à des octets de données UTF-16 provenant d'un objet guest. Le diagnostic se déplace donc vers la génération/mise à jour du contexte d'appel du chemin fallback de `f_7001759b20`.

Désassemblage guest complet : https://github.com/sinedgiveaways/tool/actions/runs/45480761866


## Valeur exacte de x1 sur le chemin fallback

Le probe de pile guest `45481414761` a fourni les variables locales exactes après le prologue :
- `SP+0x20 = 0x12E1A80000` (x19 local)
- `SP+0x38 = 0x05241000` (x9 candidat)
- `SP+0x80 = 0x11C51F8A8` (x8 sélectionné pour x1)
- `SP+0x88 = 0x01490140` (x25 signé)
- `x25 << 2 = 0x05240500`, exactement le R8 observé dans le helper.

Le chemin guest exécute :
- `ldr x8, [sp, #0x80]` → `x8 = 0x11C51F8A8`
- `cmp x8, #0`
- `csel x1, x9, x8, eq` → comme x8 est non nul, `x1 = 0x11C51F8A8`
- `x2 = x25 << 2 = 0x05240500`
- destination guest observée : `x0 = 0x12E1A8000C`.

**Arguments corrects au point de l'appel fallback :**
`memcpy(0x12E1A8000C, 0x11C51F8A8, 0x05240500)`.

Le champ `[context+0xD0]` contient lui aussi `0x11C51F8A8`, ce qui corrobore la valeur source attendue. Le champ `[context+8]` contient au contraire `0x01460149013D0140`, qui est la donnée UTF-16 située à `0x11C51F700`, et non le pointeur source. La taille `0x05240500` correspond bien au calcul guest `x25 << 2`, mais elle dépasse les régions mémoire engagées ; le champ source du descripteur est en plus faux.

Cette observation écarte l'hypothèse précédente selon laquelle la source attendue serait `0x0CE1682D40` pour ce crash : cette somme appartient à une autre branche de la fonction, pas au chemin fallback réellement pris.

## Défaut de marshalling distinct, confirmé dans le chemin fallback

Le bloc hôte fallback `1988E..198AA` conserve `x0` dans `[context+0]`, mais ne copie pas le registre guest `x1` dans `[context+8]` avant d'appeler le wrapper. Le contexte contient alors une ancienne valeur de source (ici les octets UTF-16 `0x01460149013D0140`). Le helper natif `orbitals-recomp.exe+0x40CE0` lit ce champ tel quel et transmet la mauvaise adresse à UCRT.

La correction minimale candidate est d'écrire le registre source courant (le registre hôte qui porte guest `x1`, `r9` dans le bloc désassemblé) dans `[rsi+8]` avant le dispatch fallback. Le champ `[rsi+0x10]` est déjà égal à `x2` dans ce dump ; il peut être réécrit en même temps pour rendre le marshalling explicite, mais ce n'est pas la valeur fautive observée.

**Statut : défaut de marshalling source confirmé, mais il n'explique pas à lui seul le crash complet.** Le champ source stale doit être corrigé, mais l'origine de la taille excessive reste la priorité. Ne pas modifier le chargeur d'imports ni le wrapper UCRT.


## Correctif binaire ciblé préparé

Le binaire de la release a été vérifié contre le dump :
- `orbitalgame.dll` SHA-256 : `8678d073fdffc4f3d518f492dbc3428f7257dc1ebe8467bb85d87a6633d97cf4`
- CodeView/PDB : GUID `d75ffc7c-ee2d-e2ca-4c4c-44205044422e`, âge 1 — identique au module `orbitalgame.dll` du dump 16952.
- Le point d'insertion est `RVA 0x1B5A9385`, instruction originale `mov [rsi+0xF0], rax`.
- Le trampoline utilise le padding INT3 vérifié à `RVA 0x1C7ED286` (0x17A octets disponibles).

Le patch remplace l'instruction de 7 octets par un saut vers le trampoline. Celui-ci :
1. conserve l'écriture originale du PC guest de retour dans `[rsi+0xF0]` ;
2. ajoute `mov [rsi+8], r9`, pour transmettre le guest `x1` courant au descripteur hostfn ;
3. revient à `RVA 0x1B5A938C`, avant l'écriture de destination déjà présente.

L'appel wrapper d'origine reste à son adresse `RVA 0x1B5A939A` : son adresse de retour native ne change pas. Le patch ne modifie ni le chargeur d'import, ni le helper UCRT, ni le reste du jeu. Il ajoute le stockage de source dans le bloc commun ; sur le chemin aligné, où `[rsi+8]` était déjà correct, il réécrit la même valeur.

Patcher reproductible : `tools/nx2/apply_orbitals_memcpy_fallback_patch.py`  
Workflow de production de l'artefact : https://github.com/sinedgiveaways/tool/actions/runs/45483610141

**État : patch partiel généré, ne pas l'appliquer pour le gameplay à ce stade.** Les vérifications binaires ont réussi, mais un contrôle séparé des régions mémoire a révélé que le memcpy guest demande 86,246,656 octets alors que les régions engagées autour de la source et de la destination sont beaucoup plus petites. Corriger uniquement le champ source déplacerait le crash plus loin dans la copie et pourrait corrompre la mémoire. L'artefact est conservé comme expérience diagnostique versionnée ; ne remplace pas encore le DLL de ton installation.




## Cause du size 86 Mo : local de pile non initialisé sur une branche

Le contrôle des registres et du code hôte donne maintenant une explication directe de la taille absurde :

- Le local guest `[sp+0x88]` est lu à `main+0x1759F4C` par `ldrsw x25,[sp,#0x88]`, puis multiplié par 4 à `main+0x1759F7C`.
- Dans le code hôte généré, le seul store vers l'emplacement correspondant `-0x98(%rbx)` est `orbitalgame.dll+0x190BD: movq %r9,-0x98(%rbx)`. La seule lecture ultérieure est `+0x19323: movslq -0x98(%rbx),%r8`. La recherche dans toute la fonction ne trouve aucun autre store vers ce slot.
- Le store `+0x190BD` appartient au chemin correspondant à la branche conditionnelle qui passe par `+0x18FDA`. Le chemin alternatif saute ce store, mais rejoint ensuite le code qui lit le local.

Valeurs reconstruites dans le dump :
- `x29=0x11C51F740`, `[x29-8]=0x128F170008)
- index de boucle `0x78), valeur signée chargée `w9=-1159757815)
- `w8=[x27+0xD8]=-3)
- bit 0 du flag lu depuis le contexte `+0x60 = 0)
- `w9 < w8` est vrai, mais `w12 & (w9 < w8)` vaut zéro à cause du flag. La branche guest `tbz ...` est donc prise et le seul store du local est sauté.
- Le local contient pourtant `[sp+0x88]=0x01490140) au moment du crash ; cette valeur est ensuite utilisée comme taille, donnant `0x05240500) (86,246,656 octets).

**Conclusion fortement étayée :** sur le chemin observé, le size est lu depuis un local de pile qui n'a pas été initialisé par le chemin courant. La valeur résiduelle `0x01490140` devient le nombre d'octets de la copie. C'est la cause immédiate de la taille démesurée et de la lecture/écriture hors des régions engagées. Le champ `-3` intervient dans la comparaison, mais n'est pas à lui seul la taille ; ne pas le patcher isolément.

## Correctif à préparer

1. Initialiser `[sp+0x88]` sur tous les chemins, ou faire en sorte que le chemin qui saute son store ne rejoigne pas la lecture/copie qui consomme ce local. La valeur par défaut correcte doit être déterminée à partir du rôle de cette branche ; ne pas mettre arbitrairement une limite de taille.
2. Corriger séparément le marshalling du host-call : écrire le vrai registre source `x1` dans `[context+8]` avant d'appeler le helper. Le champ actuel contient une valeur non canonique.
3. Vérifier que les arguments finaux sont des pointeurs de données et une longueur compatible avec les régions allouées.

Le patch qui ne rafraîchit que `[context+8]` reste **diagnostic uniquement**. Il ne corrige pas le local de taille non initialisé et ne doit pas être utilisé pour jouer.

## Nouvelle découverte : la taille guest est elle-même invalide

Le contrôle `MemoryInfoList` du dump a vérifié la couverture réelle des plages, y compris les régions adjacentes :
- source guest calculée `x1 = 0x11C51F8A8` : région engagée `0x11C42E000 + 0x100000`, fin `0x11C52E000`. La lecture atteint une région réservée/non engagée après seulement `0xE758` octets.
- destination `0x12E1A8000C` : région engagée `0x12E1A80000 + 0x180000`, fin `0x12E1C00000`. L'écriture atteint une région réservée/non engagée après `0x17FFF4` octets.
- taille demandée : `0x05240500` = 86,246,656 octets.

Donc, même avec le pointeur source corrigé à `0x11C51F8A8`, le memcpy traverserait une zone non engagée côté source après environ 59 Ko et côté destination après environ 1,5 Mo. **La taille n'est pas sûre et le patch source seul ne constitue pas un correctif jouable.**

Le code guest calcule cette taille avant l'appel :
- `main+0x1759F4C: ldrsw x25, [sp, #0x88]`
- `main+0x1759F7C: lsl x2, x25, #2`
- valeur de pile : `[sp+0x88] = 0x01490140`
- résultat : `x2 = 0x05240500`.

L'origine de cette valeur est également identifiée dans le flot guest :
- `main+0x1759E54: ldur d0, [x8, #-8]`
- `main+0x1759E58: str d0, [sp, #0x88]`
- puis `ldrsw x25, [sp, #0x88]`.

La priorité devient de reconstruire le pointeur `x8` et les données à `[x8-8]` à `0x1759E54`, puis de comprendre pourquoi leur DWORD bas vaut `0x01490140`. Il faut vérifier le layout de l'entrée sélectionnée dans la table `x27 = base + w20 * 0xE8` et ne pas supposer que le champ `-3` de `0x0CE01F2C00` est celui de `x27+0xD8` : cette correspondance n'est pas encore établie.

Rapport MemoryInfoList : https://github.com/sinedgiveaways/tool/actions/runs/45484336193


## Nouvelle analyse du calcul de taille — 24 novembre, probe du propriétaire du champ

Le désassemblage complet du callsite fournit désormais la chaîne exacte qui produit le DWORD de taille, mais le propriétaire de ce champ n'est pas encore identifié :

```asm
main+0x1759DE4: ldr x9, [x27, #0xD0]
main+0x1759E18: add x25, x27, #0x10
main+0x1759E1C: sxtw x8, w8
main+0x1759E24: cmp x9, #0
main+0x1759E28: csel x9, x25, x9, eq
main+0x1759E2C: add x8, x9, x8, lsl #6
...
main+0x1759E54: ldur d0, [x8, #-8]
main+0x1759E58: str d0, [sp, #0x88]
main+0x1759E5C: stur d8, [x8, #-8]
...
main+0x1759F4C: ldrsw x25, [sp, #0x88]
main+0x1759F7C: lsl x2, x25, #2
```

Faits supplémentaires directement visibles dans le snapshot :
- le frame guest commence à `0x11C51F680` et le frame actif est `0x11C51F560` après la réservation de `0x120) octets ;
- les locals sauvegardés à `SP+0x80) et `SP+0x88) valent respectivement `0x11C51F8A8) et `0x01490140) ;
- `SP+0x90) et `SP+0x98) contiennent tous deux `0x0E40012C10), tandis que `SP+0xA8=4), `SP+0xB0=3), et `SP+0xB8=0x0E40012C20) ;
- le contexte host conserve aussi `+0x98=0x0E40012C10) et `+0xA8=0x0E40012810). Ces valeurs sont des candidats de pointeurs d'objet, mais leur rôle exact et leur correspondance avec le registre courant `x21) doivent être validés par les accès mémoire, pas supposés.

Point important : `ldur d0, [x8,#-8]) est immédiatement suivi de `stur d8, [x8,#-8]). La fonction lit donc 8 octets du champ puis le remplace avec `d8) avant de continuer. Il faut distinguer la valeur d'entrée consommée pour le calcul de taille de la valeur écrite ensuite ; une capture mémoire après l'instruction ne permet pas, à elle seule, de déduire la valeur pré-écriture.

Un nouveau probe en lecture seule a été ajouté :
- `tools/nx2/probe_orbitals_size_field.py`
- le workflow `orbitals-guest-memcpy-size-origin` exécute maintenant ce probe en plus de l'ancien scan ;
- il teste les pointeurs candidats présents dans le contexte, suit `+0x158/+0x160) seulement lorsqu'ils sont capturés, puis scanne les enregistrements au stride `0xE8) à la recherche du DWORD bas `0x01490140). Il ne suppose plus que le x21 sauvegardé dans le prologue est le x21 courant (c'était le registre du caller).

Commits :
- probe : `6b8e9cbef1be07dabc972a1080f4139b95873bf5`
- workflow ciblé : `d26166be0337fbbe92887dd459e4707c4d3cd181`

**État : analyse en cours.** Le probe doit encore produire son artefact avant de conclure sur l'objet propriétaire, l'index d'enregistrement ou la cause de la valeur `0x01490140`. Aucun correctif de taille n'est proposé à ce stade. Le patch de marshalling de source reste un correctif partiel non jouable tant que la taille n'est pas comprise.


## Identification du propriétaire probable de la table x27

Une lecture croisée du dump brut et des accès du désassemblage permet maintenant de distinguer les deux objets candidats :
- `0x0E40012C10) (contexte `+0x98)) ne présente pas un compteur non nul à `+0x160) dans le snapshot ;
- `0x0E40012810) (contexte `+0xA8)) contient à `+0x158) le pointeur `0x0CE01F2C00) et à `+0x160) un DWORD bas égal à `10).

Cette seconde disposition correspond exactement aux accès AArch64 de la fonction :
- `ldr x9, [x21,#0x158]` : base du tableau de records ;
- `ldr w8, [x21,#0x160]` : limite/compte comparé à l'index `w20) ;
- `umaddl x27,w20,#0xE8,x9` : record sélectionné au stride `0xE8).

L'interprétation la plus probable est donc `x21 = 0x0E40012810), tableau de records à `0x0CE01F2C00), avec 10 entrées disponibles dans le dump. Cela corrige le probe antérieur qui avait pris `0x0E40012810) lui-même comme base du tableau : cette adresse est l'objet propriétaire contenant le pointeur de tableau, pas la base du tableau.

Pour le record d'index 0, les champs `+0xD0/+0xD8) sont les prochains à vérifier. La séquence de calcul est :
`x9 = record[+0xD0] (ou record+0x10 si nul)`,
`x8 = x9 + sign_extend(record[+0xD8]) * 0x40`,
puis lecture de 8 octets à `x8-8). Le champ signé `-3) observé à `0x0CE01F2C00+0xD8) devient ainsi particulièrement pertinent : s'il s'agit bien du record sélectionné, il ferait pointer la lecture vers `0x0E40012810-0xC8). Cette relation doit encore être confirmée par le probe qui lit directement cette adresse et les autres records ; elle n'est pas encore une preuve que l'entrée 0 est celle active au crash.

Le nouveau script `tools/nx2/probe_orbitals_size_field.py` teste maintenant les deux candidats à partir des pointeurs effectivement capturés dans le contexte et vérifie les champs de table et le DWORD chargé, sans présumer l'index actif.


## Scan du motif exact de la taille

Un scan des plages mémoire capturées retrouve le DWORD `0x01490140` à plusieurs endroits (85 occurrences, plafond de scan 200), dont :
- `0x11C51F5E8` : local guest `[sp+0x88]` qui alimente `x25`.
- `0x11C51F708` : huit octets après le début du buffer candidat `0x11C51F700).
- Le qword invalide `0x01460149013D0140` apparaît à `0x11C51F700), dont les octets sont une séquence de quatre unités 16 bits. Le DWORD à `0x11C51F708` est `0x01490140`.

La proximité est notable : le champ source stale du descripteur est égal au qword à `0x11C51F700`, tandis que le DWORD utilisé pour calculer la taille apparaît à `0x11C51F708`. Cela suggère une confusion avec des données 16 bits/une chaîne, mais le scan trouve de nombreuses occurrences et ne prouve pas que `ldur d0,[x8,#-8]` a lu précisément `0x11C51F708`.

Le prochain probe relève les entrées exactes `x21+0x158 + index*0xE8), le champ `+0xD0/+0xD8), le pointeur `x29-8), l'index `[sp+0xC0]` et la comparaison signée qui décide de la branche. Il doit établir l'adresse effective du chargement qui a produit `0x01490140`.

Rapport de scan : workflow `orbitals-memcpy-size-dword-scan`, run https://github.com/sinedgiveaways/tool/actions/runs/45488518166


## Correction de diagnostic : le DWORD de taille n'est pas démontré comme local non initialisé

La relecture du flot AArch64 complet corrige l'hypothèse précédente « local de pile non initialisé ». Cette hypothèse ne doit plus être traitée comme la cause établie.

Le flot exact montre que le code calcule x27 = table_base + sign_extend(w20)*0xE8, charge w8 depuis [x27+0xD8], sélectionne x9 depuis [x27+0xD0] ou x27+0x10, puis calcule x8 = x9 + sign_extend(w8)*0x40. Il lit explicitement 8 octets à [x8-8], copie d0 vers [sp+0x88], puis écrit d8 à [x8-8]. Plus tard, [sp+0x88] est étendu en signé et multiplié par quatre pour former la taille memcpy.

Le DWORD est donc copié explicitement depuis une adresse calculée à partir du record sélectionné et de son champ signé +0xD8. Le store vers [sp+0x88] est exécuté sur le chemin qui atteint le calcul de taille. Le fait que la valeur soit grande ne suffit pas à prouver un local non initialisé : elle peut être une valeur de données incorrecte lue depuis le mauvais record, le mauvais offset, ou un objet dont le layout/durée de vie est incorrect.

Le probe précédent avait aussi une erreur de reconstruction de l'index : il utilisait ctx+0xC0 comme index, alors que cette valeur correspond au pointeur de pile x23 sauvegardé. Le registre x24 est sauvegardé à sp+0xF0, pas à sp+0xC0. Le pointeur d'index-array est chargé depuis [x29-8], et le load d'index utilise l'adresse base + x24*8. Les anciennes conclusions sur w9 obtenues à partir de sp+0xC0 ne sont donc pas fiables.

Un nouveau probe ciblé a été ajouté pour recalculer depuis le dump le vrai x24, le pointeur [x29-8], w20 depuis la paire x23, le record x27, les valeurs w9/w8/w12, l'adresse effective du load [x8-8] et le qword post-écriture (à ne pas confondre automatiquement avec la valeur pré-écriture).

Script : tools/nx2/probe_orbitals_memcpy_branch_exact.py
Workflow : orbitals-memcpy-branch-exact
Commit du script : f071ab5200b5d55d93fb306d1b87bf35d427d00c
Commit du workflow : 4f55d32fcf54aafff57b2d2fb55159da01d0ba74

**État :** probe ajouté sur analysis/recomp-build; son artefact doit être consulté avant de choisir un patch. Aucun patch de la taille n'est appliqué. Le défaut de marshalling source du chemin fallback reste distinct et confirmé, mais ne doit pas être confondu avec la provenance du DWORD de taille.



## Cause guest du size : branche d'écriture rendue impossible par le flag (probe corrigé)

Le probe `orbitals-memcpy-branch-exact` a été corrigé pour lire les registres vivants depuis le contexte hostfn, et non les sauvegardes de registres du caller. Il confirme les valeurs suivantes dans le dump 16952 :

- `x21 = 0x0E40012810`
- `x27 = 0x0CE01F2C00`
- `x29 = 0x11C51F740`
- `x24 = 0x78` (itération courante 120)
- `x23 = 0x128F170000`
- paire de boucle à `x23 + x24*8 = 0x128F1703C0`, DWORD `w20 = 0`
- base du tableau `[x21+0x158] = 0x0CE01F2C00`, limite 10 ; le record sélectionné est bien le record 0 (`x27 == table_base + 0*0xE8`)
- `[x27+0xD8] = -3`
- `[x29-8] = 0x128F170008`, et `w9 = [0x128F1703C8] = -1159757815`
- comparaison signée `w9 < w8` : vraie
- flag conservé sur la pile `[sp+0x4C] = 0x70`, donc bit 0 = 0
- local consommé plus tard `[sp+0x88] = 0x01490140`

Le flot AArch64 est décisif :

```asm
cmp  w9, w8
cset w9, lt
and  w9, w12, w9
tbz  w9, #0, 0x1759ef8
...
0x1759ef8: b.le 0x1759da0
...
0x1759f4c: ldrsw x25, [sp, #0x88]
0x1759f7c: lsl x2, x25, #2
```

Le chemin qui écrit le DWORD dans `[sp+0x88]` commence après le `tbz` et contient `ldur d0,[x8,#-8]` puis `str d0,[sp,#0x88]`. Or `w12` est restauré à chaque itération depuis `[sp+0x4C]`; son bit 0 vaut zéro dans ce dump. Donc `w12 & (w9 < w8)` a nécessairement le bit 0 à zéro : le `tbz` saute le bloc qui écrit le local. La comparaison est vraie, mais elle est neutralisée par le flag.

Le local `[sp+0x88]` atteint ensuite `ldrsw` sans que le bloc conditionnel l'ait initialisé. La valeur résiduelle `0x01490140` est multipliée par quatre et devient exactement `0x05240500` (86 246 656 octets). Ce n'est donc pas une longueur guest raisonnable issue du buffer source : c'est une valeur de pile non initialisée consommée comme longueur.

Cette conclusion corrige l'hypothèse antérieure du rapport qui attribuait directement `0x01490140` à la donnée chargée depuis le record courant. Dans l'itération capturée (record 0, itération 120), le bloc de chargement/stockage est sauté ; le qword à l'adresse théorique `0x0CE01F2B48` dans le snapshot est postérieur aux écritures ultérieures et n'est pas la provenance démontrée du DWORD local.

Probe corrigé :
- commit : `c7fcd48de79be86899272ef32e223c70e33f87a`
- run : https://github.com/sinedgiveaways/tool/actions/runs/45495545903
- artefact : https://github.com/sinedgiveaways/tool/actions/runs/45495545903/artifacts/14968113355

## Correctif à appliquer — initialisation du local, puis marshalling source

Le correctif minimal à valider est maintenant clair sur le plan sémantique : initialiser le local guest correspondant à `[sp+0x88]` à zéro avant la boucle/avant tout chemin conditionnel, ou garantir que le chemin qui saute son affectation ne peut pas atteindre le `ldrsw` consommateur. La valeur par défaut zéro est la seule valeur neutre sûre en l'absence d'une entrée ayant écrit une longueur. Ne pas plafonner la taille à une constante arbitraire.

Le correctif distinct du marshalling doit également écrire le vrai pointeur guest `x1 = 0x11C51F8A8` dans `[context+8]` sur le chemin fallback. Les deux changements sont nécessaires pour éviter à la fois la longueur hors limites et la source non canonique.

**Aucun de ces deux changements n'est encore déclaré jouable.** Le workflow `orbitals-memcpy-size-local-host-layout` inspecte maintenant le prologue x86-64 généré et les accès au local `[rbx-0x98]` dans le DLL exact de la release. Il doit établir le point d'insertion sûr et les octets d'origine avant de produire un patch binaire versionné. Il ne lance ni `setup.py`, ni `prepare.py`, ni génération/recompilation du jeu.



## Patch binaire combiné généré — 24 novembre

L'inspection du DLL exact a confirmé les accès machine au local :
- entrée de `f_7001759b20` : `orbitalgame.dll+0x1B5A8470) ;
- `mov rbx,[rsi+0x100]` à RVA `0x1B5A84AE` charge le SP guest pré-prologue ;
- le point juste après, RVA `0x1B5A84B5`, contient `lea r14,[rbx-0x120]` et sert de site d'insertion sûr après chargement de RBX ;
- l'unique écriture du local est `mov [rbx-0x98],r9` à RVA `0x1B5A8BAD` ;
- lecture consommatrice : `movsxd r8,dword ptr [rbx-0x98]` à RVA `0x1B5A8E13` ;
- la troisième référence à `rbx-0x98` (RVA `0x1B5A91C4`) ne fait que calculer l'adresse et la passer dans le contexte ; ce n'est pas une initialisation.

Le patcher versionné applique deux modifications dans le même DLL :
1. À RVA `0x1B5A84B5), remplace l'instruction de 7 octets par un saut vers un trampoline qui rejoue la LEA originale, exécute `mov qword ptr [rbx-0x98],0`, puis revient à `0x1B5A84BC).
2. À RVA `0x1B5A9385), rejoue l'écriture originale du PC guest, ajoute `mov [rsi+8],r9` pour transmettre le pointeur guest `x1`, puis revient à `0x1B5A938C`.

Le second trampoline est placé à `CAVE_RVA+0x20) ; les deux utilisent le padding INT3 vérifié de la release. Les instructions d'origine sont conservées dans les trampolines. Le DLL est verrouillé par SHA-256 et PDB GUID/âge.

Patcher : `tools/nx2/apply_orbitals_memcpy_size_and_source_patch.py`  
Workflow : `orbitals-memcpy-size-and-source-patch`  
Commit patcher : `5efb7c4325dd776cce86d890acbea9f4310d4792`  
Commit correction RVA/fichier : `c13b8f6e1cfa246ceebc940e1fa211ed268528eb`  
Run de production : https://github.com/sinedgiveaways/tool/actions/runs/45496338669  
Artefact : https://github.com/sinedgiveaways/tool/actions/runs/45496338669/artifacts/14968721707

Hashes :
- DLL d'origine : `8678d073fdffc4f3d518f492dbc3428f7257dc1ebe8467bb85d87a6633d97cf4`
- DLL patché : `b0f31b26d16f433b0a4a9767d5237d0eb487ff177deb8b56458029a065106e41`

**Validation actuelle :** création du patch et vérification des octets/branches/trampolines réussies dans GitHub Actions. Le DLL n'a pas encore été lancé dans le jeu : ce patch est un candidat à tester, pas une correction gameplay certifiée. Il ne faut pas déclarer le crash résolu avant un test du jeu, plusieurs démarrages et une traversée des transitions où les crashes se produisaient. Aucune préparation, régénération ou recompilation du jeu n'a été exécutée.
