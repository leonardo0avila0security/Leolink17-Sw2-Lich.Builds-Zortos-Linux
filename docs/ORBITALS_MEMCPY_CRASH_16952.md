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

## Structure suspecte et valeur -3

Le champ `RSI+0xD8` contient le pointeur `0x0CE01F2C00`. L'objet pointé a été extrait dans `descriptor_ptr_0D8_0000000CE01F2C00.bin`. À l'offset `+0xD8` de CET objet, les octets sont :

```
FD FF FF FF 03 00 00 00
```

Le premier DWORD est bien un entier signé `-3` ; le DWORD adjacent vaut `3`. Donc la piste `-3` est réelle et localisée, mais il s'agit d'un champ de l'objet pointé par `RSI+0xD8`, pas du champ `RSI+0xD8` lui-même. Il faut identifier le type/layout de cet objet et retrouver comment ce champ est consommé avant d'en faire la cause du mauvais pointeur source.

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
