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
