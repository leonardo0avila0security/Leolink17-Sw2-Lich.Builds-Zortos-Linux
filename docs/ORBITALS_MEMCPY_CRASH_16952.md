# Orbitals — diagnostic du crash memcpy (dump 16952)

Date d'analyse : 2026-11-24  
Source : release [analysis-data](https://github.com/sinedgiveaways/tool/releases/tag/analysis-data), asset `orbitals-recomp.exe.16952.dmp.zip`  
SHA-256 de l'archive : `1046109831d1fa9451e3d8a047bbb07fd286a289c12035bebaf786f7b51f7dbd`  
Dump décompressé : 8,798,186,414 octets ; minidump AMD64 ; 94 threads ; 3,487 plages mémoire.

## Résumé exécutif

Le crash observé est une lecture invalide pendant une copie mémoire dans `ucrtbase.dll`. Les arguments invalides sont déjà présents dans le descripteur consommé par le helper de copie de `orbitals-recomp.exe`. Les données du dump ne justifient pas de modifier le chargeur d'imports.

Une correspondance forte a été trouvée : le qword source invalide est exactement le premier qword du buffer mémoire candidat situé à `0x11C51F700`. Ce buffer commence par les octets `40 01 3D 01 49 01 46 01` (quatre unités little-endian de 16 bits : `0x0140, 0x013D, 0x0149, 0x0146`). Le contenu du buffer semble donc avoir été interprété comme une adresse. Il reste à identifier l'instruction et la transformation qui ont placé ce contenu dans le champ source.

## Faits établis par le dump

- Exception : `0xC0000005`, thread `0x5B10` (23312).
- RIP : `ucrtbase.dll+0xEE44D`.
- Instruction fautive : `vmovdqu ymm0, ymmword ptr [rdx]`.
- Registres au point de faute :
  - destination RCX : `0x12E1A8000C`
  - source RDX : `0x01460149013D0140`
  - taille R8 : `0x05240500` = 86,246,656 octets
  - RSI : `0x1C92EAB0540`
- Le bloc à RSI a été capturé sur 0x400 octets. Ses premiers champs sont :
  - `+0x00 = 0x12E1A8000C`
  - `+0x08 = 0x01460149013D0140`
  - `+0x10 = 0x05240500`
  - `+0x40 = 0x01460149013D0140` (copie du qword source)
  - `+0x48 = 0x11C51F6F0`
  - `+0x50 = 0xFF`
  - `+0xD0 = 0x11C51F8A8`
  - `+0xD8 = 0xCE01F2C00`
- Le buffer candidat extrait à `0x11C51F700` commence exactement par le qword source invalide. L'adresse `+0x48` du descripteur (`0x11C51F6F0`) est 0x10 octets avant ce début de données. Cette proximité est une relation structurelle plausible, pas encore la preuve que `+0x48` est le propriétaire ou la source attendue.
- Le dump ne contient aucune référence directe au pointeur candidat `0x11C51F700` dans le scan exécuté. L'adresse candidate a été déduite de l'emplacement où le qword source apparaît comme contenu.
- Le helper natif de copie à `orbitals-recomp.exe+0x40CE0` lit le descripteur via `[rcx]`, `[rcx+8]`, `[rcx+0x10]`, puis transmet destination/source/taille au thunk à `orbitals-recomp.exe+0x70C430`. Le retour capturé est `orbitals-recomp.exe+0x40D1F`. Le helper reçoit donc déjà une source non canonique ; le crash n'est pas provoqué par le décodeur de `memcpy`.
- Le chemin natif de l'appelant contient un retour à `orbitalgame.dll+0x1B5A939F`, après un appel à `orbitalgame.dll+0x1C11DF00` à `+0x1B5A939A`. Un autre retour est présent à `orbitalgame.dll+0x1C11DF58`. Ces adresses sont des points d'ancrage de pile, pas encore une attribution symbolique complète aux fonctions guest.

## Import memcpy : conclusion

Le dump montre :
- GOT guest `0x700900A008 = 0x7020002CD0`
- slow-dispatch lookup : clé `0x7020002CD0` trouvée à l'index `0x7B3`
- entrée hostfn `memcpy`, slot `0x2CD`, cible `orbitals-recomp.exe+0x40CE0`

Cela confirme que `0x7020002CD0` est un identifiant/adresse synthétique du runtime et que le chemin hostfn aboutit au helper de copie. Ne pas patcher le chargeur d'imports sur la seule base de cette panne.

## Points non démontrés / à ne pas confondre

- La valeur signée `-3` mentionnée dans une autre inspection à l'offset `+0xD8` n'est pas confirmée par le descripteur RSI de ce dump : ici `RSI+0xD8 = 0xCE01F2C00`, qui est un pointeur. Ne pas fusionner ces deux structures ou deux observations sans retrouver leurs bases respectives.
- Les noms guest `f_7001759b20` et `f_70017508e0` restent à raccorder à ce chemin natif. Le workflow de recherche de source C n'a trouvé aucun fichier C contenant ces noms ; l'archive setup-work contient surtout des objets compilés et les sources générées n'étaient pas présentes.
- La cause racine (mauvais offset, double déréférencement, mauvais type/layout, corruption antérieure ou durée de vie invalide) n'est pas encore prouvée.

## Prochaines analyses requises

1. Extraire depuis le dump les octets autour de `0x11C51F6F0` (header potentiel) et `0x11C51F700`, ainsi que les régions qui référencent `0x11C51F6F0`.
2. Désassembler/unwinder précisément le chemin depuis `orbitalgame.dll+0x1B5A939A` à travers le wrapper `+0x1C11DF00`, le dispatcher, puis `orbitals-recomp.exe+0x40CE0`.
3. Reconstituer la provenance des champs `[descriptor+0]`, `[descriptor+8]`, `[descriptor+0x10]` au moment où le descripteur est créé. Chercher l'endroit où l'adresse `0x11C51F700` est remplacée par son contenu `0x01460149013D0140`.
4. Raccorder le chemin hôte aux fonctions guest `f_7001759b20` et `f_70017508e0` avec les symboles et l'objet compilé exacts.
5. Seulement après cette preuve, préparer un correctif minimal et un test de non-régression. Ne pas régénérer/recompiler tout le jeu pour chaque expérimentation.

## Artefacts d'analyse

- Workflow dump analysis : https://github.com/sinedgiveaways/tool/actions/runs/45455492238
- Artefact de rapports ciblés : https://github.com/sinedgiveaways/tool/actions/runs/45455492238
- Workflow d'inventaire du C généré (aucun fichier source correspondant trouvé) : https://github.com/sinedgiveaways/tool/actions/runs/45455524457
- Release des données : https://github.com/sinedgiveaways/tool/releases/tag/analysis-data
