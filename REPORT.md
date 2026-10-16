# AdventureQuest 3D — reverse engineering (Android, REA)

Data: 2026-10-16. Narzędzie: REA (`morluto/rea`, npm `rea-agents@6.5.0`) + własny parser
`global-metadata.dat`. Zakres: rozpoznanie logiki gry / protokołu z klienta Android.

## 1. Materiał wejściowy

| Pozycja | Wartość |
|---|---|
| Pakiet | `com.battleon.aq3d` |
| Wersja | 1.161.0 (versionCode 704) |
| Plik | `target/aq3d.apk` (base APK ze sklepu Aptoide „aptoide-web”) |
| md5 | `9877dd8f9f368295f9eb7c05bc395618` |
| sha256 (wg REA) | `8394cf34e7e38b8e6374ab08e80b17c9752b5f1e8fdc3a1247af9a76b0344806` |
| Silnik | Unity, skryptowanie **IL2CPP**, metadata version **31** |
| minSdk / targetSdk | 29 / 36 |

Brakuje **`lib/arm64-v8a/libil2cpp.so`**: to wydanie jest dystrybuowane jako AAB, a sklep
oddał tylko moduł „base”. Split ABI to `config.arm64_v8a`
(md5 `b076fd317f7e8f15e593a027f7a0e5b5`, 33 481 664 B). Wszystkie publiczne mirrory APK
blokują pobranie captchą (APKPure = Tencent EdgeOne, Uptodown = Cloudflare Turnstile,
APKCube = Turnstile + proof-of-work, apkfab/apkcombo = Cloudflare). Dlatego analiza jest
na poziomie **metadanych** (nazwy typów/metod/pól + literały), bez ciał metod/RVA.

## 2. Metoda

1. `target/il2cpp_metadata_dump.js` — parser `global-metadata.dat` v31 (układy struktur wg
   `Il2CppDumper`/Perfare, dostosowane do v31). Walidacja: magic `0xFAB11BAF`, version 31,
   typ[0] = `<Module>`, poprawne nazwy assembly (Assembly-CSharp.dll, mscorlib.dll, …).
2. REA na APK (JADX headless 0.7.1 + JDK 21):
   - `rea inspect-android-package` → `target/rea_android_pkg.json`, `target/rea_manifest.xml`
     (evidence_id `ev_7889f99fead2ee83127be0b683b94ebaad768809d2711b84dc3e163c80392886`)
   - `rea search-android-classes` (evidence_id `ev_045580e4fdfb73fa96ed6fc36655688d41e03db072bce395bf11a63e32b85cf0`)

Warstwa Javy jest cienka (8064 klasy: Unity player + Google Play Billing + Facebook SDK +
Firebase + reklamy + `com.battleon.aq3d.R`). Cała logika gry jest w IL2CPP.

## 3. Inwentaryzacja metadanych (Assembly-CSharp)

- typów w `Assembly-CSharp.dll`: **3337** (razem w pliku 14 627)
- metod: 96 699 · pól: 64 729 · właściwości: 16 432 · parametrów: 102 959
- literałów string: **22 332**
- 100 obrazów (assembly): Assembly-CSharp, Assembly-CSharp-firstpass, Unity.*, System.*,
  Newtonsoft.Json (JSON!), Facebook.Unity, itd.

Pełny zrzut: `target/dump_metadata.txt` (typy + pola/właściwości/metody/parametry),
`target/dump_stringliterals.txt`.

## 4. Protokół sieciowy (najważniejsze znalezisko)

Protokół jest zdefiniowany enumami opkodów `Cmd*` (37 grup) i klasami
`Request*`/`Response*` (478 szt.), częściowo w
`Assets.Scripts.NetworkClient.CommClasses`. Pełna mapa: `target/cmd_opcodes.txt`,
lista komunikatów: `target/protocol_messages.txt`.

Grupy opkodów (`struct Cmd…`): Admin, Area, Audio, BagSpace, Bank, Cell, Channel, Chat,
Class, Combat, Command, DailyTask, Entity, Friend, Guild, Housing, Item, Leaderboard,
LiveEvent, Loot, Machine, Mail, Merge, Misc, Move, NPC, NpcMove, Party, Player, PvP, Quest,
Resource, ServerDaily, ServerTools, Sheathing, SystemPerformance, Trade.

Przykład — komendy walki (`CmdCombat`): `SpellRequest, SpellTrigger, SpellCancel, Spell,
EffectPulse, Item, IAO, MachineSpell, EffectRemove, ResetCD, AuraUpdate`.

Endpointy usług (z literałów): `https://game.aq3d.com/api`, `https://code.aq3d.com/api`,
`https://code2.aq3d.com/api`, `https://content.aq3d.com/api`,
`https://admin.aq3d.com/content/MapAssets/`, `https://aq3d.com/news/`,
`https://bugs.artix.com/tracker/...`.

## 5. Logika walki i postaci

- `DamageModel` (enum typów obrażeń): None, Damage, Heal, Resource, Kill, DoT, HoT, Berserk,
  PercentHpBonus, PercentHp, PercentCurrentHp, CasterHealByTargetHp, BerserkHeal,
  UltChargePercent.
- `CombatSolver`: `GCDBaseLength`, `Spell_Queue_Window`, `Auto_Attack_Response_Delay`,
  `Max_Target_Distance`, kolejka zaklęć, cooldowny; metody `IsGcdOver`, `GetRemainingCooldown`,
  `IsCoreSpell`, `SetGCDTrigger` itd.
- `SpellCastData`: `chargeTime`, `channelTime`, `aoeLocations`, `state`, `npcSpellID`.
- `SpellVersion` / `SpellUpgrade` / `SpellRequirement` / `SpellComboState`.
- `EntityStats` (tablica statystyk per encja, `Stat_Count`, dostęp po indeksie i po nazwie) +
  `StatMod` (`stat, type, percent, flat, useInverseHealth`).

## 6. Pozostałe podsystemy (klasy z dumpu)

Loot (`ComLoot`, `LootItem`, `LootItemAddress`, `LootBag*`, `Request/ResponseLoot*`,
`RequestOpenLootBox`), Inventory/Bank/Trade (`CmdItem`, `CmdBank`, `CmdTrade`,
`DropSurface*`), Quest (`ResponseQuestMeta`, 249 klas `*Quest*`), Guild (36 klas),
Housing (`Request/ResponseHouse*`, `ComHouse*`), PvP (`ResponsePlayerPvPStats`, 49 klas),
DailyTask, Mail, Friend, Leaderboard, LiveEvent, Machine, Craft, Mount/Pet.

## 7. Artefakty

```
target/aq3d.apk                     zrzut APK (base)
target/base/assets/bin/Data/...     data.unity3d, global-metadata.dat, boot.config
target/il2cpp_metadata_dump.js      parser/dumper metadanych v31
target/dump_metadata.txt            pełny zrzut typów i członków (Assembly-CSharp i in.)
target/dump_stringliterals.txt      22 332 literały stringów
target/cmd_opcodes.txt              mapa opkodów Cmd*
target/protocol_messages.txt        lista Request*/Response*
target/rea_android_pkg.json         dowód REA: manifest, uprawnienia, SDK
target/rea_manifest.xml             zdekodowany AndroidManifest
target/meta_stats.txt               statystyki/pozycje assembly
```

## 8. Jak dokończyć (ciała metod / RVA)

Metadane dają pełną *powierzchnię API* gry, ale bez `libil2cpp.so` nie ma adresów i kodu.
Aby to uzyskać:

1. Na urządzeniu/emulatorze z zainstalowaną wersją 1.161.0:
   `rea pull-adb-package com.battleon.aq3d` (ściąga komplet splitów wraz z `lib/arm64-v8a/*.so`).
2. Uruchomić `Il2CppDumper` (albo `Cpp2IL`) na `libil2cpp.so` + `global-metadata.dat` →
   `dump.cs` z RVA i sygnaturami typów.
3. Opcjonalnie zdemontować wybrane metody (Ghidra/IDA, REA `annotate-native-function`).

Alternatywa bez urządzenia: dowolny mirror oddający XAPK/AAB (np. Google Play przez
konto + bundletool). Captche na publicznych mirrorach uniemożliwiają to w tym środowisku.

## 9. Zastrzeżenie

Analiza wyłącznie w celach badawczych/interoperacyjnościowych, na kopii aplikacji
publicznie dostępnej. Nie używać do omijania zabezpieczeń ani modyfikowania rozgrywki online.
