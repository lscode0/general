# AQ-REA — AdventureQuest 3D reverse engineering

Reverse-engineering notes and recovered metadata for **AdventureQuest 3D** (Android,
`com.battleon.aq3d`, Unity **IL2CPP**, metadata version **31**, version **1.161.0**),
produced with [REA](https://github.com/morluto/rea) (`rea-agents`) and a small
`global-metadata.dat` parser.

> Research/interoperability use only, on a publicly available copy of the app.
> Do not use to bypass protections or tamper with the live game.

## Contents

| Path | Description |
|---|---|
| `REPORT.md` | Full report (PL): provenance, method, protocol map, game-logic findings, limitations, how to finish with `libil2cpp.so` |
| `tools/il2cpp_metadata_dump.js` | Standalone Node parser/dumper for IL2CPP `global-metadata.dat` v31 (types, fields, properties, methods, params, string literals) |
| `data/dump_metadata.txt` | Recovered type/member surface (Assembly-CSharp: 3337 types; incl. fields, props, methods, params) |
| `data/dump_stringliterals.txt` | 22,332 managed string literals (endpoints, keys, UI/format strings) |
| `data/cmd_opcodes.txt` | Network opcode map — 37 `Cmd*` enum groups (Admin, Area, … Trade) |
| `data/protocol_messages.txt` | 478 `Request*`/`Response*` message types |
| `data/meta_stats.txt` | Assembly/image inventory and metadata counters |
| `evidence/rea_manifest.xml` | AndroidManifest decoded by REA (JADX headless) |
| `evidence/rea_android_pkg.json` | REA evidence bundle for `inspect-android-package` |

## Headline findings

- Entire game logic lives in **IL2CPP** (Assembly-CSharp); the Java/DEX layer is only the
  Unity player + Google Play Billing / Facebook SDK / Firebase / ads + `com.battleon.aq3d.R`.
- **Network protocol** is described by 37 opcode groups (`CmdCombat`, `CmdItem`, `CmdQuest`,
  `CmdGuild`, `CmdPvP`, `CmdHousing`, `CmdTrade`, …) and 478 `Request*`/`Response*` classes.
- **Combat**: `DamageModel` (Damage/Heal/DoT/HoT/Berserk/PercentHp/…), `CombatSolver`
  (GCD, spell queue, cooldowns), `SpellCastData`, `SpellVersion`, `EntityStats`, `StatMod`.
- **Service endpoints** (string literals): `game.aq3d.com/api`, `code.aq3d.com/api`,
  `code2.aq3d.com/api`, `content.aq3d.com/api`, `admin.aq3d.com/content/MapAssets/`.

## Reproduce

```sh
# 1) metadata dump (no native library required)
node tools/il2cpp_metadata_dump.js /path/to/global-metadata.dat out/

# 2) Android package/Java analysis with REA
export REA_JADX_MCP_JAR=/absolute/path/jadx-headless-mcp-0.7.1-all.jar   # + JDK 17+
npx rea-agents inspect-android-package /path/to/aq3d.apk
npx rea-agents search-android-classes  /path/to/aq3d.apk ""
```

## Not included (by design)

- The game APK and Unity data blobs, and the missing ABI split (`config.arm64_v8a`,
  `lib/arm64-v8a/libil2cpp.so`). The store distributed an **AAB "base" module** only, and
  public APK mirrors gate the split behind captchas (APKPure = Tencent EdgeOne,
  Uptodown = Cloudflare Turnstile, APKCube = Turnstile + PoW, apkfab/apkcombo = Cloudflare).
- Because of that, this repo has **no method bodies / RVAs**. See `REPORT.md` §8 for how to
  obtain `libil2cpp.so` (e.g. `rea pull-adb-package com.battleon.aq3d` from a device) and run
  Il2CppDumper / Cpp2IL.
