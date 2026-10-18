# iOS Porting Notes (read before claiming iOS support)

This mod targets the **desktop / Unity Editor (Mono)** backend of
AdventureQuest 3D. It is **NOT** an iOS build, and the `iPhone`/ARM64
build configs that exist here are stubs only.

## Why there is no iOS version yet

AQ3D on iOS ships a Unity **IL2CPP** build (Mono backend), not a Mono build.
The cheat's core depends on managed runtime bindings:

* `typeof(EntityController)`
* `Entities.Instance`, `Game.Instance`, `Stat.*` dictionary access
* `FindObjectsOfType<...>()`
* reflection / `System.Reflection` targets

Under IL2CPP those become native C++ types with generated names and no managed
metadata to bind against. There is no managed runtime to inject a `.dll` into
(or a `Main.cs` assembly the modloader could load). Runtime loading of
managed assemblies from a shipping app is blocked by iOS code-signing and
sandboxing.

What survives a hypothetical rewrite is only the UI shape and pure logic:
IMGUI menu screen, ESP drawing math, health/armor colours. Everything that
touches game state has to be rebuilt against IL2CPP function offsets — i.e.
reverse-engineering the shipped binary, which is a separate project, not a
port of this source.

## What this repo currently offers for iOS

Nothing functional. The code contains touch-handling scaffolding that will
compile under `UNITY_IOS`, but because the managed mod loader cannot run on an
IL2CPP binary it will never execute on iOS. The `iPhone`/ARM64 MSBuild
property groups must not be read as "this produces an iOS cheat."

## Honest scope statement

**Desktop / Unity Editor only.** No standalone Apple Silicon / iOS build of
this cheat ships in this branch.
