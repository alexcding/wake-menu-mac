# Contributing to WakeMenu

Thanks for your interest! WakeMenu is a small, single-file Swift app — easy to hack on.

## Project layout

```
WakeMenu/
├── src/main.swift   # the entire app (model, WoL, discovery, UI)
├── build.sh         # compiles src/main.swift into WakeMenu.app
├── README.md
└── LICENSE
```

## Building

```sh
./build.sh        # produces WakeMenu.app (ad-hoc signed)
open WakeMenu.app
```

Requires the Xcode command-line tools (`xcode-select --install`). No external packages.

## Code conventions

- Keep it dependency-free and in a single `src/main.swift` unless there's a strong reason to split.
- Match the existing style: small `enum` namespaces for logic (`WOL`, `Net`, `Pinger`, `Resolver`), `AppDelegate` for UI/state.
- Networking that may block runs off the main thread; UI updates hop back to `DispatchQueue.main`.

## Pull requests

1. Fork and create a feature branch.
2. Make sure `./build.sh` compiles cleanly with no warnings.
3. Describe what you changed and how you tested it (which macOS version, real WoL target, etc.).

## Ideas / good first issues

- Remote shutdown/sleep via SSH
- "Wake & wait" (send packet, watch the dot flip to online)
- Launch-at-login toggle inside the app
- MAC vendor (OUI) lookup in the discovery list
- Scheduled wakes
