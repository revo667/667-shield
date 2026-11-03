# Vendored: GoodbyeDPI engine (DPI bypass)

These files are **vendored third-party binaries**, bundled unmodified into 667
Shield to power the DPI-bypass feature (reaching ISP-blocked sites such as
Discord, Roblox and Wattpad). 667 Shield runs them as:

```
goodbyedpi.exe -5 --blacklist blacklist.txt
```

## Source & version

- **Engine:** GoodbyeDPI **0.2.2** by **ValdikSS**
  <https://github.com/ValdikSS/GoodbyeDPI> — License: **Apache-2.0**
- **Bundled driver:** WinDivert (by Basil00), redistributed inside the GoodbyeDPI
  release — License: **LGPLv3 / GPLv3** (see `licenses/LICENSE-windivert.txt`)
- Pulled from the official release asset `goodbyedpi-0.2.2.zip`
  SHA-256 `00a2f8b99cd817f8c7fc4c449033015f039d18af213de78cb66bf202277c0628`

The Turkey focus and the idea of a blacklist limited to Discord / Roblox /
Wattpad come from **SplitWire-Turkey** by **cagritaskn**
<https://github.com/cagritaskn/SplitWire-Turkey> (License: MIT). Our
`blacklist.txt` is our own small list; `presets.txt` uses GoodbyeDPI's own modes.

## Files & checksums (SHA-256)

```
331ac6c1d22ba5a0a217f3f27d0d823051869cafc8b8ef7f2002fa2accebc74e  x86_64/goodbyedpi.exe
a97859785a2df1d4462e7d48d33ccbd89fedd40dac4970f4afd89e63f59ee1ec  x86_64/WinDivert.dll
53ab28ec00be6e6f8aefa9ee76fc2735e94d7f3f9dbc06eb2b7ac8cd3084a6af  x86_64/WinDivert64.sys
```

`blacklist.txt`, `presets.txt` and this file are authored by the 667 Shield
project; `licenses/` and `service_remove.cmd` are from the GoodbyeDPI release.

## Thanks

Huge thanks to **ValdikSS** for GoodbyeDPI and to **cagritaskn** for
SplitWire-Turkey — this feature stands entirely on their work. Please support
the upstream projects.
