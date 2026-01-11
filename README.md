# Metin1 ANI_FORMAT_ERROR Fix

A fix for Metin1 that resolves the `ANI_FORMAT_ERROR` on non-Chinese Windows systems.

## Download

Download `local.dll` from the [latest release](https://github.com/Helia01/Metin1-local-fix/releases/latest).

## Usage

Replace `local.dll` in the same folder as `mts.exe` (Metin1's main executable file).

Run the client with:
```
mts.exe ( --)(-- )/now 192.168.1.100 5001
```

## Compatibility

This fix works only with client version **1.0.0.56**. For other versions, you will need to modify the hook addresses in `main.c`.

## Local Build

```batch
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
cl /LD /Fe:local.dll main.c /link /DYNAMICBASE:NO
```

## How It Works

The library hooks `mbstowcs` and `CreateFileA` calls, converting paths and strings from GBK encoding (codepage 936) instead of the system locale.
