# Wraith

real-time process surveillance tool for windows. uses ETW to track suspicious behavior -- processes that hide from task manager, headless apps calling window APIs, buffered log writes. dark UI with animated splash. built with C# / WPF / .NET 6.

## Requirements

- Windows 10/11 (x64)
- .NET SDK 6.0
- Administrator privileges

## Build

```
dotnet restore src/Wraith.csproj
dotnet build src/Wraith.csproj -c Release
dotnet publish src/Wraith.csproj -c Release -r win-x64 --self-contained
```

## License

MIT

---

MADE BY REAL
