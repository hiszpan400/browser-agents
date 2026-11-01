# Browser Agents — Setup & Status

## Status wdrożenia

| Agent | Kod | Zależności | Model | Gotowy |
|---|---|---|---|---|
| ghost-browser | ✅ | ✅ | ⚠️ qwen2.5:7b (w trakcie pobierania) | ⏳ |
| laya-ultrafast | ✅ | ✅ | ✅ Laya MLX (lokalne) | ⚠️ Browser Harness |
| browser-use | ✅ | ✅ | ⚠️ qwen2.5:7b (w trakcie pobierania) | ⏳ |
| FastAPI service | ✅ port 8900 | ✅ | — | ✅ |
| launchd autostart | ✅ | — | — | ✅ |
| Guardian AI patch | ✅ prepared | — | — | ⏳ RPi offline |

## ⚠️ Wymagane kroki użytkownika

### 1. Browser Harness dla laya-ultrafast (jednorazowo)

laya-ultrafast wymaga Browser Harness do połączenia z Chrome via CDP.
Chrome musi być uruchomiony z remote debugging:

**Opcja A: Restart Chrome z CDP (zamknie bieżące karty!)**
```bash
# Zamknij Chrome, potem uruchom z debuggiem:
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --user-data-dir=/tmp/chrome-debug-profile
```

**Opcja B: Zezwól przez chrome://inspect (polecana)**
1. Otwórz Chrome → `chrome://inspect/#remote-debugging`
2. Zaznacz "Discover network targets"
3. W terminalu uruchom:
   ```bash
   cd ~/browser-agents/agents/laya_ultrafast
   ~/.local/bin/uv run browser-harness mac-approve
   ```

Po konfiguracji sprawdź:
```bash
cd ~/browser-agents/agents/laya_ultrafast
~/.local/bin/uv run browser-harness --doctor
# Powinno pokazać: [ok] daemon alive, [ok] active browser connections
```

### 2. Guardian AI — wdrożenie patch (gdy RPi wróci online)

Plik patch: `~/browser-agents/guardian-ai-patch.md`

```bash
# Gdy SSH do RPi znowu działa:
scp pi@192.168.0.76:/home/pi/guardian-ai/src/index.ts /tmp/guardian-index.ts
# → zastosuj zmiany z guardian-ai-patch.md
# → deploy jak zwykle
```

### 3. Zmiana modelu na Oracle Cloud (gdy Oracle wróci)

Edytuj `~/browser-agents/.env`:
```env
GHOST_OLLAMA_HOST=http://100.71.250.62:11434
GHOST_MODEL=gemma4:e4b
TEXT_MODEL_BASE_URL=http://100.71.250.62:11434/v1
TEXT_MODEL=gemma4:e4b
```
Potem `launchctl stop com.jarvis.browser-agents && launchctl start com.jarvis.browser-agents`

## Użycie (gdy wszystko skonfigurowane)

```bash
# Health check
curl http://localhost:8900/health

# Test ghost-browser
curl -X POST http://localhost:8900/task \
  -H "Content-Type: application/json" \
  -d '{"goal": "Sprawdź tytuł strony google.com", "url": "https://google.com", "agent": "ghost"}'

# Test laya-ultrafast (po Browser Harness setup)
curl -X POST http://localhost:8900/task \
  -H "Content-Type: application/json" \
  -d '{"goal": "Find one-way flights from Warsaw to Madrid on Oct 15", "url": "https://www.google.com/travel/flights", "agent": "laya"}'

# Test browser-use (headless)
curl -X POST http://localhost:8900/task \
  -H "Content-Type: application/json" \
  -d '{"goal": "Znajdź tytuł strony example.com", "agent": "browser_use"}'
```

## Logi

```bash
tail -f /tmp/browser-agents.log
tail -f /tmp/browser-agents-err.log
```

## Zmiana modelu

Edytuj `~/browser-agents/.env` → `GHOST_MODEL=<nowy_model>`  
Zrestartuj: `launchctl stop com.jarvis.browser-agents && launchctl start com.jarvis.browser-agents`
