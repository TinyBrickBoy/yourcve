# yourcve

Selbst gehosteter CVE Alarm: Techstack in der Web UI zusammenklicken (oder `package.json`, `go.mod`, `requirements.txt`, `docker-compose.yml`, CycloneDX/SPDX importieren) und per Discord, Slack, Teams, Mattermost, Telegram, Matrix, ntfy, Gotify, Pushover, Webhook oder Email benachrichtigt werden, sobald eine passende CVE erscheint. Eine lokale KI (Ollama) fragt die Daten über REST und MCP ab und schreibt englische Kurzfassungen.

```
Internet → Caddy (TLS) → Anubis (Bot Schutz) → yourcve (ein Go Binary) → PostgreSQL 17 (pgvector, pg_trgm) → WAL-G → S3
                                                   ↘ Ollama (optional)
```

Ein Binary enthält UI, API, MCP, Ingest, Matcher, KI Worker und Versand. Alle Worker sprechen nur mit PostgreSQL (Jobs mit River, Outbox in `deliveries`), daher ist der App Container zustandslos und setzt nach jedem Neustart am gespeicherten Stand fort.

## Schnellstart

```bash
git clone https://github.com/tinybrickboy/yourcve && cd yourcve
cp .env.example .env
```

In `.env` mindestens setzen: `BASE_URL`, `DOMAIN`, `SECRET_KEY` (`openssl rand -hex 32`), `POSTGRES_PASSWORD`, `ADMIN_EMAILS`, `SMTP_URL`, `SMTP_FROM`. Ein `NVD_API_KEY` macht den Erstimport rund zehnmal schneller.

```bash
docker compose --profile tls up -d          # Caddy + Anubis + yourcve + PostgreSQL
docker compose --profile tls --profile ai up -d   # zusätzlich Ollama mit den beiden Modellen
```

Ohne `--profile tls` lauscht Anubis auf Port 8923 und dein eigener Reverse Proxy zeigt dorthin (er muss `X-Real-Ip` setzen, ohne Proxy `ANUBIS_USE_REMOTE_ADDRESS=true`).

Beim ersten Start importiert yourcve die komplette Historie (cvelistV5 Archiv, NVD, OSV Ökosysteme, CPE Katalog). Das dauert je nach API Key 30 bis 90 Minuten; der Fortschritt steht unter **Admin** und im Log. Ohne `SMTP_URL` werden Login Links ins Log geschrieben (`docker compose logs yourcve | grep link`).

## Deployment mit Coolify

Für Coolify gibt es `docker-compose.coolify.yml`. Coolify erzeugt Domain, Datenbank Passwort, `SECRET_KEY` und den Anubis Schlüssel selbst (Magic Variables) und macht TLS mit seinem Proxy; eine `.env` und Caddy sind nicht nötig.

1. In Coolify: Projekt öffnen, **+ New**, das Git Repository wählen (öffentlich oder per GitHub App).
2. Unter **General**: Build Pack **Docker Compose**, Base Directory `/`, Docker Compose Location `/docker-compose.coolify.yml`. Speichern und **Reload Compose File**.
3. Unter **Domains** beim Service **anubis** deine Domain mit internem Port eintragen, z.B. `https://cve.example.com:8923` (der Port ist nur der Container Port, aufgerufen wird normal über 443).
4. Unter **Environment Variables** mindestens `ADMIN_EMAILS` setzen (Pflicht), dazu empfohlen `SMTP_URL`, `SMTP_FROM`, `NVD_API_KEY`; optional `OLLAMA_URL` für eine externe Ollama Instanz und `WALG_S3_PREFIX` mit S3 Zugang für Backups.
5. **Deploy**. Der erste Build (UI und Go Binary) dauert einige Minuten, danach startet der Erstimport der CVE Historie (Fortschritt im Admin Dashboard).

Impressum und Datenschutzerklärung bearbeitest du in Coolify unter **Persistent Storage** (`coolify/imprint.html`, `coolify/privacy.html`). `SERVICE_HEX_64_SECRETKEY` darf nach dem ersten Start nicht mehr geändert werden, sonst lassen sich gespeicherte Kanal Secrets nicht mehr entschlüsseln. Anubis braucht den Header `X-Real-Ip`; der Standard Proxy von Coolify (Traefik) setzt ihn. Wer in Coolify Caddy als Proxy nutzt, muss den Header dort ergänzen.

## Datenquellen

| Quelle | Takt | Verfahren |
| --- | --- | --- |
| cvelistV5 | 1 min | Erstimport aus dem Release Archiv; danach Git `ls-refs` auf `main` (wenige Bytes, kein API Limit) und Range Request auf `cves/deltaLog.json` des Commits |
| NVD API 2.0 | 1 min | `lastModStartDate` Cursor, CVSS, CWE, CPE Konfigurationen; Backoff bei 403/429 |
| CISA KEV | 1 min | `If-None-Match`, unveränderte Daten kosten nichts |
| FIRST EPSS | 1 h | Import nur bei neuem `score_date` (einmal am Tag) |
| OSV.dev | 1 min | Erstimport `<ökosystem>/all.zip`, danach Kopf von `modified_id.csv` per Range Request |
| NVD CPE Dictionary | 24 h | Produktkatalog für den Stack Builder |

Takte per `INTERVAL_*` einstellbar. Jede Quelle speichert ihren Cursor in `sync_state`; Verzögerung pro Quelle zeigt das Admin Dashboard und `yourcve_ingest_lag_seconds`.

## Matching und Benachrichtigungen

Stack → Produkt → `cve_affects` (Versionsbereiche aus NVD, OSV und CNA). Versionsvergleich nach Ökosystem: SemVer, Debian, RPM, PEP 440, generisch. Treffer über CNA Daten ohne CPE gelten als **unconfirmed**. Pro Treffer wird der Grund angezeigt; „not affected“ oder „patched“ stoppt weitere Meldungen.

Nach jedem Import läuft der Matcher als River Job. Neue Treffer schreiben in derselben Transaktion Outbox Zeilen (`deliveries`, eindeutig pro CVE × Stack × Kanal × Anlass: `new`, `kev_added`, `cvss_raised`). Regeln: Mindest CVSS, nur KEV, Mindest EPSS, sofort/stündlich/täglich, Ruhezeiten mit Zeitzone. Über `MAX_MESSAGES_PER_CHANNEL_HOUR` (Standard 20) gehen weitere Meldungen in eine Sammelnachricht. Retries mit Backoff (30 s bis 12 h, 8 Versuche), fehlgeschlagene Zustellungen lassen sich in der UI erneut senden. Kanal Secrets liegen mit Envelope Encryption (AES-256-GCM, Schlüssel aus `SECRET_KEY` per HKDF) in der Datenbank.

Webhooks: nur HTTPS, IP Prüfung nach der DNS Auflösung bei jedem Verbindungsaufbau (private Netze geblockt), keine Redirects, 10 s Timeout, Signatur `X-Yourcve-Signature: sha256=HMAC(secret, timestamp + "." + body)`.

## API und MCP

OpenAPI: [`api/openapi.yaml`](api/openapi.yaml). Auth per Session (UI) oder API Key (`Authorization: Bearer yc_…`, unter Settings anlegen).

MCP Endpunkt `POST /mcp` (Streamable HTTP), nur lesende Tools: `search_cves`, `get_cve`, `explain_cve`, `list_stacks`, `cves_for_stack`, `semantic_search` (mit Ollama). Beispiel für einen MCP Client:

```json
{ "mcpServers": { "yourcve": { "type": "http", "url": "https://yourcve.example.com/mcp",
  "headers": { "Authorization": "Bearer yc_..." } } } }
```

## KI (optional)

`OLLAMA_URL` setzen (z.B. `http://ollama:11434` mit `--profile ai`). Modelle: `OLLAMA_MODEL` (Standard `qwen2.5:3b-instruct`) und `nomic-embed-text`. Kurzfassung und Kategorie entstehen nur für CVEs mit Treffern oder aus den letzten `AI_RECENT_YEARS` Jahren und werden gecacht. Schutz vor erfundenen Details: nur die Beschreibung als Input, JSON Schema, Temperatur 0.1, Ausgaben mit fremden CVE IDs oder Scores werden verworfen; Fakten kommen nie aus der KI. In UI und Nachrichten steht „AI generated“.

## Betrieb

**Update**: `docker compose pull && docker compose up -d` startet nur den App Container neu (wenige Sekunden). Laufende Zustellungen werden beim Stoppen zu Ende gebracht (`stop_grace_period: 30s`), Jobs und Outbox liegen in PostgreSQL. Migrationen laufen beim Start automatisch und sind nur erweiternd.

**Backup**: `WALG_S3_PREFIX` und S3 Zugang setzen. PostgreSQL archiviert WAL laufend (`archive_timeout=60`), dazu ein tägliches Basis Backup, die letzten `BACKUP_RETAIN_FULL` bleiben.

**Wiederherstellung** (monatlich testen):

```bash
docker compose stop yourcve postgres
mv pg pg.old && mkdir pg
docker compose run --rm --entrypoint sh postgres -c \
  'wal-g backup-fetch "$PGDATA" LATEST && touch "$PGDATA/recovery.signal" &&
   echo "restore_command = '\''wal-g wal-fetch %f %p'\''" >> "$PGDATA/postgresql.auto.conf" &&
   chown -R postgres:postgres "$PGDATA" && chmod 700 "$PGDATA"'
docker compose up -d
```

Für Point in Time Recovery zusätzlich `recovery_target_time = '2026-11-20 10:00:00+00'` eintragen. Major Updates von PostgreSQL: frisches Backup, dann `pg_upgrade`.

**Monitoring**: `/healthz`, `/readyz`, `/metrics` (Prometheus: Ingest Läufe und Lag, Zustellungen, HTTP Latenz), Admin Dashboard mit Sync Status, Queue und Versandfehlern.

**Ressourcen**: ohne KI 2 vCPU, 4 GB RAM, ca. 20 GB Disk; mit Ollama auf CPU zusätzlich 6 bis 8 GB RAM.

**Email Zustellbarkeit**: Für die Absender Domain SPF, DKIM (signiert dein Mailserver) und DMARC einrichten. Email Kanäle haben Double Opt in, jede Mail einen Abmeldelink und `List-Unsubscribe` Header.

**DSGVO**: `config/imprint.html` und `config/privacy.html` anpassen (werden unter `/imprint` und `/privacy` angezeigt). Nutzer löschen ihr Konto mit allen Daten selbst unter Settings. Mit Plus später AV Verträge mit seven.io und Stripe.

## Konfiguration

| Variable | Standard | Bedeutung |
| --- | --- | --- |
| `BASE_URL` | – | öffentliche URL |
| `SECRET_KEY` | – | min. 32 Zeichen, verschlüsselt Kanal Secrets, signiert Captchas |
| `DATABASE_URL` | – | PostgreSQL 17 mit pgvector |
| `ADMIN_EMAILS` | – | Kommagetrennt, bekommen das Admin Dashboard |
| `REGISTRATION_OPEN` | `true` | offene Registrierung |
| `FREE_MAX_STACKS` / `FREE_MAX_CHANNELS` | `5` / `5` | Limits im Free Plan |
| `SMTP_URL` / `SMTP_FROM` | – | `smtp://user:pass@host:587` (STARTTLS) oder `smtps://…:465` |
| `NVD_API_KEY`, `GITHUB_TOKEN` | – | schnellerer NVD Import, Release Abfrage |
| `INITIAL_IMPORT` | `true` | komplette Historie beim ersten Start |
| `OSV_ECOSYSTEMS` | npm,PyPI,Go,… | OSV Ökosysteme |
| `INTERVAL_CVELIST`, `_NVD`, `_KEV`, `_OSV` | `1m` | Takt pro Quelle |
| `INTERVAL_EPSS`, `INTERVAL_CPE` | `1h`, `24h` | |
| `OLLAMA_URL`, `OLLAMA_MODEL`, `OLLAMA_EMBED_MODEL` | – | KI, leer = aus |
| `AI_RECENT_YEARS`, `AI_CONCURRENCY` | `3`, `1` | |
| `MAX_MESSAGES_PER_CHANNEL_HOUR` | `20` | darüber Sammelnachricht |
| `EMAIL_RATE_PER_HOUR` | `30` | Emails pro Nutzer und Stunde |
| `ALLOW_PRIVATE_TARGETS` | `false` | Kanäle im privaten Netz erlauben (z.B. eigenes ntfy im LAN) |
| `TRUST_PROXY` | `true` | Client IP aus `X-Real-Ip` |
| `IMPRINT_FILE`, `PRIVACY_FILE` | – | HTML Dateien |
| `LOG_LEVEL` | `info` | |

## Entwicklung

```bash
cd web && npm ci && npm run build && cd ..          # UI nach web/build (wird eingebettet)
go run ./cmd/yourcve                                  # braucht DATABASE_URL, SECRET_KEY
cd web && npm run dev                                 # UI mit Proxy auf :8080
TEST_DATABASE_URL=postgres://…/yourcve_test go test ./...   # inkl. Ende zu Ende Tests (Datenbank wird geleert)
```

## Stand gegenüber dem Plan

Phasen 0 bis 5 und 7 sind umgesetzt. Phase 6 (Plus mit SMS, WhatsApp, Anruf über seven.io und Stripe) kommt laut Plan nach dem Start: Tabellen `credit_ledger` und `channel_prices`, `GET /v1/credits` und die „Coming soon“ Kanäle in der UI sind vorbereitet.

Abweichungen: Go 1.26+ statt 1.25 (aktuelle Versionen von River, goose und go-webauthn verlangen es). Datenbankzugriff mit handgeschriebenen pgx Queries statt sqlc. Die OpenAPI Datei ist der Vertrag, die Handler sind von Hand geschrieben statt mit oapi-codegen generiert. Discord, Slack, Teams und Mattermost laufen über einen eigenen HTTP Client mit SSRF Schutz (Discord mit Embeds); Telegram, Matrix, ntfy, Gotify und Pushover über Shoutrrr. cvelistV5 nutzt das Git Protokoll statt `git fetch`, weil das distroless Image kein git enthält.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
