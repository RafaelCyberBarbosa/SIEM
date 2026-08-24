# ZeroDay

Um SIEM (Security Information and Event Management) completo e self-hosted:
ingestão de logs (syslog UDP/TCP, HTTP, agentes), normalização, motor de
deteção por regras (threshold / match / sequence), alertas (email + webhook),
API REST com autenticação JWT, dashboard web em tempo real, e agentes de
recolha para Linux e Windows.

## Arquitetura

```
                 ┌─────────────┐    ┌──────────────┐
 syslog UDP/TCP─▶│              │    │  Detection   │──▶ Alerts ──▶ Email/Webhook
 HTTP /ingest ──▶│  Normalizer  │───▶│  Engine      │
 Agentes ───────▶│  + Parsers   │    │ (threshold/  │
                 │              │    │  match/seq)  │
                 └──────┬───────┘    └──────┬───────┘
                        ▼                   ▼
                 ┌─────────────────────────────────┐
                 │   Base de dados (SQLite/Postgres) │
                 │   events / alerts / rules / ...   │
                 └──────────────┬────────────────────┘
                                ▼
                     API REST (FastAPI, JWT)
                                │
                     Dashboard Web (SPA) + WebSocket live tail
```

### Componentes

- **Ingestão** (`app/ingestion/`): recetor syslog assíncrono (UDP+TCP,
  RFC3164/RFC5424), endpoints HTTP (`/api/ingest/event`, `/bulk`, `/raw`) para
  agentes e integrações, parsers para JSON, CEF, syslog, access logs
  nginx/apache, `auth.log` SSH, eventos de segurança do Windows.
- **Normalização** (`app/ingestion/normalizer.py`): mapeia tudo para um
  esquema comum de evento (categoria, ação, resultado, severidade, IPs,
  utilizador, etc.) e persiste na base de dados.
- **Motor de deteção** (`app/detection/`): corre em ciclo (por omissão a cada
  5s), avalia regras carregadas da base de dados contra os eventos novos.
  Suporta 3 tipos de regra:
  - `threshold`: N eventos que passam um filtro, agrupados por campo, numa
    janela de tempo (ex: 5 falhas de login SSH do mesmo IP em 2 minutos).
  - `match`: um único evento que corresponde a um filtro dispara logo um
    alerta (ex: log limpo, conta adicionada a grupo privilegiado).
  - `sequence`: dois passos ordenados no tempo para o mesmo grupo (ex: falha
    de login seguida de sucesso a partir do mesmo IP).
  - 14 regras predefinidas cobrindo brute-force, escalada de privilégios,
    SQL injection, directory traversal, PowerShell suspeito, malware
    conhecido, port scan, etc. — todas editáveis/desativáveis via UI.
- **Alertas** (`app/alerting/`): notificações por email (SMTP) e webhook
  genérico (compatível com Slack/Discord/Teams via JSON), com deduplicação
  (alertas repetidos da mesma regra+grupo são fundidos por 15 minutos).
- **API REST** (`app/api/`): autenticação JWT (`/api/auth/login`), CRUD de
  regras/fontes/utilizadores, pesquisa de eventos com filtros e paginação,
  gestão de alertas, estatísticas para o dashboard, WebSocket `/ws/live`
  para live tail.
- **Dashboard Web** (`app/static/`): SPA em JavaScript puro (sem build
  step), tema escuro estilo SOC — dashboard com gráficos, explorador de
  eventos, gestão de alertas, live tail, editor de regras, gestão de fontes
  e utilizadores.
- **Agentes** (`agents/`): agente Python multiplataforma para enviar
  ficheiros de log (`agent.py`), coletor de Windows Event Log
  (`windows_eventlog_collector.py`, via pywin32), coletor de journald para
  Linux (`linux_journald_collector.py`).

## Instalação rápida (sem Docker)

Requisitos: Python 3.11+.

```powershell
# Windows (PowerShell)
.\start.ps1
```

```bash
# Linux/macOS
chmod +x start.sh
./start.sh
```

Isto cria um `.venv`, instala dependências, copia `.env.example` para `.env`
(edite `SECRET_KEY` e `ADMIN_PASSWORD`!) e arranca o servidor em
`http://localhost:8000`. Usa SQLite por omissão — zero configuração.

Utilizador administrador criado automaticamente no primeiro arranque, com o
`ADMIN_USERNAME`/`ADMIN_PASSWORD` definidos em `.env`.

## Instalação com Docker (recomendado para produção)

```bash
cp .env.example .env   # edite SECRET_KEY, INGEST_API_KEY, ADMIN_PASSWORD
docker compose up -d --build
```

Isto arranca o SIEM + PostgreSQL. A UI fica em `http://localhost:8000`, o
listener de syslog em `udp/tcp 5514`.

## Uso

1. Aceda a `http://localhost:8000`, autentique-se com o admin criado.
2. **Fontes** → crie uma fonte (ex: `web-server-1`) para obter uma API key
   dedicada, ou use a `INGEST_API_KEY` global do `.env` para testes rápidos.
3. Envie logs:
   - **Syslog**: aponte os seus dispositivos/servidores para
     `udp://<host>:5514` ou `tcp://<host>:5514`.
   - **HTTP direto**:
     ```bash
     curl -X POST http://localhost:8000/api/ingest/event \
       -H "X-API-Key: SUA_CHAVE" -H "Content-Type: application/json" \
       -d '{"category":"authentication","action":"login_failure","outcome":"failure","src_ip":"203.0.113.5","user":"root","message":"Failed password for root"}'
     ```
   - **Agentes**: ver secção abaixo.
   - **Dados de demonstração**:
     ```bash
     python scripts/generate_sample_logs.py --siem-url http://localhost:8000 --api-key SUA_CHAVE
     ```
     Isto gera tráfego normal e injeta padrões maliciosos (brute-force SSH,
     SQL injection, escalada de privilégios, assinatura de malware) para ver
     o dashboard e os alertas a funcionar.
4. **Regras**: ative/desative, edite severidade e a definição JSON de
   qualquer regra, ou crie novas.
5. **Alertas**: veja, filtre por severidade/estado, marque como reconhecido/
   resolvido, veja os eventos que o geraram.
6. **Live Tail**: stream em tempo real de todos os eventos e alertas
   (WebSocket).

## Agentes de recolha

### Linux (ficheiros de log)

```bash
pip install -r agents/requirements-agent.txt
cp agents/agent_config.example.json agent_config.json   # edite siem_url, api_key, files
python agents/agent.py --config agent_config.json
```

### Linux (journald)

```bash
python agents/linux_journald_collector.py --siem-url http://localhost:8000 --api-key SUA_CHAVE
```

### Windows (Event Log)

```powershell
pip install -r agents\requirements-agent.txt
# Correr como Administrador (necessário para ler o log de Security)
python agents\windows_eventlog_collector.py --siem-url http://localhost:8000 --api-key SUA_CHAVE
```

## Configuração (`.env`)

Ver `.env.example` para todas as opções: base de dados, chave secreta JWT,
chave de ingestão global, credenciais do admin, portas do syslog, intervalo
do motor de deteção, SMTP e webhook para alertas, retenção de eventos.

## Testes

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Cobertura: parsers de log, motor de correspondência de filtros de regras, e
um teste de integração ponta-a-ponta (ingestão → deteção → alerta) para a
regra de brute-force SSH.

## Modelo de dados

- `events`: evento normalizado (timestamp, host, categoria, ação, resultado,
  severidade, utilizador, IPs, mensagem, raw, tags, extra JSON).
- `alerts`: gerado pelo motor de deteção; agrega `event_ids`, tem estado
  (`open`/`acknowledged`/`resolved`/`closed`), severidade, MITRE ATT&CK.
- `rules`: definição de deteção (tipo, filtro, severidade, MITRE, JSON de
  parâmetros), editável via API/UI.
- `sources`: origens de log registadas, cada uma com a sua API key.
- `users`: contas com perfis `admin` / `analyst` / `viewer`.

## Segurança e produção

- Mude sempre `SECRET_KEY`, `INGEST_API_KEY` e `ADMIN_PASSWORD` antes de
  expor o serviço.
- Para produção, use PostgreSQL (`DATABASE_URL`) em vez de SQLite.
- Coloque o serviço atrás de TLS (reverse proxy — nginx/Caddy/Traefik) já
  que a API e o WebSocket correm em HTTP simples por omissão.
- Rode as API keys das fontes periodicamente (botão "Rodar chave" na UI).
- A retenção é automática: uma tarefa em background purga eventos com mais de
  `EVENT_RETENTION_DAYS` dias a cada 6 horas (`app/core/retention.py`). Defina
  `EVENT_RETENTION_DAYS=0` para desativar a purga.
