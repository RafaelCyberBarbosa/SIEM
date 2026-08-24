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
  - 34 regras predefinidas cobrindo brute-force, escalada de privilégios,
    integridade de ficheiros, SQL injection, directory traversal, PowerShell
    suspeito, malware conhecido, port scan, etc. — todas editáveis/
    desativáveis via UI.
- **UEBA / análise comportamental** (`app/detection/ueba.py`): em vez de
  regras fixas, aprende o comportamento normal de cada utilizador (horas de
  login habituais, países de origem conhecidos) a partir dos logins com
  sucesso, e pontua novos logins contra essa baseline. Deteta **Impossible
  Travel** (login em dois países num intervalo de tempo fisicamente
  impossível de percorrer, com pontuação de risco 0-100), login a partir de
  país novo, e login fora do horário habitual. A resolução de país/
  coordenadas por IP usa o serviço gratuito ip-api.com com cache local
  (`app/core/geoip.py`) — cada IP só é consultado uma vez.
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
   - **Demonstração de UEBA / Impossible Travel**:
     ```bash
     python scripts/generate_ueba_demo.py --siem-url http://localhost:8000 --api-key SUA_CHAVE
     ```
     Cria uma baseline de logins normais para um utilizador a partir de
     Portugal, depois simula um login a partir da Alemanha 2 minutos depois
     — dispara um alerta crítico de "Impossible Travel" com pontuação de
     risco. Vê o resultado em **Alertas** e o perfil aprendido em
     **Comportamento**.
4. **Regras**: ative/desative, edite severidade e a definição JSON de
   qualquer regra, ou crie novas.
5. **Alertas**: veja, filtre por severidade/estado, marque como reconhecido/
   resolvido, veja os eventos que o geraram, e clique em **"Ver cadeia de
   ataque"** para reconstruir a linha temporal de tudo o que aconteceu com o
   mesmo IP/host/utilizador.
6. **Comportamento (UEBA)**: perfis de comportamento aprendidos por
   utilizador — horas de login habituais e países conhecidos.
7. **Live Tail**: stream em tempo real de todos os eventos e alertas
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

### Integridade de ficheiros (FIM) — criação/alteração/eliminação de ficheiros

Multiplataforma, sem dependências extra. Vigia os ficheiros/pastas indicados e
reporta `file_created` / `file_modified` / `file_deleted` ao SIEM. A primeira
execução só cria uma base de referência (não envia eventos); a partir da
segunda deteta mudanças reais.

```powershell
cp agents\fim_config.example.json fim_config.json   # edite siem_url, api_key, watch_paths
python agents\file_integrity_agent.py --config fim_config.json
```

Exemplo de `watch_paths` úteis: a tua pasta de Downloads (deteta malware
descarregado), `C:\Windows\System32\drivers\etc\hosts` (deteta manipulação de
DNS local), ou uma pasta de configuração de uma aplicação sensível.

## Regras de deteção incluídas

37 regras predefinidas, todas editáveis/ativáveis/desativáveis na UI
(separador **Regras**) sem tocar em código:

- **Ficheiros**: criação, alteração e eliminação de ficheiros, modificação de
  ficheiros de sistema sensíveis, executáveis novos, eliminação/modificação
  em massa (indicador de ransomware).
- **Autenticação**: brute-force SSH/RDP/web, lockouts em massa, login falhado
  em conta privilegiada, sucesso após falhas repetidas.
- **Contas**: criação de utilizador, adição a grupo privilegiado, conta guest
  ativada, password sem expiração, administrador renomeado.
- **Sistema**: log de auditoria limpo, tarefa agendada criada, política de
  auditoria alterada, firewall desativada, antivírus desativado, novo serviço
  instalado.
- **Rede**: possível port scan, ligação a porta associada a C2/reverse shell,
  volume elevado de ligações de saída.
- **Web**: SQL injection, directory traversal, upload de web shell, remote
  file inclusion.
- **Malware/execução**: PowerShell suspeito, padrão de reverse shell,
  assinaturas de ferramentas conhecidas (Mimikatz, Cobalt Strike, etc.).
- **Comportamental (UEBA)**: impossible travel, login a partir de país novo,
  login fora do horário habitual — ver secção UEBA acima.

## Configuração (`.env`)

Ver `.env.example` para todas as opções: base de dados, chave secreta JWT,
chave de ingestão global, credenciais do admin, portas do syslog, intervalo
do motor de deteção, SMTP e webhook para alertas, retenção de eventos.

## Testes

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Cobertura: parsers de log, motor de correspondência de filtros de regras, o
agente de integridade de ficheiros (deteção de criação/alteração/eliminação),
o motor UEBA (cálculo de distância/impossible travel), a cadeia de ataque
(correlação de eventos+alertas), e testes de integração ponta-a-ponta
(ingestão → deteção → alerta) para brute-force SSH e impossible travel.

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
