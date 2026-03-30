# Changelog — Vicarius vRx Resources

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.
O formato é baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) e este projeto adere ao [Versão Semântica](https://semver.org/lang/pt-BR/).

## [1.1.0] - 2026-03-30

### Adicionado
- **Rate Limiter Global** no script `export-inventory-vulnerabilities.py` com limite de 50 req/min para conformidade com a API Vicarius.
- Suporte ao cabeçalho `X-Rate-Limit-Retry-After-Seconds` para tratamento dinâmico de erros 429.
- Validação explícita que impede paginação profunda (`from > 10.000`), evitando erros silenciosos de API.

### Alterado
- Refatoração da função `request_json` para centralizar a lógica de retry e throttling.
- Atualização da documentação `export-inventory-vulnerabilities.md` com avisos de segurança sobre Token individual.
- Padronização do `README.md` raiz como índice navegável de soluções.

### Corrigido
- Problema de interrupção em janelas temporais grandes devido ao estouro de limites de requisições por minuto.

---
## [1.0.1] - 2026-03-22

### Adicionado
- Inclusão da coluna **KEV** nativa no payload de incidentes.
- Suporte a múltiplos CVEs formatados com pipe `|`.

---
## [1.0.0] - 2026-03-01

### Adicionado
- Versão inicial do script de exportação entre inventário e vulnerabilidades.
- Sistema de cache local para redução de carga na API.
- Motor de particionamento dinâmico para janelas temporais.
