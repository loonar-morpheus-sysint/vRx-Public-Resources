# vRx Postman Collection

Coleção Postman completa baseada no fluxo real de `vicarius-external-scripts/VickyvRxReportCLI.py` e seus módulos dependentes.

## Estrutura

```text
vrx-postman-collection/
├── postman/
│   ├── collections/
│   │   └── vRx-Public-API.postman_collection.json
│   ├── environments/
│   │   ├── local.postman_environment.json
│   │   └── production.postman_environment.json
│   └── globals/
│       └── vRx-Globals.postman_globals.json
└── docs/
    └── endpoints-mapping.md
```

## O que foi coberto

A coleção contém requests para todos os domínios usados no Python:

- Endpoints (`endpoint/search`, `endpointAttributes/search`)
- Endpoint Groups (`organizationEndpointGroup/search` + busca por `searchQuery`)
- Product Versions (`organizationEndpointPublisherProductVersions/search`)
- Task Endpoint Events (`taskEndpointsEvent/count` e `taskEndpointsEvent/filter`)
- Endpoint Vulnerabilities (`organizationEndpointVulnerabilities/search`)
- Incident Events (`incidentEvent/count` e `incidentEvent/filter`)
- Patch Aggregation (`aggregation/searchGroup`)

## Como usar

1. Importe a coleção em `postman/collections/vRx-Public-API.postman_collection.json`.
2. Importe um environment (`local` ou `production`).
3. Preencha ao menos:
   - `dashboardUrl` (ex.: `https://<tenant>.vicarius.cloud`)
   - `apiKey` (valor do header `Vicarius-Token`)
4. Ajuste variáveis opcionais (`from`, `size`, `endpointHash`, janelas de data etc.).

## Observações importantes

- Alguns requests seguem exatamente o comportamento do script Python e usam **GET com body** (`searchQueryJson`).
- As expressões em `q` foram mantidas no formato original do código para facilitar troubleshooting.
- A coleção inclui scripts globais de automação:
    - **Pre-request**: valida `dashboardUrl` e `apiKey`, além de default para `from` e `size`.
    - **Tests**: valida status HTTP, tempo de resposta, JSON válido e envelope padrão (`serverResponseCount`/`serverResponseObject`) quando presente.