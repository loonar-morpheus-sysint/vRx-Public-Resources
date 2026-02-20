# Endpoint Mapping (derivado dos scripts Python)

Mapeamento real extraído de:

- `Endpoint.py`
- `EndpointGroups.py`
- `EndpointPublisherProductVersions.py`
- `EndpointsEventTask.py`
- `EndpointVulnerabilities.py`
- `IncidentsEvents.py`
- `PatchsByAssets.py`

Base path comum: `/vicarius-external-data-api`

## Versão da API

- **API version (Swagger `info.version`)**: `1`
- **OpenAPI spec**: `3.0.1`

## Tabela de endpoints

| Endpoint | Método | Uso no script | Parâmetros principais |
|---|---|---|---|
| `/endpoint/search` | GET | Contagem/listagem de endpoints | `from`, `size`, `includeFields`, `q`, body (`searchQueryJson`) |
| `/endpointAttributes/search` | GET | Contagem/listagem de atributos de endpoint | `from`, `size` |
| `/organizationEndpointGroup/search` | GET | Contagem/listagem de grupos | `from`, `size`, `sort` |
| `/organizationEndpointPublisherProductVersions/search` | GET | Contagem/listagem de versões de produtos por endpoint | `from`, `size` |
| `/taskEndpointsEvent/count` | GET | Contagem de eventos de task por data | `from`, `size`, `sort`, `q` |
| `/taskEndpointsEvent/filter` | GET | Listagem de eventos de task por janela temporal | `from`, `size`, `sort`, `q` |
| `/organizationEndpointVulnerabilities/search` | GET | Contagem/listagem de vulnerabilidades por endpoint/hash e data | `from`, `size`, `sort`, `q` |
| `/incidentEvent/count` | GET | Contagem de incidentes (simples e por tipo/faixa nano) | `from`, `size`, `group`, `q`, `sort` |
| `/incidentEvent/filter` | GET | Listagem de incidentes (simples e por tipo/faixa nano) | `from`, `size`, `group`, `q`, `sort` |
| `/aggregation/searchGroup` | GET | Agregação de patches por endpoint hash/nome | `from`, `size`, `group`, `objectName`, `q`, etc. |

## Headers usados

- `Accept: application/json`
- `Vicarius-Token: {{apiKey}}`
- Para consultas com body em GET: `Charset: utf-8` e `Content-Type: application/json`

## Exemplos de expressões `q`

- Task events por janela:
  - `analyticsEventCreatedAt>{{taskMinDateMs}};analyticsEventCreatedAt<{{taskMaxDateMs}}`
- Vulnerabilidades por hash + janela:
  - `organizationEndpointVulnerabilitiesCreatedAt>{{vulnMinDateMs}};organizationEndpointVulnerabilitiesCreatedAt<{{vulnMaxDateMs}};organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=({{endpointHash}})`
- Incidentes por tipo + nano:
  - `analyticsEventCreatedAtNano>{{incidentMinDateNano}};analyticsEventCreatedAtNano<{{incidentMaxDateNano}};incidentEventIncidentEventType=in=({{incidentTypes}})`

## Variáveis principais da coleção

- `dashboardUrl`
- `apiKey`
- `from`, `size`
- `endpointHash`, `endpointName`
- `taskMinDateMs`, `taskMaxDateMs`
- `vulnMinDateMs`, `vulnMaxDateMs`
- `incidentMinDateNano`, `incidentMaxDateNano`, `incidentTypes`
- `searchQueryJson`

## Seção separada: cobertura complementar baseada no Swagger

Após comparar `postman/swagger.json` com a coleção principal `postman/collections/vRx-Public-API.postman_collection.json`:

- Métodos no Swagger: **121**
- Métodos cobertos na coleção principal: **10**
- Métodos não cobertos originalmente: **111**

Esses 111 endpoints/métodos foram adicionados em uma coleção complementar:

- `postman/collections/vRx-Public-API-swagger-extra.postman_collection.json`

Distribuição dos endpoints adicionados:

- `GET`: 41
- `POST`: 50
- `PUT`: 13
- `DELETE`: 7

Observações:

- A coleção principal (baseada nos scripts Python) foi mantida como fonte “opiniada” para os fluxos usados no projeto.
- A coleção complementar cobre os endpoints restantes do Swagger para exploração completa da API.
- A coleção complementar foi regenerada com parâmetros explícitos por endpoint (query/path/header), para preencher a aba **Params** no Postman automaticamente.