# Guia prático do parâmetro `q` (Vicarius External Data API)

Este guia resume **como o parâmetro `q` é usado nos scripts Python** em `vicarius-external-scripts/` e traz exemplos prontos para uso em Postman.

> Fontes analisadas: `VickyvRxReportCLI.py`, `EndpointsEventTask.py`, `EndpointVulnerabilities.py`, `IncidentsEvents.py`, `PatchsByAssets.py`.

---

## O que é o parâmetro `q`

`q` é um parâmetro de filtro da API usado em chamadas GET (`/count`, `/filter`, `/search`, `/aggregation/searchGroup`).

Na prática, ele funciona como uma linguagem de consulta simples:

- `campo>valor` → maior que
- `campo<valor` → menor que
- `campo==valor` → igualdade exata
- `campo=in=(a,b,c)` → campo em lista de valores
- `;` → combina condições (AND)

---

## Regras de sintaxe observadas nos scripts

1. **Condições compostas usam `;`**
   - Exemplo: `data>min;data<max;tipo=in=(A,B)`

2. **Campos podem ser aninhados (dot notation)**
   - Exemplo: `organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash`

3. **Filtros de tempo mudam por endpoint**
   - Em Tasks/Vulnerabilities: campos em **milissegundos**
   - Em Incidents: `analyticsEventCreatedAtNano` em **nanosegundos**

4. **`in=(...)` aceita valores textuais e numéricos**
   - Exemplo textual: `incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)`
   - Exemplo numérico: `externalReferenceId=in=(-1,1947539,...)`

---

## Exemplos práticos extraídos dos scripts

## 1) Tasks de endpoints por janela de tempo

Arquivo: `EndpointsEventTask.py`  
Método: `getTasksEndopintsEvents`

Endpoint:
- `GET /vicarius-external-data-api/taskEndpointsEvent/filter`

`q` usado:
- `analyticsEventCreatedAt>{minDate};analyticsEventCreatedAt<{maxDate}`

Exemplo real:
- `q=analyticsEventCreatedAt>1700000000000;analyticsEventCreatedAt<1700500000000`

Uso:
- Buscar eventos de tarefas dentro de um intervalo temporal.

---

## 2) Count de tasks após último checkpoint

Arquivo: `EndpointsEventTask.py`  
Método: `getCountEvents`

Endpoint:
- `GET /vicarius-external-data-api/taskEndpointsEvent/count`

`q` usado:
- `analyticsEventCreatedAt>{lastdate}`

Exemplo:
- `q=analyticsEventCreatedAt>1700000000000`

Uso:
- Obter quantidade de novos eventos desde o último timestamp salvo.

---

## 3) Vulnerabilidades por intervalo + endpointHash

Arquivo: `EndpointVulnerabilities.py`  
Método: `getEndpointVulnerabilities`

Endpoint:
- `GET /vicarius-external-data-api/organizationEndpointVulnerabilities/search`

`q` usado:
- `organizationEndpointVulnerabilitiesCreatedAt>{minDate};organizationEndpointVulnerabilitiesCreatedAt<{maxDate};organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=({endpointHash})`

Exemplo:
- `q=organizationEndpointVulnerabilitiesCreatedAt>1700000000000;organizationEndpointVulnerabilitiesCreatedAt<1700500000000;organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=(ABCD1234HASH)`

Uso:
- Filtrar vulnerabilidades de um endpoint específico em uma janela de tempo.

---

## 4) Count de vulnerabilidades após data

Arquivo: `EndpointVulnerabilities.py`  
Método: `getCountEvents`

Endpoint:
- `GET /vicarius-external-data-api/organizationEndpointVulnerabilities/search`

`q` usado:
- `organizationEndpointVulnerabilitiesEndpoint.endpointCreatedAt>{lastdate}`

Exemplo:
- `q=organizationEndpointVulnerabilitiesEndpoint.endpointCreatedAt>1700000000000`

Uso:
- Medir volume de endpoints com vulnerabilidades criados após determinada data.

---

## 5) Incidents por tipo (lista)

Arquivo: `IncidentsEvents.py`  
Método: `getIncidentesEventsCount`

Endpoint:
- `GET /vicarius-external-data-api/incidentEvent/count`

`q` usado:
- `incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)`

Uso:
- Contar apenas incidentes de vulnerabilidade detectada/mitigada.

---

## 6) Incidents por intervalo nano + tipo

Arquivo: `IncidentsEvents.py`  
Métodos: `getIncidentesEventsCountbyType`, `getIncidentEventsbyType`

Endpoints:
- `GET /vicarius-external-data-api/incidentEvent/count`
- `GET /vicarius-external-data-api/incidentEvent/filter`

`q` usado:
- `analyticsEventCreatedAtNano>{minDate};analyticsEventCreatedAtNano<{maxDate};incidentEventIncidentEventType=in=({incidenttype})`

Exemplo:
- `q=analyticsEventCreatedAtNano>1698796800000000000;analyticsEventCreatedAtNano<1698883200000000000;incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)`

Uso:
- Busca incremental de incidentes com precisão em nanosegundos.

---

## 7) Patches por endpointHash (aggregation)

Arquivo: `PatchsByAssets.py`  
Método: `getCountEndpointsPatchs`

Endpoint:
- `GET /vicarius-external-data-api/aggregation/searchGroup`

`q` usado:
- `organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=({endpointHash})`

Exemplo:
- `q=organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=(ABCD1234HASH)`

Uso:
- Contar/agrupar patches associados ao endpoint filtrado.

---

## 8) Patches por endpointHash + externalReferenceId

Arquivo: `PatchsByAssets.py`  
Método: `getCountEndpointsPatchsApps`

Endpoint:
- `GET /vicarius-external-data-api/aggregation/searchGroup`

`q` usado:
- `organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=({endpointHash});externalReferenceId=in=(-1,1947539,-1,1972712,-1,2030761,4897281,-1,1826256,-1,4142147,1552707)`

Uso:
- Restringir patches por endpoint e conjunto específico de referências externas.

---

## 9) Patches por igualdade de nome de endpoint

Arquivo: `PatchsByAssets.py`  
Método: `getEndpointsPatchs`

Endpoint:
- `GET /vicarius-external-data-api/aggregation/searchGroup`

`q` usado:
- `organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointName=={endpointName}`

Exemplo:
- `q=organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointName==HOST-APP-01`

Uso:
- Agregar patches por nome exato do endpoint.

---

## Como montar no Postman

No Postman, em uma requisição GET:

1. Defina URL base: `https://SEU_DASHBOARD.vicarius.cloud`
2. Adicione header:
   - `Vicarius-Token: <API_KEY>`
3. Em **Params**, adicione:
   - `from`
   - `size`
   - `sort` (quando aplicável)
   - `q` com os filtros

Exemplo de Params para incidents incrementais:

- `from = 0`
- `size = 500`
- `sort = -analyticsEventCreatedAtNano`
- `q = analyticsEventCreatedAtNano>1698796800000000000;analyticsEventCreatedAtNano<1698883200000000000;incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)`

---

## Cuidados importantes

- **Unidade de tempo correta**:
  - `analyticsEventCreatedAt` (ms)
  - `analyticsEventCreatedAtNano` (ns)
- **Sem espaços desnecessários** no valor de `q`.
- **Caracteres especiais** (quando houver) devem ser codificados pela ferramenta cliente (Postman normalmente faz isso).
- **Igualdade textual**: em alguns filtros de string o script usa `==` sem aspas no valor.

---

## Mapeamento rápido (`q` por arquivo)

- `EndpointsEventTask.py`
  - `analyticsEventCreatedAt>{lastdate}`
  - `analyticsEventCreatedAt>{mindate};analyticsEventCreatedAt<{maxdate}`

- `EndpointVulnerabilities.py`
  - `organizationEndpointVulnerabilitiesEndpoint.endpointCreatedAt>{lastdate}`
  - `organizationEndpointVulnerabilitiesCreatedAt>{minDate};organizationEndpointVulnerabilitiesCreatedAt<{maxDate};organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=({endpointHash})`

- `IncidentsEvents.py`
  - `incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)`
  - `analyticsEventCreatedAtNano>{minDate};analyticsEventCreatedAtNano<{maxDate};incidentEventIncidentEventType=in=({incidenttype})`

- `PatchsByAssets.py`
  - `organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=({endpointHash})`
  - `organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=({endpointHash});externalReferenceId=in=(...)`
  - `organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointName=={endpointName}`

---

## Requests prontos para Postman (copiar e colar)

Use variáveis de ambiente no Postman:

- `{{dashboardUrl}}` → ex.: `https://SEU_DASHBOARD.vicarius.cloud`
- `{{apiKey}}` → token da API
- `{{minDateMs}}`, `{{maxDateMs}}` → timestamps em milissegundos
- `{{minDateNano}}`, `{{maxDateNano}}` → timestamps em nanossegundos
- `{{endpointHash}}`, `{{endpointName}}`

Header comum em todos:

- `Vicarius-Token: {{apiKey}}`
- `Accept: application/json`

### Alinhado à coleção `vRx-Public-API-swagger-extra.postman_collection.json`

Na coleção, os métodos com suporte a `q` aparecem em duas formas:

- **GET** para leitura direta (`/search`, `/searchByFields`, `/filter`, `/count`)
- **POST** equivalentes para os mesmos recursos (também aceitam `q` em query params)

Variáveis da própria coleção:

- `{{dashboardUrl}}`
- `{{apiKey}}`

Famílias de métodos da coleção onde `q` é aplicável (exemplos reais):

1. **Tasks / Task Events**
    - `GET|POST /vicarius-external-data-api/taskEndpointsEvent/count`
    - `GET|POST /vicarius-external-data-api/taskEndpointsEvent/filter`
    - `GET|POST /vicarius-external-data-api/taskEvent/count`
    - `GET|POST /vicarius-external-data-api/taskEvent/filter`
    - Exemplos de `q`:
       - `analyticsEventCreatedAt>{{minDateMs}}`
       - `analyticsEventCreatedAt>{{minDateMs}};analyticsEventCreatedAt<{{maxDateMs}}`

2. **Incidents**
    - `POST /vicarius-external-data-api/incidentEvent/count`
    - `POST /vicarius-external-data-api/incidentEvent/filter`
    - Exemplos de `q`:
       - `incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)`
       - `analyticsEventCreatedAtNano>{{minDateNano}};analyticsEventCreatedAtNano<{{maxDateNano}};incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)`

3. **Vulnerabilities**
    - `POST /vicarius-external-data-api/organizationEndpointVulnerabilities/search`
    - `GET|POST /vicarius-external-data-api/endpointVulnerability/count`
    - `GET|POST /vicarius-external-data-api/endpointVulnerability/filter`
    - `GET /vicarius-external-data-api/vulnerability/count`
    - `GET /vicarius-external-data-api/vulnerability/search`
    - Exemplos de `q`:
       - `organizationEndpointVulnerabilitiesCreatedAt>{{minDateMs}};organizationEndpointVulnerabilitiesCreatedAt<{{maxDateMs}};organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=({{endpointHash}})`
       - `organizationEndpointVulnerabilitiesEndpoint.endpointCreatedAt>{{minDateMs}}`

4. **Patches / External References / Aggregation**
    - `GET|POST /vicarius-external-data-api/organizationEndpointPatchPatchPackages/count`
    - `GET|POST /vicarius-external-data-api/organizationEndpointPatchPatchPackages/filter`
    - `GET /vicarius-external-data-api/organizationEndpointExternalReferenceExternalReferences/search`
    - `POST /vicarius-external-data-api/organizationEndpointExternalReferenceExternalReferences/search`
    - `POST /vicarius-external-data-api/aggregation/searchGroup`
    - Exemplos de `q`:
       - `organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=({{endpointHash}})`
       - `organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointName=={{endpointName}}`
       - `organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=({{endpointHash}});externalReferenceId=in=(-1,1947539,-1,1972712,-1,2030761,4897281,-1,1826256,-1,4142147,1552707)`

5. **Entidades administrativas com busca**
    - `GET|POST /vicarius-external-data-api/automation/search`
    - `GET|POST /vicarius-external-data-api/automation/searchAll`
    - `GET|POST /vicarius-external-data-api/automation/searchByFields`
    - `GET|POST /vicarius-external-data-api/user/search`
    - `GET|POST /vicarius-external-data-api/userInvitation/search`
    - `GET|POST /vicarius-external-data-api/userInvitation/searchByFields`
    - `GET|POST /vicarius-external-data-api/organizationEndpointGroup/search`
    - `GET|POST /vicarius-external-data-api/organizationEndpointGroup/searchByFields`
    - `GET|POST /vicarius-external-data-api/organizationPublisherProducts/search`
    - `GET|POST /vicarius-external-data-api/organizationPublisherOperatingSystems/search`
    - `GET|POST /vicarius-external-data-api/organizationEndpointPublisherOperatingSystems/search`
    - `POST /vicarius-external-data-api/organizationEndpointPublisherProductVersions/search`
    - `GET|POST /vicarius-external-data-api/organizationScanInput/search`
    - `GET|POST /vicarius-external-data-api/scriptTemplate/search`
    - `GET|POST /vicarius-external-data-api/scriptTemplateCommands/searchByFields`
    - `GET|POST /vicarius-external-data-api/patchPackage/searchByFields`
    - `GET|POST /vicarius-external-data-api/patchPackageLinks/searchByFields`
    - Exemplo genérico de `q`:
       - `createdAt>{{minDateMs}};createdAt<{{maxDateMs}}`

### 1) Count de tasks incrementais

- Método: `GET`
- URL: `{{dashboardUrl}}/vicarius-external-data-api/taskEndpointsEvent/count`
- Params:
   - `from=0`
   - `size=1`
   - `sort=-analyticsEventCreatedAt`
   - `q=analyticsEventCreatedAt>{{minDateMs}}`

### 2) Tasks por intervalo de tempo

- Método: `GET`
- URL: `{{dashboardUrl}}/vicarius-external-data-api/taskEndpointsEvent/filter`
- Params:
   - `from=0`
   - `size=500`
   - `sort=-analyticsEventCreatedAt`
   - `q=analyticsEventCreatedAt>{{minDateMs}};analyticsEventCreatedAt<{{maxDateMs}}`

### 3) Vulnerabilities por tempo + endpoint hash

- Método: `GET`
- URL: `{{dashboardUrl}}/vicarius-external-data-api/organizationEndpointVulnerabilities/search`
- Params:
   - `from=0`
   - `size=500`
   - `sort=-organizationEndpointVulnerabilitiesCreatedAt`
   - `q=organizationEndpointVulnerabilitiesCreatedAt>{{minDateMs}};organizationEndpointVulnerabilitiesCreatedAt<{{maxDateMs}};organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=({{endpointHash}})`

### 4) Count de incidents por tipo

- Método: `GET`
- URL: `{{dashboardUrl}}/vicarius-external-data-api/incidentEvent/count`
- Params:
   - `from=0`
   - `size=1`
   - `q=incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)`

### 5) Incidents incrementais por intervalo nano + tipo

- Método: `GET`
- URL: `{{dashboardUrl}}/vicarius-external-data-api/incidentEvent/filter`
- Params:
   - `from=0`
   - `size=500`
   - `group=incidentEventIncidentEventType&metricActionName=IncidentEvent`
   - `sort=-analyticsEventCreatedAtNano`
   - `q=analyticsEventCreatedAtNano>{{minDateNano}};analyticsEventCreatedAtNano<{{maxDateNano}};incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)`

### 6) Count de patches por endpoint hash (aggregation)

- Método: `GET`
- URL: `{{dashboardUrl}}/vicarius-external-data-api/aggregation/searchGroup`
- Params:
   - `from=0`
   - `size=1`
   - `includeOriginalDoc=false`
   - `newParser=true`
   - `objectName=OrganizationEndpointExternalReferenceExternalReferences`
   - `sort=OrganizationEndpointExternalReferenceExternalReferences.sensitivityLevelRank`
   - `subAggregationLevel=0`
   - `sumLastSubAggregationBuckets=0`
   - `group=organizationEndpointExternalReferenceExternalReferencesPatches.patchName.raw;organizationEndpointExternalReferenceExternalReferencesPatches.patchDescription;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelName;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelRank;externalReferenceId;>;organizationEndpointExternalReferenceExternalReferencesPatches.patchId;externalReferenceSourceId;endpointId`
   - `q=organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=({{endpointHash}})`

### 7) Patches por nome exato de endpoint (aggregation)

- Método: `GET`
- URL: `{{dashboardUrl}}/vicarius-external-data-api/aggregation/searchGroup`
- Params:
   - `from=0`
   - `size=500`
   - `includeOriginalDoc=false`
   - `newParser=true`
   - `objectName=OrganizationEndpointExternalReferenceExternalReferences`
   - `sort=OrganizationEndpointExternalReferenceExternalReferences.sensitivityLevelRank`
   - `subAggregationLevel=0`
   - `sumLastSubAggregationBuckets=0`
   - `group=organizationEndpointExternalReferenceExternalReferencesPatches.patchName.raw;organizationEndpointExternalReferenceExternalReferencesPatches.patchDescription;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelName;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelRank;externalReferenceId;>;organizationEndpointExternalReferenceExternalReferencesPatches.patchId;externalReferenceSourceId;endpointId`
   - `q=organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointName=={{endpointName}}`

### Observação rápida de troubleshooting

- Se vier vazio, primeiro valide unidade de tempo (`ms` vs `nano`).
- Em igualdade textual (`==`), teste com e sem caracteres especiais no nome.
- Para filtros longos, confirme se o cliente está codificando URL corretamente.

