# Documentação do script `export-inventory-vulnerabilities.py`

> ⚠️ ATENÇÃO
> Durante a execução deste script, foram observadas lentidão nas respostas e interrupções associadas a limites de tempo e volume de chamadas. Embora esse comportamento tenha sido mitigado com um **Rate Limiter Global (50 req/min)** e intervalos de espera estratégicos, o uso indevido ainda pode gerar bloqueios.
>
> **SEGURANÇA E LIMITES:**
> O usuário **DEVE** utilizar um **TOKEN DE API PRÓPRIO** e individual. Não utilize tokens compartilhados, pois os limites de throughput (60 req/min nominais) são aplicados ao escopo do token/organização. O uso simultâneo do mesmo token em múltiplas instâncias causará erros 429 frequentes.
>
> No download do inventário, foram necessários aproximadamente `35 minutos de execução`, dos quais apenas `4 segundos corresponderam a processamento efetivo de CPU`. Em outras palavras, mais de 99% do tempo total foi consumido aguardando respostas da API, tráfego de rede, `sleeps` e mecanismos de controle de ritmo da execução (Rate Limiting). Comportamento semelhante foi observado na exportação dos eventos de vulnerabilidade: em uma `janela de 7 dias para 12.582 endpoints identificados`, a execução levou aproximadamente `4 minutos`, dos quais somente `12 segundos` corresponderam a processamento real.
>
> Recomenda-se validar sua utilização com a Vicarius antes de adotá-lo de forma contínua.
>
>
> **Adicionada coluna com os códigos KEV caso existam**
> A adição dessa coluna aumentou significativamente o tempo de execução. O tempo para conclusão da mesma janela temporal levou aproximadamente 20 minutos com tempo efetivo de uso de CPU de 01 minuto, ou seja, 19 minutos aguardando resposta da API e pausas de 15 segundos estratégicas para contornar a restrição de máximo de requisições da API.

## Índice

- [Objetivo](#objetivo)
- [Layout dos dados exportados](#layout-dos-dados-exportados)
  - [Observações importantes sobre preenchimento](#observações-importantes-sobre-preenchimento)
- [Endpoints de API utilizados](#endpoints-de-api-utilizados)
  - [1. `incidentEvent/filter`](#1-incidenteventfilter)
  - [2. `endpoint/search`](#2-endpointsearch)
  - [3. `endpointAttributes/search`](#3-endpointattributessearch)
  - [4. `organizationPublisherOperatingSystems/search`](#4-organizationpublisheroperatingsystemssearch)
- [Geração dos dados de cache](#geração-dos-dados-de-cache)
  - [Estrutura do cache](#estrutura-do-cache)
  - [Quando o cache é usado](#quando-o-cache-é-usado)
  - [Quando o cache é recriado](#quando-o-cache-é-recriado)
  - [Como o cache é gerado](#como-o-cache-é-gerado)
  - [Modo incremental do cache](#modo-incremental-do-cache)
  - [Limitações do modo incremental](#limitações-do-modo-incremental)
  - [Metadados gravados no cache](#metadados-gravados-no-cache)
- [Lógica utilizada para a correlação](#lógica-utilizada-para-a-correlação)
  - [1. Seleção dos eventos](#1-seleção-dos-eventos)
  - [2. Resolução do endpoint](#2-resolução-do-endpoint)
  - [3. Lookup de endpoint](#3-lookup-de-endpoint)
  - [4. Lookup de atributos](#4-lookup-de-atributos)
  - [5. Correlação de campos principais](#5-correlação-de-campos-principais)
    - [`CVE Name`](#cve-name)
    - [`Vendor` e `Product`](#vendor-e-product)
    - [`Operating System`](#operating-system)
    - [`Operating System Version`](#operating-system-version)
    - [`Internal IP Address` e `External IP Address`](#internal-ip-address-e-external-ip-address)
    - [`MAC Address`](#mac-address)
    - [`Organizational Unit`](#organizational-unit)
    - [`Patch ID`](#patch-id)
    - [`Event ID`](#event-id)
- [Parâmetros do script e como utilizá-los](#parâmetros-do-script-e-como-utilizá-los)
  - [Variáveis de ambiente](#variáveis-de-ambiente)
  - [Parâmetros do script](#parâmetros-do-script)
  - [Exemplos de uso](#exemplos-de-uso)
    - [1. Baixar ou atualizar somente o cache do inventário](#1-baixar-ou-atualizar-somente-o-cache-do-inventário)
    - [2. Exportação usando cache existente no intervalo fechado de datas](#2-exportação-usando-cache-existente-no-intervalo-fechado-de-datas)
- [Recomendações de execução](#recomendações-de-execução)
  - [1. Fluxos suportados](#1-fluxos-suportados)
  - [2. Preferir cache local para execuções recorrentes](#2-preferir-cache-local-para-execuções-recorrentes)
  - [3. Recriar cache em mudanças relevantes do inventário](#3-recriar-cache-em-mudanças-relevantes-do-inventário)
  - [4. O export exige intervalo fechado](#4-o-export-exige-intervalo-fechado)
  - [5. Usar incremental para rotinas frequentes](#5-usar-incremental-para-rotinas-frequentes)
  - [6. Exportação com cache não baixa inventário automaticamente](#6-exportação-com-cache-não-baixa-inventário-automaticamente)
  - [7. Manter refresh completo periódico](#7-manter-refresh-completo-periódico)
  - [8. O nome dos arquivos de saída é fixo](#8-o-nome-dos-arquivos-de-saída-é-fixo)
  - [9. Usar partições para coletas grandes](#9-usar-partições-para-coletas-grandes)
  - [10. Usar filtros temporais quando não precisar do histórico inteiro](#10-usar-filtros-temporais-quando-não-precisar-do-histórico-inteiro)
- [Histórico de problemas e soluções aplicadas](#histórico-de-problemas-e-soluções-aplicadas)
  - [1. Campos importantes vinham vazios na exportação inicial](#1-campos-importantes-vinham-vazios-na-exportação-inicial)
  - [2. O endpoint do incidente nem sempre batia diretamente com o inventário](#2-o-endpoint-do-incidente-nem-sempre-batia-diretamente-com-o-inventário)
  - [3. Versão do sistema operacional tinha cobertura limitada](#3-versão-do-sistema-operacional-tinha-cobertura-limitada)
  - [4. O nome do sistema operacional nem sempre vinha legível no incidente](#4-o-nome-do-sistema-operacional-nem-sempre-vinha-legível-no-incidente)
  - [5. `Patch ID` e `Event ID` não eram consistentes em todos os eventos](#5-patch-id-e-event-id-não-eram-consistentes-em-todos-os-eventos)
  - [6. Coletas grandes de inventário sofriam com limite operacional da API](#6-coletas-grandes-de-inventário-sofriam-com-limite-operacional-da-api)
  - [7. Atributos de endpoint eram o ponto mais sensível da coleta](#7-atributos-de-endpoint-eram-o-ponto-mais-sensível-da-coleta)
  - [8. Alguns endpoints simplesmente não existiam no inventário atual](#8-alguns-endpoints-simplesmente-não-existiam-no-inventário-atual)
  - [9. O código acumulou ramificações de tentativa durante a evolução](#9-o-código-acumulou-ramificações-de-tentativa-durante-a-evolução)
- [Testes automatizados](#testes-automatizados)
  - [O que os testes cobrem](#o-que-os-testes-cobrem)
  - [Como executar](#como-executar)
  - [Resultado validado mais recentemente](#resultado-validado-mais-recentemente)
- [Resumo operacional](#resumo-operacional)
- [Notas da Versão](#notas-da-versão)
- [Isenção de Responsabilidade](#isenção-de-responsabilidade)

## Objetivo

O script `export-inventory-vulnerabilities.py` foi elaborado para executar os fluxos:

1. Criar/atualizar o cache local do inventário Vicarius
2. Exportar eventos de vulnerabilidades detectadas usando esse cache local dentro de uma janela temporal fechada

O objetivo prático do script é produzir uma visão consolidada das vulnerabilidades do tipo `Detected Vulnerability`, combinando:

- dados do evento de incidente
- dados enriquecidos do endpoint a partir do cache local do inventário
- atributos auxiliares do endpoint presentes no cache
- catálogo de sistemas operacionais consultado no momento da exportação

Os arquivos gerados são:

- `JSONL`: `vicarius-external-scripts/vicarius_vulnerabilities.jsonl`
- `CSV`: `vicarius-external-scripts/vicarius_vulnerabilities.csv`

Os artefatos locais gerados por esse script foram adicionados ao `.gitignore` para evitar versionamento acidental.

| Arquivo | Propósito |
| --- | --- |
| `vicarius-external-scripts/cache/` | Diretório-base local criado pelo script para armazenar snapshots temporários e persistidos do inventário. |
| `vicarius-external-scripts/vicarius_vulnerabilities.jsonl` | Exportação linha a linha dos eventos `DetectedVulnerability` já normalizados. |
| `vicarius-external-scripts/vicarius_vulnerabilities.csv` | Exportação tabular das mesmas vulnerabilidades para consumo operacional e análise manual. |
| `vicarius-external-scripts/cache/vicarius_inventory/endpoints.jsonl` | Snapshot local dos endpoints do inventário usado no enriquecimento. |
| `vicarius-external-scripts/cache/vicarius_inventory/endpoint_attributes.jsonl` | Snapshot local dos atributos relevantes dos endpoints usado no enriquecimento. |
| `vicarius-external-scripts/cache/vicarius_inventory/metadata.json` | Metadados do snapshot local, incluindo completude, partições e marcos de refresh. |

O comportamento atual do script é intencionalmente restrito para privilegiar previsibilidade operacional, menor ambiguidade de uso e menor acúmulo de caminhos alternativos de execução.

## Layout dos dados exportados

Cada linha exportada representa um evento `DetectedVulnerability` já normalizado. O layout atual contém as colunas abaixo.

| Campo | Descrição |
| --- | --- |
| `CVE Name` | Identificador da vulnerabilidade, priorizando o CVE informado pela referência externa da vulnerabilidade. |
| `Product` | Produto afetado, obtido do evento de produto ou do contexto de sistema operacional. |
| `Vendor` | Fabricante do produto ou do sistema operacional relacionado ao evento. |
| `CVE Severity` | Severidade textual derivada do score CVSS v3 (`Critical`, `High`, `Medium`, `Low`, `Unknown`). |
| `CVSS 3 Base Score` | Score base CVSS v3 da vulnerabilidade. |
| `CVSS Vector` | Vetor CVSS v3 informado pela API. |
| `CVE Publish Date` | Data de publicação da vulnerabilidade, convertida para `YYYY-MM-DD`. |
| `Vendor Patch Link` | Link para patch na plataforma Vicarius, gerado a partir do `Patch ID` quando disponível. |
| `KEV` | Códigos KEV separados por pipe caso existam. |
| `Vulnerability Summary` | Resumo textual da vulnerabilidade. |
| `Endpoint` | Nome do endpoint correlacionado. |
| `Endpoint ID` | Identificador do endpoint. |
| `Operating System` | Nome do sistema operacional, obtido do cache do inventário, do evento ou do catálogo de sistemas operacionais. |
| `Operating System Version` | Versão do sistema operacional, quando encontrada em atributos ou no payload do endpoint. |
| `Internal IP Address` | IP interno do endpoint. |
| `External IP Address` | IP externo do endpoint. |
| `MAC Address` | Endereço MAC do endpoint. |
| `Organizational Unit` | Unidade organizacional ou organização relacionada ao endpoint. |
| `DetectionDate` | Data da detecção da vulnerabilidade. |
| `Last Seen` | Última data conhecida do evento. |
| `SnapshotDate` | Data da execução/exportação. |
| `Patch ID` | Identificador do patch, quando informado pela API. |
| `Incident Event Type` | Tipo do evento retornado pela API. O script só exporta `DetectedVulnerability`. |
| `Event ID` | Identificador do evento, com fallback seguro quando o campo principal não está disponível. |

### Observações importantes sobre preenchimento

- O script exporta apenas eventos cujo campo `incidentEventIncidentEventType` seja `DetectedVulnerability`.
- O enriquecimento durante a exportação depende da existência prévia do cache local do inventário.
- Alguns campos podem permanecer vazios quando o endpoint não existir no cache local ou quando a API não fornecer o dado correspondente.
- `External IP Address` passa por normalização para remover sufixos CIDR como `/32`.
- O arquivo final apresenta, ao término da execução, um resumo de cobertura por coluna.

## Endpoints de API utilizados

O script utiliza os endpoints abaixo da API externa da Vicarius.

### 1. `incidentEvent/filter`

Usado para buscar os eventos de vulnerabilidade detectada.

**Finalidade no script:**

- exportação dos incidentes
- obtenção dos identificadores e status KEV (`vulnerabilityCISARequiredAction`) nativamente sem necessidade de chamadas adicionais
- leitura particionada por `analyticsEventCreatedAtNano`
- refinamento automático de partições quando há risco de extrapolar o limite prático de paginação

**Filtro principal usado:**

- `incidentEventIncidentEventType=in=(DetectedVulnerability)`

### 2. `endpoint/search`

Usado para consultar o inventário de endpoints.

**Finalidade no script:**

- construir ou atualizar o cache local de endpoints
- enriquecer endpoint, organização, sistema operacional e referências externas via cache previamente salvo

### 3. `endpointAttributes/search`

Usado para obter atributos auxiliares dos endpoints.

**Finalidade no script:**

- construir ou atualizar o cache local dos atributos relevantes
- enriquecer IP interno, IP externo, unidade organizacional, versão do sistema operacional e MAC via cache previamente salvo

### 4. `organizationPublisherOperatingSystems/search`

Usado para consultar o catálogo de sistemas operacionais por par `publisherId` + `operatingSystemId`.

**Finalidade no script:**

- preencher `Operating System` quando o cache do endpoint ou o evento não trazem um nome legível do SO
- servir como fallback para correlação de sistema operacional

## Geração dos dados de cache

O script mantém um snapshot local do inventário para reutilização nas exportações.

### Estrutura do cache

Por padrão, o cache é salvo em:

- diretório: `vicarius-external-scripts/cache/vicarius_inventory`
- endpoints: `vicarius-external-scripts/cache/vicarius_inventory/endpoints.jsonl`
- atributos: `vicarius-external-scripts/cache/vicarius_inventory/endpoint_attributes.jsonl`
- metadados: `vicarius-external-scripts/cache/vicarius_inventory/metadata.json`

### Quando o cache é usado

O cache é utilizado quando a execução inclui:

- `--use-inventory-cache`

Importante: o uso do cache durante a exportação **não dispara download nem refresh automático**. Se o snapshot local não existir, a execução falha e orienta o usuário a gerar o cache antes.

### Quando o cache é recriado

O refresh do cache ocorre quando:

- o parâmetro `--refresh-inventory-cache` é informado

Esse refresh é uma **operação separada** da exportação de incidentes:

- se o cache existir, o script tenta atualizá-lo incrementalmente
- se o cache não existir, o script baixa o inventário completo
- ao final da operação de cache, o script encerra sem exportar incidentes

### Como o cache é gerado

1. O script descobre os limites mínimo e máximo de `endpointCreatedAt` em `endpoint/search`.
2. Ele cria partições numéricas para reduzir paginação profunda e risco de respostas parciais.
3. Faz a coleta dos endpoints por partição.
4. Aguarda um tempo de aquecimento (`ATTRIBUTE_WARMUP_DELAY`) antes de consultar atributos.
5. Gera partições de atributos a partir dos `endpointId` encontrados.
6. Baixa os atributos relevantes por partição.
7. Salva os arquivos `JSONL` e o `metadata.json`.

### Modo incremental do cache

Quando `--refresh-inventory-cache` é informado, o fluxo tenta:

1. carregar o snapshot local já existente
2. identificar o maior `endpointCreatedAt` salvo no cache
3. buscar endpoints novos a partir desse marco temporal
4. buscar atributos apenas para os novos `endpointId`
5. fazer merge com o snapshot já existente e regravar o cache

Se o cache ainda não existir, o script faz um download completo do inventário em vez do incremental.

### Limitações do modo incremental

O modo incremental foi desenhado para ser seguro principalmente para **novos endpoints**.

Limitações importantes:

- ele **não garante** capturar alterações em endpoints antigos se a API não expuser um campo confiável de atualização do inventário
- ele depende de um snapshot local anterior **completo** (`endpointsComplete=true` e `endpointAttributesComplete=true`)
- se o cache local estiver ausente, incompleto ou apontando para outra `baseUrl`, o script faz fallback automático para refresh completo

Na prática, a recomendação é usar:

- refresh incremental para rotina frequente
- refresh completo periódico para reconciliar mudanças antigas do inventário

### Metadados gravados no cache

O arquivo `metadata.json` contém informações como:

- `createdAt`
- `baseUrl`
- quantidade de endpoints e atributos
- campo de partição usado
- tamanho máximo por partição
- completude da coleta (`endpointsComplete`, `endpointAttributesComplete`)
- resumos das partições executadas
- `lastEndpointCreatedAt`
- `lastFullRefreshAt`
- `lastIncrementalRefreshAt`
- contadores do incremental (`incrementalAddedEndpointsCount`, `incrementalAddedEndpointAttributesCount`)

## Lógica utilizada para a correlação

A correlação foi desenhada para ser resiliente a lacunas do payload original dos incidentes.

### 1. Seleção dos eventos

Somente eventos com tipo `DetectedVulnerability` entram na exportação final.

### 2. Resolução do endpoint

O endpoint é obtido prioritariamente de:

1. `incidentEventEndpoint`
2. `analyticsEventAuthenticatedModelAbs` (fallback)

### 3. Lookup de endpoint

O script constrói um lookup com duas chaves:

- por `endpointId`
- por `endpointName`

Isso permite correlacionar mesmo quando o `endpointId` do incidente não coincide com o `endpointId` do snapshot local, desde que o nome seja o mesmo.

### 4. Lookup de atributos

Os atributos de endpoint também são indexados por:

- `endpointId`
- `endpointName`

A coleta considera apenas fontes relevantes, definidas em `ATTRIBUTE_MATCHERS`, como:

- `Internal IP Address`
- `External IP Address`
- `Organizational Unit`
- `Organization Unit`
- `OU`
- `Operating System Version`
- `OS Version`
- `Operating System Build`
- `MAC Address`
- `MAC Address ID`

### 5. Correlação de campos principais

#### `CVE Name`

Prioridade:

1. `incidentEventVulnerability.vulnerabilityExternalReference.externalReferenceExternalId`
2. `incidentEventCve.cveName`
3. `incidentEventVulnerability.vulnerabilityName`

#### `Vendor` e `Product`

Prioridade principal:

- dados de `incidentEventOrganizationPublisherProducts`
- fallback para `incidentEventOrganizationPublisherOperatingSystems`
- fallback adicional para sistema operacional do endpoint

#### `Operating System`

Prioridade:

1. `endpointOperatingSystem.operatingSystemName` do cache do endpoint
2. nome do SO presente no evento
3. catálogo `organizationPublisherOperatingSystems/search`

#### `Operating System Version`

Prioridade:

1. atributos do endpoint compatíveis com versão/build do SO
2. `endpoint.operatingSystemVersion`

#### `Internal IP Address` e `External IP Address`

Prioridade:

1. atributos do endpoint
2. campos presentes diretamente no endpoint do incidente

#### `MAC Address`

Prioridade:

1. referências externas do endpoint (`MAC Address ID` / `MAC Address`)
2. atributos do endpoint
3. campos diretos do endpoint

#### `Organizational Unit`

Prioridade:

1. atributos do endpoint
2. `endpointOrganization.organizationName`

#### `Patch ID`

Prioridade:

1. `patchId`
2. `incidentEventPatch.patchId`

Se o valor vier como `0`, o campo é tratado como vazio.

#### `Event ID`

Prioridade:

1. `incidentEventId`
2. `_id`

## Parâmetros do script e como utilizá-los

Além dos parâmetros funcionais, é recomendável medir o tempo total de execução sempre que o objetivo for avaliar eficiência operacional, comparar estratégias de coleta ou validar o impacto de ajustes no particionamento, no uso de cache e na janela temporal escolhida. Registrar essa duração ajuda a identificar degradações de desempenho, comparar execuções incrementais versus completas e sustentar decisões sobre a estratégia mais adequada para uso recorrente.

### Variáveis de ambiente

O script espera um arquivo `.env` no diretório corrente da execução ou variáveis de ambiente contendo:

- `VICARIUS_API_KEY` — obrigatório
- `VICARIUS_BASE_URL` — obrigatório, padrão: `https://<tenant>.vicarius.cloud`

### Parâmetros do script

| Parâmetro | Descrição |
| --- | --- |
| `--from-date` | Data/hora inicial em formato ISO 8601 para exportação usando cache local. Deve ser usada junto com `--to-date`. |
| `--to-date` | Data/hora final em formato ISO 8601 para exportação usando cache local. Deve ser usada junto com `--from-date`. |
| `--refresh-inventory-cache` | Operação exclusiva de cache: se o snapshot local existir, tenta atualizá-lo incrementalmente; se não existir, baixa o inventário completo e encerra. |
| `--use-inventory-cache` | Usa o cache local existente para enriquecimento durante a exportação, sem baixar ou atualizar inventário. |

### Exemplos de uso

#### 1. Baixar ou atualizar somente o cache do inventário

```bash
/usr/bin/time -p python vicarius-external-scripts/export-inventory-vulnerabilities.py --refresh-inventory-cache
```

#### 2. Exportação usando cache existente no intervalo fechado de datas

```bash
/usr/bin/time -p python vicarius-external-scripts/export-inventory-vulnerabilities.py --use-inventory-cache --from-date 2026-03-01T00:00:00 --to-date 2026-03-07T23:59:59
```

## Recomendações de execução

### 1. Fluxos suportados

O script foi simplificado para executar os fluxos:

1. Criar/Atualizar o snapshot local do inventário
2. Exportar incidentes usando esse snapshot dentro de uma janela fechada de datas

### 2. Preferir cache local para execuções recorrentes

Para exportações repetidas, prefira:

```bash
/usr/bin/time -p python vicarius-external-scripts/export-inventory-vulnerabilities.py --use-inventory-cache --from-date 2026-03-18T00:00:00 --to-date 2026-03-22T23:59:59
```

Isso reduz chamadas às APIs de inventário e tende a dar mais estabilidade operacional por evitar atingir limites de uso da API desde que o cache tenha sido anteriormente populado.

### 3. Recriar cache em mudanças relevantes do inventário

Se houve alteração significativa no inventário ou se há suspeita de cache desatualizado, execute o comando abaixo antes de exportar os eventos:

```bash
/usr/bin/time -p python vicarius-external-scripts/export-inventory-vulnerabilities.py --refresh-inventory-cache
```

### 4. O export exige intervalo fechado

Ao exportar com cache, o script exige obrigatoriamente:

- `--use-inventory-cache`
- `--from-date`
- `--to-date`

Isso evita execuções abertas ou ambíguas e deixa o comportamento previsível.

### 5. Usar incremental para rotinas frequentes

Se o objetivo é reduzir tempo de coleta e chamadas pesadas ao inventário, o próprio `--refresh-inventory-cache` já tentará atualizar o snapshot existente a partir do ponto atual. Se o cache ainda não existir, ele cairá automaticamente para um download completo.

### 6. Exportação com cache não baixa inventário automaticamente

Ao usar:

```bash
/usr/bin/time -p python vicarius-external-scripts/export-inventory-vulnerabilities.py --use-inventory-cache --from-date 2026-03-18T00:00:00 --to-date 2026-03-22T23:59:59
```

o script apenas reutiliza o snapshot local. Se o cache não existir, a execução falha e orienta o usuário a rodar primeiro `--refresh-inventory-cache`.

### 7. Manter refresh completo periódico

Mesmo com incremental habilitado, ainda é recomendável executar um refresh completo periodicamente para reconciliar mudanças em endpoints antigos.

### 8. O nome dos arquivos de saída é fixo

Para reduzir variações operacionais, a exportação grava sempre em:

- `vicarius-external-scripts/vicarius_vulnerabilities.jsonl`
- `vicarius-external-scripts/vicarius_vulnerabilities.csv`

### 9. Usar partições para coletas grandes

Para exportações com muitos incidentes, o fluxo padrão usa coleta particionada para reduzir:

- estouro de paginação
- respostas parciais
- necessidade de retry manual

### 10. Usar filtros temporais quando não precisar do histórico inteiro

Os parâmetros `--from-date` e `--to-date` reduzem a quantidade de incidentes exportados e podem encurtar bastante execuções longas.

Regras do script:

- `--from-date` e `--to-date` são obrigatórios no modo de exportação
- `--to-date` deve ser maior ou igual a `--from-date`
- datas sem horário (por exemplo `2026-03-22`) são aceitas em formato ISO; para `from-date` o script assume o início do dia e para `to-date` o fim do dia

## Histórico de problemas e soluções aplicadas

Esta seção consolida, de forma resumida, os principais problemas observados durante a evolução do script e o que permaneceu na versão atual.

### 1. Campos importantes vinham vazios na exportação inicial

**Problema observado:**

- vários campos de enriquecimento não eram preenchidos corretamente, como IP, MAC, SO e OU

**Causa identificada:**

- o payload de `incidentEvent/filter` não traz sozinho todos os dados necessários

**Solução aplicada:**

- reforço da correlação com inventário e atributos de endpoint
- adoção do cache local como base do enriquecimento de exportação

### 2. O endpoint do incidente nem sempre batia diretamente com o inventário

**Problema observado:**

- em alguns casos o `endpointId` do evento não bastava para resolver o endpoint enriquecido

**Causa identificada:**

- havia divergências entre o identificador presente no incidente e o snapshot do inventário

**Solução aplicada:**

- manutenção do lookup por `endpointId` e `endpointName`

### 3. Versão do sistema operacional tinha cobertura limitada

**Problema observado:**

- a versão do sistema operacional nem sempre vinha preenchida

**Causa identificada:**

- a API não fornecia esse dado de maneira consistente nos mesmos campos para todos os endpoints

**Solução aplicada:**

- uso apenas de fontes mais seguras para esse campo
- aceitação explícita de que ele pode continuar vazio em parte dos registros

### 4. O nome do sistema operacional nem sempre vinha legível no incidente

**Problema observado:**

- o incidente nem sempre trazia um nome amigável do SO

**Causa identificada:**

- em vários casos só havia IDs técnicos

**Solução aplicada:**

- fallback via `organizationPublisherOperatingSystems/search`

### 5. `Patch ID` e `Event ID` não eram consistentes em todos os eventos

**Problema observado:**

- alguns eventos não traziam esses campos de forma estável

**Causa identificada:**

- inconsistência do payload entre eventos e tenants

**Solução aplicada:**

- fallbacks seguros para `Patch ID` e `Event ID`

### 6. Coletas grandes de inventário sofriam com limite operacional da API

**Problema observado:**

- coletas amplas podiam retornar resultados parciais ou sofrer `429`

**Causa identificada:**

- limitação prática de paginação e throttling da API

**Solução aplicada:**

- partições numéricas
- validação de completude
- refino recursivo das partições quando necessário

### 7. Atributos de endpoint eram o ponto mais sensível da coleta

**Problema observado:**

- `endpointAttributes/search` foi historicamente o ponto mais instável

**Causa identificada:**

- alto volume de dados e sensibilidade maior a throttling

**Solução aplicada:**

- partição por `endpointId`
- refino automático das partições problemáticas
- retenção em cache com metadados de completude

### 8. Alguns endpoints simplesmente não existiam no inventário atual

**Problema observado:**

- certos campos continuavam vazios mesmo após melhorar a correlação

**Causa identificada:**

- parte dos endpoints presentes em incidentes não aparecia no inventário disponível no momento da coleta

**Solução aplicada:**

- manutenção de fallbacks seguros
- documentação explícita de que não há garantia de cobertura de 100%

### 9. O código acumulou ramificações de tentativa durante a evolução

**Problema observado:**

- a implementação ficou carregando caminhos intermediários que já não eram mais desejados

**Causa identificada:**

- o script evoluiu ao longo das investigações até estabilizar no fluxo útil

**Solução aplicada na versão atual:**

- simplificação da CLI para dois fluxos suportados
- remoção de parâmetros e modos alternativos
- refatoração do `main()` para melhorar legibilidade sem alterar comportamento

## Testes automatizados

Existe uma suíte de testes em `./tests/test_export_inventory_vulnerabilities.py` dedicada a validar o comportamento atual do script. Esses testes devem ser executados **sempre que houver qualquer alteração** em `export-inventory-vulnerabilities.py`, mesmo quando a mudança parecer pequena, porque boa parte da lógica combina normalização, correlação, paginação refinada, cache incremental e validações de CLI — exatamente o tipo de área em que uma regressão “discreta” costuma aparecer sem cerimônia.

### O que os testes cobrem

Os testes atuais cobrem principalmente:

- normalização dos eventos `DetectedVulnerability`
- enriquecimento com lookup de endpoint e atributos
- fallback por `endpointName` quando o `endpointId` do incidente não coincide com o do inventário
- fallback do nome do sistema operacional via catálogo `organizationPublisherOperatingSystems`
- geração do resumo de cobertura por coluna
- persistência, leitura e validação de integridade do cache local
- cálculo de marcos temporais e merge incremental de endpoints e atributos
- construção de queries numéricas inclusivas
- particionamento numérico para endpoints, atributos e incidentes
- refino automático de partições quando há risco de paginação incompleta ou estouro operacional
- proteção contra overflow de paginação em eventos
- regras de intervalo fechado para `--from-date` e `--to-date`
- decisão entre refresh incremental e refresh completo do inventário
- falha controlada quando o cache local exigido não existe

Em termos práticos, essa suíte protege as áreas mais sensíveis do script: correlação dos campos exportados, previsibilidade da CLI, integridade do cache local e estratégia de particionamento/refino usada para reduzir falhas de coleta.

### Como executar

Se estiver dentro do diretório `vicarius-external-scripts/`, execute:

```bash
/usr/bin/time -p python -m unittest tests/test_export_inventory_vulnerabilities.py
```

Se preferir executar a partir da raiz do repositório, use:

```bash
/usr/bin/time -p python -m unittest vicarius-external-scripts/tests/test_export_inventory_vulnerabilities.py
```

### Resultado validado mais recentemente

Na validação mais recente desta documentação, a suíte foi executada com sucesso e retornou:

- `Ran 29 tests in 9.708s`
- `OK`

Recomendação operacional: sempre execute essa suíte após qualquer ajuste no script, nos helpers relacionados ao cache/particionamento ou na estrutura dos campos exportados. Se a alteração mudar comportamento esperado, atualize os testes na mesma entrega. Script sem teste reexecutado é só uma aposta com roupa formal.

## Resumo operacional

Em termos práticos, o script hoje segue esta estratégia:

1. atualizar o cache local do inventário quando solicitado
2. exportar incidentes `DetectedVulnerability` apenas no modo com cache local
3. exigir `--from-date` e `--to-date` para limitar a janela exportada
4. carregar o snapshot local do inventário
5. carregar o catálogo de sistemas operacionais
6. enriquecer e normalizar cada evento
7. exportar em `JSONL` e `CSV`
8. apresentar resumo de cobertura por coluna ao final

Esse desenho prioriza robustez, repetibilidade e menor ambiguidade operacional, mantendo apenas o comportamento que permaneceu útil e validado no script.

## Notas da Versão

- **v1.1.0** (Atual):
    - Implementação de **Rate Limiter Global** limitado a 50 requisições por minuto (margem de segurança).
    - Ajuste no tratamento de erro 429 para suportar o cabeçalho `X-Rate-Limit-Retry-After-Seconds`.
    - Proteção explícita contra paginação profunda (`from > 10.000`).
    - Adição de logs de progresso de cadência (`RateLimiter] ...`).
- **Inclusão da coluna KEV**: O script passou a extrair a indicação nativa de diretrizes KEV presentes no payload `incidentEvent/filter`.
- **Formatação de Extração KEV**: A coluna `KEV` foi introduzida no CSV/JSONL logo após a coluna `Vulnerability Summary`, informando o status usando a convenção de código `[Vulnerability ID] CVE-XXXX-XXXX` (ex. `[444299] CVE-2025-15556`).
- **Suporte a Múltiplos CVEs**: No caso da vulnerabilidade carregar mais de um CVE na nomenclatura (CVE em formato de lista textual), cada iteração de código é mapeada e unificada pelo delimitador `|`.

## Referências

- [Vicarius API Documentation](https://customer-portal.vicarius.io/api-max-throughput) — Detalhes técnicos sobre limites de throughput e paginação.
- [Conventional Commits](https://www.conventionalcommits.org/pt-br/) — Padrão utilizado no histórico de mudanças deste projeto.

## Isenção de Responsabilidade

O código gerado e as lógicas de integração contidas neste script e suas eventuais extensões são fornecidos "no estado em que se encontram" (*as-is*). Não há garantias explícitas ou implícitas de adequação a ambientes produtivos, de disponibilidade livre de falhas ou aderência contínua à API no longo prazo. O uso desta solução é de total responsabilidade do operador.

É expressamente recomendado que a estrutura lógica, parâmetros de tempo (`delay`/`sleep`) e a governança deste código sejam submetidos à análise prévia e validação técnica da **Vicarius** antes de sua inserção ou execução contínua em qualquer infraestrutura ou arquitetura de produção corporativa.
