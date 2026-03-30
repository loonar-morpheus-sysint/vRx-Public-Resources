# Vicarius vRx — Recursos Públicos e Automações

Este repositório consolidado (Monorepo) contém scripts, ferramentas de integração, dashboards e proxies para facilitar a operação na plataforma vRx.

## Índice de Soluções

| Categoria | Solução | Descrição | Link |
| :--- | :--- | :--- | :--- |
| **Scripts** | `export-inventory-vulnerabilities` | Exportação de inventário e vulnerabilidades com enriquecimento e cache local. | [Docs](./vicarius-external-scripts/export-inventory-vulnerabilities.md) |
| **Dashboard** | `vicarius-Reports-Dashboard` | Painéis e relatórios consolidados para vRx. | [Dir](./vicarius-Reports-Dashboard/) |
| **Proxy** | `vicarius-proxy` | Intermediário seguro para chamadas de API Vicarius. | [Dir](./vicarius-proxy/) |
| **API** | `vrx-postman-collection` | Coleção de requisições prontas para testes via Postman/Insomnia. | [Dir](./vrx-postman-collection/) |

## Estrutura do Projeto

- `.github/workflows/`: Pipelines de CI/CD para validação e release.
- `assets/`: Materiais de suporte, diagramas e referências externas.
- `docs/`: Documentação complementar e arquitetura.
- `LICENSE`: Licença MIT para uso público.
- `THIRDPARTY.md`: Lista de dependências de terceiros utilizadas.

## Como Contribuir

Consulte o arquivo [CONTRIBUTING.md](./CONTRIBUTING.md) para detalhes sobre o padrão de commits semânticos e fluxo de PRs.

## Isenção de Responsabilidade

Todas as soluções aqui contidas são fornecidas "no estado em que se encontram" e seu uso é de responsabilidade do operador. Consulte sempre a documentação oficial da Vicarius antes de execuções em larga escala.
