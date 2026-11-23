# Panoptes

> Panoptes, o gigante de cem olhos que nunca dormia.

Monitor de custo zero para os meus sites: **SLA, SLO, segurança e IA**, rodando só em GitHub Actions + GitHub Pages. Sem contas novas, sem cartão de crédito e sem secrets obrigatórios.

**Status page:** https://ogatalars.github.io/panoptes/

[English version below](#english)

## O que ele faz

| Pilar | Como |
|---|---|
| **SLI** | A cada ~15 min, um probe HTTP por alvo. Um probe é "bom" se voltou `2xx` dentro do limite de latência (2 s). SLI = % de probes bons nos últimos 30 dias. |
| **SLO vs SLA** | Cada alvo tem um SLO interno (99,5%) mais rígido que o SLA público (99%). A página mostra o error budget restante das duas linhas lado a lado. |
| **Burn rate** | Alertas multiwindow (Google SRE Workbook), adaptados à cadência de 15 min: `fast` 1h/30min a 14,4x, `slow` 6h/1h a 6x, `drift` 3d/6h a 1x (só aviso). |
| **Segurança** | Dias até o certificado TLS expirar e headers de segurança por alvo. Toda semana, Trivy (CVEs de dependências, secrets, misconfig) e Semgrep (SAST) em todos os meus repositórios públicos. |
| **IA** | Quando um alvo cai ou um alerta de página dispara, abre (ou atualiza) **uma** issue por alvo com fatos, timeline e um rascunho de postmortem escrito por um LLM. A IA só escreve texto. |

### Por que o SLO é mais rígido que o SLA?

O SLA é a promessa feita para quem usa; o SLO é o alarme interno, mais apertado, para o time perceber e reagir enquanto ainda há folga antes de quebrar a promessa pública.

Exemplo com SLI de 99,3%: o budget do SLO (99,5%) já estourou, mas o SLA (99%) ainda está cumprido. É exatamente essa janela que o SLO existe para criar.

## Arquitetura

```
targets.json            alvos, SLO, SLA e limite de latência (único lugar para configurar)
panoptes/probe.py       HTTP, TLS e headers (só stdlib do Python)
panoptes/slo.py         SLI, error budget, burn rate, cobertura
panoptes/monitor.py     uma rodada: probe -> histórico -> status.json -> incidentes
panoptes/incident.py    issues no GitHub + rascunho opcional por LLM
panoptes/scan.py        resume os relatórios do Trivy/Semgrep (só contagens)
site/                   status page em HTML/CSS/JS puro
.github/workflows/      monitor (15 min), security-scan (semanal), ci (testes)
```

## Onde os dados ficam (e por que não incham o `main`)

- O histórico bruto (`history.json`) e o resumo (`status.json`) vivem na branch **`data`**.
- Cada rodada recria essa branch como **um único commit órfão** e faz force-push. A branch sempre tem 1 commit, então não acumula ~100 commits por dia em lugar nenhum.
- O histórico é uma janela móvel de 30 dias: amostras mais velhas são descartadas a cada rodada. 3 alvos x 96 probes/dia x 30 dias ≈ 8.600 amostras, uns 260 KB. Limitado por construção.
- A página não lê o histórico bruto: o `status.json` já traz o agregado (SLI diário, últimas 24h).
- O `main` só recebe código e **um** commit por semana do scan de segurança (`security/summary.json`).

O force-push é intencional e restrito à branch `data`, que é descartável: se ela sumir, o monitor recomeça a janela do zero.

## Medição honesta

- O `cron` do GitHub Actions é best-effort: execuções podem atrasar vários minutos (mais em horário de pico) e às vezes são puladas. O SLI é calculado sobre os probes que **de fato** rodaram: um probe pulado é um ponto cego, não um sucesso.
- Por isso a página mostra, por alvo, probes recebidos vs esperados e o maior buraco entre probes.
- Os probes saem de runners do GitHub. Uma falha de rede do runner aparece como falha do alvo. Para não acordar ninguém por um soluço, um alerta exige pelo menos 2 probes ruins na janela longa.
- O agendamento usa minutos "quebrados" (`7,22,37,52`) para fugir do pico do minuto `:00`.

### O GitHub desliga workflows agendados após 60 dias?

Sim. A [documentação oficial](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/disable-and-enable-workflows) diz que, em repositório público, workflows agendados são desativados automaticamente quando não há atividade no repositório por 60 dias. A documentação **não** define se commits feitos por bot (`GITHUB_TOKEN`) contam como atividade, e relatos da comunidade divergem. Mitigação adotada, sem certeza de que baste sozinha:

1. O scan semanal faz um commit real no `main` (o resumo de segurança). Relatos indicam que commits reais renovam o prazo, enquanto só "reativar" o workflow pela API não renova.
2. Os force-pushes na branch `data` a cada 15 min também podem contar (não confirmado).
3. Se mesmo assim desativar, o GitHub manda e-mail e basta reativar em Actions (um clique).

## IA: rascunho de postmortem

A ideia original era usar o **GitHub Models** com `GITHUB_TOKEN`. Porém o [GitHub Models foi aposentado em 30/07/2026](https://github.blog/changelog/2026-07-30-github-models-is-now-retired/): o endpoint `models.github.ai` não responde mais com completions. A alternativa oficial (Copilot em Actions) consome créditos pagos, o que quebra o "custo zero".

Por isso:

- **Sem configuração (padrão):** a issue é aberta mesmo assim, com fatos, timeline dos probes e a nota "AI draft unavailable".
- **Com um endpoint compatível com OpenAI:** defina as variáveis do repositório `LLM_ENDPOINT` e `LLM_MODEL` (e, se o provedor exigir, o secret `LLM_API_KEY`). O monitor pede o rascunho com Resumo, Timeline, Causa provável e Próximos passos. Se a chamada falhar ou voltar algo inválido, a issue sai sem a seção de IA.

Regras que valem nos dois casos: uma issue aberta por alvo (dedupe pelo título), comentário só quando o estado muda (cai -> abre/comenta; volta -> comenta e fecha) e a IA nunca altera código ou config. O prompt leva só status HTTP e latências, nunca o conteúdo das páginas, então não há como uma página monitorada injetar instruções no modelo.

Para testar o caminho de incidente sem derrubar nada: `gh workflow run monitor -f drill=cv`. A rodada abre a issue marcada como drill, e a próxima rodada normal a fecha. O drill não altera os dados do SLI.

## Segurança: headers no GitHub Pages

O GitHub Pages não deixa configurar headers HTTP. O monitor modela isso honestamente:

- `ok`: o header foi enviado (no Pages, só HSTS);
- `meta`: a política foi declarada em `<meta>` no HTML (possível para CSP e Referrer-Policy);
- `platform`: ausente porque o host não permite. É uma limitação conhecida da plataforma, mostrada mas **fora** do error budget;
- `missing`: ausente num host que permite configurar (`"headers_configurable": true` no `targets.json`). Esse é um problema de verdade.

A própria status page declara CSP e Referrer-Policy via `<meta>`. O resumo do scan semanal publica só contagens por severidade, nunca caminhos de arquivo ou trechos de secrets.

## Custo

| Item | Custo |
|---|---|
| Repositório público | grátis |
| GitHub Actions em runner padrão (`ubuntu-latest`) em repo público | grátis, sem limite de minutos |
| GitHub Pages | grátis |
| Trivy, Semgrep (regras públicas, `--metrics=off`) | grátis, sem login |
| Issues via `GITHUB_TOKEN` | grátis |
| LLM | desligado por padrão. Só custa se você configurar um provedor pago |

## Rodar localmente

```bash
python3 -m unittest -v                  # testes da matemática de SLO e do parsing
PANOPTES_DATA=/tmp/panoptes python3 -m panoptes.monitor targets.json
```

Sem `GITHUB_TOKEN` no ambiente, a parte de issues é pulada.

---

## English

**Panoptes** is a zero-cost monitor for my sites running only on GitHub Actions and Pages.

- **SLI:** a probe every ~15 min per target. Good = `2xx` within 2 s. SLI = share of good probes over 30 days.
- **SLO vs SLA:** an internal 99.5% SLO, stricter than a public 99% SLA, so the team reacts before the public promise breaks. Both error budgets are shown side by side, along with multiwindow burn-rate alerts adapted to a 15-minute cadence.
- **Security:** TLS days-to-expiry and security headers per target. Headers GitHub Pages cannot set show as a *platform limitation*, never as budget-burning failures. Every week, Trivy and Semgrep scan all my public repos (only counts are published).
- **AI:** one deduplicated GitHub issue per target when it goes down or a page-level burn alert fires, with facts, a probe timeline and an optional LLM-drafted postmortem. GitHub Models was retired on 2026-07-30, so the AI step uses any OpenAI-compatible endpoint set through repo variables and is off by default. The issue always opens, with or without the AI section.
- **Data:** a rolling 30-day window stored on a `data` branch that is rewritten as a single orphan commit on every run, so history stays bounded and `main` stays clean.
- **Honesty:** Actions cron is delayed or skipped at times. The page shows probes received vs expected and the largest gap. Scheduled workflows in public repos are disabled after 60 days of inactivity; a weekly real commit on `main` is the mitigation.

MIT licensed.
