# Wireshark — Implementação base de uma nova janela de estatísticas
## Beatriz Vitória Pereira Moura (232076) e Rafael Masato Haga (247348)

Resumo de métricas TCP: contagem de retransmissões, RTT médio (mediana), perdas por segundo e pacotes fora de ordem. Ajustes no tap de conversas, alterações na UI e procedimento de testes.

## Visão geral
- Objetivo: expor métricas úteis por conversa TCP em "Conversations" para ajudar numa análise rápida.
- Métricas implementadas: Retransmissions, RTT, perdas por segundo e pacotes fora de ordem (implementação parcial).
- Coleta de amostras, flags a partir da análise TCP (`tcp_analysis`) e agregação no tap de conversas.
- UI Qt atualizada para exibir colunas estendidas.

## Retransmissions
- Ao percorrer os registros de análise TCP (`tcp_analysis->acked_table`),as flags que indicam retransmissões são somadas.
- A contagem se baseia nas marcações feitas pelo dissector TCP (flags de análise). Em casos complexos (duplicatas, reordenações ambíguas) a classificação decorre da lógica do dissector
- O total por conversa é gravado no campo de extensão (`conv_extension_tcp_t.retransmissions`).
- `epan/conversation_table.c` — leitura/agregação dos acked entries e incremento do contador de retransmissões.
- `ui/qt/models/atap_data_model.*` — mapeamento da coluna de retransmissões para a UI..

## RTT (Avg RTT / mediana)
- As amostras são recolhidas de RTT associadas a ACKs em `tcp_analysis->acked_table` e a soma, contagem e mediana são calculadas.
- Armazenamos agregados em `conv_extension_tcp_t` e expusemos na UI (coluna estendida mostrada como mediana em ms com contagem de amostras no conteúdo/tooltip).
- A célula apresenta a mediana (menos sensível a outliers); o tooltip contém média e mediana.
- Atualmente a agregação ocorre no tap (mais simples para protótipo). Para escalabilidade futura, pode ser melhor mover agregação incremental para o dissector TCP.
- `epan/conversation_table.h` / `epan/conversation_table.c` — novos campos e lógica de agregação (soma, contagem, mediana).
- `tools/generate_tcp_rtt_pcap.py` — utilitário para gerar pcaps determinísticos para validação.
- `ui/qt/models/atap_data_model.*` — apresentação do valor na coluna e tooltip.

## Pacotes fora de ordem (Out‑of‑order)
- Alterou-se a lógica do dissector TCP (`packet-tcp.c`) para marcar eventos OOO e adicionou-se um contador por conversa (`tcpd->ooo_count`).
- O tap de conversas lê `tcpd->ooo_count` e também faz fallback somando elementos em `ooo_segments` quando apropriado.
-  `expected_ooo` é calculado no arquivo de testes a partir da ordem de `tcp.seq` por frame e os CSVs são gerados por pacote para análise.
- `epan/dissectors/packet-tcp.c` / `epan/dissectors/packet-tcp.h` — instrumentação de marcação e contador `ooo_count`.
- `epan/conversation_table.c` — agregação e leitura de `ooo_count` / listas OOO.
- `tools/run_tcp_stats_tests.py` — harness que gera pcaps, extrai campos por frame e compara heurística vs dissector.
- Por que ainda não está perfeito:
- O dissector aplica uma lógica mais complexa do que a heurística simples; em muitos casos ele classifica como *RETRANSMISSION* ou "previous segments not captured" em vez de OOO, o que resulta em `ooo_count == 0` embora a heurística detecte reordenação. Também foram identificados caminhos onde a contagem não é feita de forma centralizada, e existe risco de timing (tap ler tcpd antes da atualização). Assim, a métrica ainda necessita de ajustes e normalização.

## Tap de conversas (Conversation tap)
- O TAP de conversas foi estendido para popular `conv_extension_tcp_t` com os novos agregados (RTT, retransmissions, out_of_order, losses estimadas e duração estatística).
- O tap agrega lendo `tcp_analysis` associado a cada conversa: percorre `acked_table`, recolhe amostras e flags e escreve os campos de extensão.
- Arquivos: `epan/conversation_table.c`, `epan/conversation_table.h`.
- A alteração localizada no tap tende a reduzir o impacto no dissector, mas pode ser refatorada para mover a agregação incremental para o dissector.

## UI (modificações) e testes realizados
- UI:
- Foram adicionadas colunas estendidas em `ui/qt/models/atap_data_model.h` / `.cpp` para as métricas: RTT, retransmissões, perdas por segundo e pacotes fora de ordem.
- A célula de RTT mostra mediana em ms e número de amostras; tooltip contém média, mediana e contagem.
- Coluna de retransmissões e out_of_order mostram contadores agregados; valores brutos também expostos para processamento downstream.

- Testes e validação:
- `tools/generate_tcp_rtt_pcap.py` cria um pcap determinístico usado para validar cálculo de RTT (amostras conhecidas: 1 ms, 1 ms, 20 ms → mediana 1.0 ms).
- `tools/run_tcp_stats_tests.py` gera vários pcaps sintéticos (baseline, retransmission, out_of_order, force_ooo, high_retrans), extrai campos por frame com `tshark`, produz `test/tcp_stats_results.csv` e por pacotes CSVs para inspeção (`test/per_packet_<scenario>.csv`).
- Adicionamos logs (`g_warning`) no dissector para ajudar nas decisões OOO/RETRANSMISSION para diagnosticar classificações.

## Próximos passos
- Consolidar marcação/contagem de OOO: criar um helper central em `packet-tcp.c` para evitar contagens dispersas/duplicadas.
- Auditar e, se necessário, ajustar as condições que distinguem RETRANSMISSION vs OUT_OF_ORDER na análise do dissector.
- Mover agregação para o dissector e expor contadores já agregados ao tap.
- Adicionar um fallback heurístico controlado na UI/tap para casos onde o dissector não marca eventos mas a heurística indicou reordenação.

