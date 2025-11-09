# Contagem de retransmissões em uma conexão TCP

Status: Concluído (prova-de-conceito + UI)

## Objetivo
Adicionar a contagem dos pacotes retransmitidos em uma conexão TCP e apresenta-las na inteface "Conversations". A implementação seguiu uma estratégia semelhante a desenvolvida no cálculo do RTT médio, identificando e contabilizando os segmentos retransmitidos através do ACKs armazenados na estrutura `tcp_analysis`.

## Resumo do trabalho realizado
- Adiciona um contador de retransmissões incrementado ao percorrer `tcp_analysis->acked_table`;
- Atualiza a UI de Conversations (Qt) e adiciona um tooltip para incluir o dado armazenado no contador de retransmissões;
- Atualiza o gerador de pcap para incluir retransmissões - inclui uma variavel de configuração para desabilitar a função no inicio do arquivo;
- O código foi compilado e validado com o pcap de teste gerado;

## Ficheiros alterados
- `ui/qt/models/atap_data_model.h`
    - Adiciona a enumeração `CONV_TCP_EXT_COLUMN_RETRANS` para a coluna extendida;

- `ui/qt/models/atap_data_model.cpp`
    - Adiciona novo cabeçalho para retransmissões, preenche o campo alterando `ConversationDataModel::data()`, apresentando número de segmentos retransmitidos, dado é adicionado ao tooltip. Assim como no caso do RTT médio o dado bruto também é retornado para processamento posterior;

- `tools/generate_tcp_rtt_pcap.py`
    - Adiciona geração de segmentos repetidos, simulando retransmissões. Adiciona uma variavel de configuração para desabilitar a opção;

