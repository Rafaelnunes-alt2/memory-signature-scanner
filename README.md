# memory-signature-scanner

Scanner de assinaturas em arquivo e memória de processo, só leitura, sem modificar nada. Padrão em hex com wildcard `??`, motor em C++17 puro. Backend Windows via ReadProcessMemory e backend Linux via process_vm_readv, com modo arquivo portátil.

## Por que eu fiz isso

Queria o mesmo motor que EDR usa para achar padrão em memória, sem hook e sem escrita. Comecei pelo parser de padrão e terminei lendo região por região com limite de tamanho para não derrubar o processo alvo.

## Como funciona

Três partes, todas com teto para não estourar.

1. Padrão: texto tipo `48 8B 05 ?? ?? ?? ?? 48 85 C0` vira vetor de bytes com flag wild. Rejeita token inválido, padrão vazio e padrão maior que 256 bytes.

2. Motor: busca linear com early exit no primeiro byte divergente. Limite de 10000 hits e 256 MB por scan. Padrão só com wildcard casa em toda posição, que é o comportamento correto.

3. Alvos: modo arquivo lê até 256 MB e escaneia. Modo pid no Linux itera `/proc/pid/maps`, só região com `r`, pula região maior que 64 MB, total máximo 256 MB, lê com process_vm_readv. No Windows itera com VirtualQueryEx, só MEM_COMMIT legível sem GUARD, lê com ReadProcessMemory. Modo processo por nome resolve pid via comm no Linux e Toolhelp no Windows.

## Segurança

Só leitura. Nenhuma chamada de escrita, nenhum VirtualProtect, nenhum CreateRemoteThread. Pid validado entre 1 e 4194304, nome até 256 chars. Região sem leitura é pulada. Falha de leitura em uma região não aborta o scan, só pula. Compila com -Wall -Wextra -Wpedantic -Werror, fortify e stack protector.

## Estrutura

    src/
      main.cpp         CLI e saída
      scanner.cpp      parser de padrão e motor
      proc_linux.cpp   backend Linux via proc maps
      proc_win.cpp     backend Windows via API
    include/
      scanner.hpp      tipos e limites
    patterns/
      examples.txt     padrões de exemplo
    examples/
      output-selftest.txt    validação do motor
      output-file-elf.txt    scan de arquivo real
    CMakeLists.txt
    README.md

## Como compilar

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j
    ./build/scanner --selftest

No Windows abre o mesmo CMakeLists no Visual Studio.

## Como rodar

    scanner --file <path> --pattern "48 8B ??"
    scanner --pid <pid> --pattern "48 8B 05 ?? ?? ?? ?? 48 85 C0"
    scanner --process <nome> --pattern "55 48 89 E5"
    scanner --selftest

Saída em stdout com um endereço por linha em hex, contagem em stderr como hits=N. Retorno 0 em sucesso, 1 em argumento ou padrão inválido, 2 em falha de acesso.

## Testes validados

    --selftest com buffer de 4096 bytes, padrão exato acha 1 em offset 100 — OK
    --selftest com wildcard acha 2 — OK
    --file em /bin/ls com 7F 45 4C 46 acha 0x0 — OK
    --file com 7F 45 ?? 46 acha 0x0 — OK
    padrão ZZ rejeitado com bad_hex — OK
    arquivo inexistente rejeitado com open_failed — OK
    --pid em container bloqueado por Yama com EPERM, código trata como região pulada — documentado

Saídas em examples/.

## Benchmark

Medido nessa máquina, build Release, padrão de 4 a 6 bytes:

    arquivo de 64 MB aleatório, 0 hits, 0.159 s — cerca de 402 MB/s
    launcher_v5.exe de 5.8 MB, padrão 55 48 89 E5, 13 hits, 0.018 s — cerca de 322 MB/s

Motor linear com early exit. Suficiente para binário e região de processo sem travar.

## Diferenças para scanners existentes

YARA é engine de regras completa com condição e metadata. Esse scanner é binário único sem dependência, só match de bytes com wildcard.

Cheat Engine escaneia e escreve, com GUI. Esse só lê, via CLI, para auditoria e EDR.

EDR interno é fechado. Esse é aberto, portátil Windows mais Linux, com backend separado por SO.

## Limitações

Scan de pid precisa de mesma permissão de usuário e ptrace_scope permissivo no Linux, ou SeDebugPrivilege no Windows. Container com Yama em 1 bloqueia process_vm_readv e /proc/pid/mem, por isso validação de pid foi feita em código mais selftest mais file. Não faz escrita, não injeta, não esconde handle. Padrão todo wildcard casa em tudo, que é esperado mas gera muitos hits.

## Próximos passos

Algoritmo Horspool com wildcard para região grande, saída em JSON com pid mais endereço mais bytes, modo contínuo com intervalo para monitorar EDR.

## Autor

Rafael Nunes — [@Rafaelnunes-alt2](https://github.com/Rafaelnunes-alt2)
