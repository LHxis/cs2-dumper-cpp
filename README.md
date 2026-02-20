# cs2-dumper (C++ Port)

Port em C++ do projeto [cs2-dumper](https://github.com/a2x/cs2-dumper/tree/main), originalmente escrito em **Rust** por [a2x](https://github.com/a2x).

O objetivo deste port é oferecer a mesma funcionalidade do projeto original — extrair **offsets**, **interfaces**, **botões** e **schemas** do Counter-Strike 2 — utilizando C++17 puro com a Windows API, sem dependência de frameworks externos como o memflow.

---

## Sobre o Projeto Original

O [cs2-dumper](https://github.com/a2x/cs2-dumper/tree/main) é um dumper externo de offsets/interfaces para o CS2, escrito em Rust. Ele utiliza o [memflow](https://github.com/memflow/memflow) para leitura de memória e suporta tanto Windows quanto Linux. Os dados extraídos são exportados em múltiplos formatos (`.cs`, `.hpp`, `.json`, `.rs`), facilitando o uso em projetos de diferentes linguagens.

Este port em C++ replica a arquitetura e a lógica do projeto Rust, adaptando para o ecossistema C++ nativo do Windows.

---

## Estrutura dos Arquivos

| Arquivo | Descrição |
|---|---|
| `main.cpp` | Ponto de entrada — parser de argumentos CLI e orquestração geral |
| `analysis.cpp` / `analysis.h` | Análise do processo do CS2: extração de buttons, interfaces, offsets e schemas |
| `output.cpp` / `output.h` | Geração dos arquivos de saída nos formatos `.cs`, `.hpp`, `.json` e `.rs` |
| `process.cpp` / `process.h` | Abstração do processo do jogo — leitura de memória via `ReadProcessMemory` |
| `pattern.h` | Scanner de padrões de bytes (IDA-style, ex: `48 8B 15 ?? ?? ?? ??`) |
| `pe.h` | Parser de headers PE para resolução de exports |
| `source2.h` | Structs do engine Source 2 (layout de memória exato, matching com as definições Rust) |
| `util.h` | Utilitários: logging, formatação de strings, etc. |
| `CMakeLists.txt` | Build system — suporte a MSVC e MinGW |
| `cs2-dumper.sln` | Solution do Visual Studio |

---

## Compilação

### Visual Studio

1. Abra o `cs2-dumper.sln` no Visual Studio 2019+ (com suporte a C++17).
2. Selecione a configuração **Release x64**.
3. Compile com `Ctrl+Shift+B`.

### CMake

```bash
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### MinGW (MSYS2)

```bash
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

> **Nota:** Este projeto é exclusivo para Windows, pois utiliza `ReadProcessMemory`, `CreateToolhelp32Snapshot` e outras APIs do Windows para leitura de memória do processo do jogo.

---

## Uso

1. Certifique-se de que o **CS2 está rodando** (estar no menu principal é suficiente).
2. Execute o `cs2-dumper.exe` (recomendado rodar como **Administrador**).

```
cs2-dumper.exe [OPÇÕES]
```

### Argumentos Disponíveis

| Argumento | Descrição | Padrão |
|---|---|---|
| `-f, --file-types <TIPOS>` | Tipos de arquivo para gerar, separados por vírgula | `cs,hpp,json,rs` |
| `-i, --indent-size <TAM>` | Espaços por nível de indentação | `4` |
| `-o, --output <DIR>` | Diretório de saída | `output` |
| `-p, --process-name <NOME>` | Nome do processo do jogo | `cs2.exe` |
| `-v, --verbose` | Aumentar verbosidade (pode repetir: `-vvv`) | — |
| `-n, --no-log-file` | Não criar arquivo `cs2-dumper.log` | — |
| `-h, --help` | Exibir ajuda | — |

### Exemplos

```bash
# Uso básico (gera todos os formatos na pasta output/)
cs2-dumper.exe
```

```bash
# Gerar apenas .json e .hpp com verbosidade máxima
cs2-dumper.exe -f json,hpp -vvv
```

O flag `-f` permite escolher quais formatos de saída serão gerados, separados por vírgula. Neste exemplo, apenas `.json` e `.hpp` serão criados (em vez de todos os 4 formatos padrão).

O flag `-v` controla o nível de **verbosidade** do log durante a execução. Cada `-v` adicional aumenta a quantidade de informações exibidas no console:

| Nível | Flag | O que é exibido |
|---|---|---|
| 0 | *(sem -v)* | Apenas erros fatais |
| 1 | `-v` | Erros + avisos (warnings) |
| 2 | `-vv` | Erros + avisos + informações gerais (quantidade de offsets encontrados, tempo de execução, etc.) |
| 3 | `-vvv` | Tudo acima + mensagens de debug (cada offset/interface encontrado individualmente com endereço) |
| 4+ | `-vvvv` | Tudo acima + trace (detalhes internos de baixo nível) |

Sem nenhum `-v`, o programa roda silenciosamente e só imprime algo se ocorrer um erro. Com `-vvv` (verbosidade máxima útil), você consegue ver cada offset, interface e schema sendo extraído em tempo real, útil para debug ou para verificar se algum pattern está desatualizado.

```bash
# Salvar em outra pasta
cs2-dumper.exe -o meus_offsets
```

```bash
# Usar indentação de 2 espaços
cs2-dumper.exe -i 2
```

O flag `-i` define quantos espaços são usados por nível de indentação nos arquivos gerados. O padrão é **4 espaços**. Se preferir um código mais compacto, pode usar `-i 2` para gerar com 2 espaços. Isso afeta todos os formatos de saída (`.cs`, `.hpp`, `.rs` e `.json`).

**Exemplo da diferença:**

Com `-i 4` (padrão):
```cpp
namespace cs2_dumper {
    namespace offsets {
        namespace client_dll {
            constexpr std::ptrdiff_t dwEntityList = 0x1234;
        }
    }
}
```

Com `-i 2`:
```cpp
namespace cs2_dumper {
  namespace offsets {
    namespace client_dll {
      constexpr std::ptrdiff_t dwEntityList = 0x1234;
    }
  }
}
```

---

## O que é Extraído

| Categoria | Descrição |
|---|---|
| **Buttons** | Offsets dos botões de input do client (`attack`, `jump`, `forward`, etc.) — extraídos de `client.dll` |
| **Interfaces** | Ponteiros de interfaces registradas via `CreateInterface` em cada módulo do engine |
| **Offsets** | Offsets de variáveis internas do engine (`dwLocalPlayerPawn`, `dwEntityList`, etc.) |
| **Schemas** | Classes e enums do Schema System do Source 2, incluindo campos, tipos, offsets e metadados |

---

## Formatos de Saída

Os dados são exportados em 4 formatos:

- **`.cs`** — C# (namespaces e constantes `nint`/`uint`)
- **`.hpp`** — C++ (namespaces e `constexpr`)
- **`.json`** — JSON estruturado
- **`.rs`** — Rust (módulos e constantes)

---

## Diferenças em Relação ao Projeto Original (Rust)

| Aspecto | Rust (original) | C++ (este port) |
|---|---|---|
| Linguagem | Rust | C++17 |
| Leitura de memória | [memflow](https://github.com/memflow/memflow) (cross-platform) | Windows API (`ReadProcessMemory`) |
| Suporte a SO | Windows + Linux | Apenas Windows |
| Parser de CLI | `clap` (crate) | Parser manual integrado |
| Conectores externos | pcileech, kvm, etc. via memflow | Não suportado (leitura direta) |
| Build system | Cargo | CMake / Visual Studio |

---

## Créditos

- **[a2x](https://github.com/a2x)** — Autor do projeto original [cs2-dumper](https://github.com/a2x/cs2-dumper/tree/main) em Rust
- Este port em C++ foi desenvolvido com base na arquitetura e lógica do projeto original

---

## Licença

Licenciado sob a licença MIT ([LICENSE](LICENSE)).
