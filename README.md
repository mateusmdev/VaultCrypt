# VaultCrypt

VaultCrypt é uma ferramenta de linha de comando (CLI) escrita em Python para criptografar e descriptografar arquivos de texto de forma segura, eficiente e resiliente a falhas.

O projeto foi desenvolvido com foco em segurança local, isolamento entre arquivos e preservação dos dados originais em caso de erro.

## Principais Características

* Criptografia autenticada com **ChaCha20-Poly1305**
* Derivação de chave com **Argon2id**
* Salt aleatório exclusivo para cada arquivo
* Processamento paralelo com múltiplos workers
* Suporte a diretórios inteiros e processamento recursivo
* Rollback seguro em falhas
* Preservação do arquivo original em qualquer erro
* Verificação automática de integridade durante a descriptografia
* Feedback visual em tempo real utilizando Rich
* Nenhum arquivo temporário intermediário gravado em disco

---

## Como Funciona

### Criptografia

```text
arquivo.txt
      ↓
VaultCrypt
      ↓
arquivo.txt.vt
```

Durante a criptografia:

1. Um salt aleatório é gerado para o arquivo.
2. A chave é derivada da passphrase usando Argon2id.
3. O arquivo é dividido em chunks de 64 KiB.
4. Cada chunk é criptografado individualmente com ChaCha20-Poly1305.
5. O resultado é armazenado em um arquivo `.vt`.

Após a conclusão bem-sucedida:

* O arquivo original é removido.
* Apenas o arquivo criptografado permanece.

### Descriptografia

```text
arquivo.txt.vt
        ↓
VaultCrypt
        ↓
arquivo.txt
```

Durante a descriptografia:

1. O cabeçalho do arquivo é validado.
2. O salt é extraído.
3. A chave é rederivada com Argon2id.
4. Cada chunk é autenticado antes de ser descriptografado.
5. O conteúdo é restaurado.

Após a conclusão bem-sucedida:

* O arquivo `.vt` é removido.
* O arquivo original é restaurado.

---

## Requisitos

* Python 3.12 ou superior
* Linux, macOS ou Windows

---

## Instalação

Clone o repositório:

```bash
git clone <repositorio>
cd vault
```

Instale as dependências:

```bash
pip install -r requirements.txt
```

---

## Uso

### Criptografar um arquivo

```bash
python vault.py \
  --path documento.txt \
  --key "minha-senha" \
  --encrypt
```

### Descriptografar um arquivo

```bash
python vault.py \
  --path documento.txt.vt \
  --key "minha-senha" \
  --decrypt
```

### Criptografar um diretório

```bash
python vault.py \
  --path ./docs \
  --key "minha-senha" \
  --encrypt
```

### Criptografar recursivamente

```bash
python vault.py \
  --path ./docs \
  --key "minha-senha" \
  --encrypt \
  --recursive
```

### Controlar o número de workers

```bash
python vault.py \
  --path ./docs \
  --key "minha-senha" \
  --encrypt \
  --workers 8
```

---

## Argumentos

| Argumento           | Descrição                                 |
| ------------------- | ----------------------------------------- |
| `--path`, `-p`      | Arquivo ou diretório a processar          |
| `--key`, `-k`       | Passphrase utilizada para derivar a chave |
| `--encrypt`         | Modo de criptografia                      |
| `--decrypt`         | Modo de descriptografia                   |
| `--recursive`, `-r` | Processa subdiretórios                    |
| `--workers`, `-w`   | Número de workers paralelos               |

---

## Arquivos Suportados

### Entrada para criptografia

```text
.txt
.md
```

### Entrada para descriptografia

```text
.txt.vt
.md.vt
```

Arquivos incompatíveis são rejeitados com mensagens de erro claras.

---

## Segurança

### Algoritmos

| Componente       | Implementação                 |
| ---------------- | ----------------------------- |
| Criptografia     | ChaCha20-Poly1305             |
| KDF              | Argon2id                      |
| Tamanho da chave | 256 bits                      |
| Salt             | 32 bytes por arquivo          |
| Nonce            | 12 bytes por chunk            |
| Autenticação     | Poly1305 (16 bytes por chunk) |

### Garantias

* Arquivos diferentes geram chaves diferentes mesmo usando a mesma passphrase.
* Alterações no arquivo criptografado são detectadas automaticamente.
* Chaves erradas falham na autenticação dos dados.
* Nenhuma chave é armazenada pela ferramenta.
* Nenhum arquivo temporário intermediário é criado em disco.

### Limitações

* Não existe mecanismo de recuperação de chave.
* Perda da passphrase implica perda permanente do acesso aos dados.
* A passphrase fornecida por linha de comando pode ser visível para outros usuários do sistema através de ferramentas como `ps`.

---

## Estrutura do Projeto

```text
vault/
├── vault.py
├── requirements.txt
├── src/
│   ├── cli/
│   ├── crypto/
│   ├── pipeline/
│   ├── progress/
│   ├── storage/
│   ├── transactions/
│   ├── utils/
│   ├── validators/
│   └── workers/
└── tests/
```

---

## Executando os Testes

Todos os testes:

```bash
python -m pytest tests/
```

Modo verboso:

```bash
python -m pytest tests/ -v
```

Com cobertura:

```bash
python -m pytest tests/ --cov=src --cov-report=term-missing
```

---

## Tratamento de Falhas

VaultCrypt foi projetado para preservar os dados originais sempre que possível.

Algumas garantias importantes:

* Destinos existentes nunca são sobrescritos.
* Falha em um arquivo não interrompe os demais.
* Arquivos originais são preservados em caso de erro.
* Interrupções via Ctrl+C cancelam operações em andamento com limpeza segura dos recursos utilizados.
* Arquivos processados com sucesso permanecem válidos mesmo que outros falhem.

---

## Licença

... .
