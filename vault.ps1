#Requires -Version 5.1
<#
.SYNOPSIS
    VaultCrypt — Interface Interativa para vault.exe

.DESCRIPTION
    Script PowerShell que fornece uma interface de menus para a ferramenta
    vault.exe, abstraindo completamente a sintaxe da linha de comando.

    O usuario interage apenas com menus e prompts. Flags, parametros e
    argumentos da CLI sao montados e executados internamente pelo script.

.NOTES
    Versao     : 1.0
    Requisitos : PowerShell 5.1+ (Windows PowerShell ou PowerShell 7+)
                 Windows 10 ou superior
                 dist\vault.exe presente no diretorio do script

    Estrutura esperada:
        Projeto\
        |-- vault.ps1       <- este arquivo
        +-- dist\
            +-- vault.exe

    CONFIGURACAO:
        Edite a variavel $script:FixedPath na secao "CONFIGURACOES" abaixo
        para definir a pasta usada pelas opcoes 1 e 2.

    SEGURANCA:
        A chave e solicitada via Read-Host -AsSecureString (entrada mascarada).
        O texto plano e derivado do SecureString apenas no momento de execucao,
        e a memoria BSTR e zerada imediatamente apos o uso (ZeroFreeBSTR).
        A chave nunca e armazenada em arquivo ou escrita em log.
#>

Set-StrictMode -Version Latest

# =============================================================================
# CONFIGURACOES — EDITE AQUI
# =============================================================================

# Caminho do executavel. $PSScriptRoot resolve para o diretorio deste script,
# garantindo que o caminho seja relativo independente de onde o script e chamado.
$script:VaultExe = Join-Path $PSScriptRoot 'dist\vault.exe'

# Caminho fixo utilizado pelas opcoes 1 (Criptografar) e 2 (Descriptografar).
# >>> Substitua pelo caminho completo da pasta que deseja proteger. <<<
# Exemplo: $script:FixedPath = 'C:\Users\joao\Documents\Notas'
$script:FixedPath = Join-Path $PSScriptRoot 'vault_data'

# =============================================================================
# FUNCOES AUXILIARES DE INTERFACE
# =============================================================================

function Write-Header {
    <#
    .SYNOPSIS
        Exibe um cabecalho padrao para cada secao ou operacao.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Title
    )
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host "   $Title" -ForegroundColor White
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host ''
}

function Write-Divider {
    <#
    .SYNOPSIS
        Exibe uma linha separadora leve entre subsecoes.
    #>
    Write-Host '  ------------------------------------------------------------' -ForegroundColor DarkGray
}

function Write-ResultPanel {
    <#
    .SYNOPSIS
        Exibe o painel de resultado ao final de cada operacao.
    .PARAMETER ExitCode
        Codigo de retorno do vault.exe. Zero indica sucesso.
    #>
    param (
        [Parameter(Mandatory)]
        [int]$ExitCode
    )
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    if ($ExitCode -eq 0) {
        Write-Host '   Operacao concluida com sucesso.' -ForegroundColor Green
    } else {
        Write-Host '   A operacao terminou com falha.' -ForegroundColor Red
        Write-Host "   Codigo de retorno : $ExitCode" -ForegroundColor Red
        Write-Host '   Consulte as mensagens acima para detalhes.' -ForegroundColor Yellow
    }
    Write-Host '  ============================================================' -ForegroundColor Cyan
}

function Wait-KeyPress {
    <#
    .SYNOPSIS
        Aguarda o usuario pressionar qualquer tecla antes de continuar.
        Compativel com PowerShell 5.1 e 7+.
    #>
    param (
        [string]$Message = '  Pressione qualquer tecla para continuar...'
    )
    Write-Host ''
    Write-Host $Message -ForegroundColor DarkGray
    try {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    } catch {
        # Fallback para ambientes que nao suportam ReadKey (ex: ISE)
        $null = Read-Host '  Pressione Enter para continuar'
    }
}

# =============================================================================
# FUNCOES DE VALIDACAO
# =============================================================================

function Test-VaultExecutable {
    <#
    .SYNOPSIS
        Verifica se o executavel vault.exe existe no caminho configurado.
    .OUTPUTS
        [bool] $true se encontrado, $false caso contrario (com mensagem de erro).
    #>
    if (-not (Test-Path -LiteralPath $script:VaultExe -PathType Leaf)) {
        Clear-Host
        Write-Host ''
        Write-Host '  ============================================================' -ForegroundColor Red
        Write-Host '   ERRO — Executavel nao encontrado' -ForegroundColor Red
        Write-Host '  ============================================================' -ForegroundColor Red
        Write-Host ''
        Write-Host '   vault.exe nao foi localizado em:' -ForegroundColor White
        Write-Host ''
        Write-Host "   $script:VaultExe" -ForegroundColor Yellow
        Write-Host ''
        Write-Host '   Certifique-se de que a pasta dist\ existe e contem' -ForegroundColor White
        Write-Host '   o arquivo vault.exe, depois execute vault.ps1 novamente.' -ForegroundColor White
        Write-Host ''
        Write-Host '  ============================================================' -ForegroundColor Red
        Wait-KeyPress -Message '  Pressione qualquer tecla para sair...'
        return $false
    }
    return $true
}

function Test-UserPath {
    <#
    .SYNOPSIS
        Valida se um caminho informado pelo usuario existe e e acessivel.
    .PARAMETER InputPath
        Caminho a ser validado.
    .OUTPUTS
        [bool] $true se valido e acessivel, $false com mensagem de erro.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$InputPath
    )

    # Verificar se a entrada nao e vazia
    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        Write-Host ''
        Write-Host '  [ERRO] O caminho nao pode ser vazio.' -ForegroundColor Red
        return $false
    }

    # Verificar existencia do caminho
    try {
        if (-not (Test-Path -LiteralPath $InputPath -ErrorAction Stop)) {
            Write-Host ''
            Write-Host '  [ERRO] Caminho nao encontrado:' -ForegroundColor Red
            Write-Host "  $InputPath" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host ''
        Write-Host '  [ERRO] Caminho invalido ou inacessivel:' -ForegroundColor Red
        Write-Host "  $InputPath" -ForegroundColor Yellow
        return $false
    }

    # Verificar permissao de leitura
    try {
        $item = Get-Item -LiteralPath $InputPath -ErrorAction Stop

        if ($item.PSIsContainer) {
            # Pasta: verificar se e possivel listar o conteudo
            $null = Get-ChildItem -LiteralPath $InputPath -ErrorAction Stop
        } else {
            # Arquivo: verificar se e possivel abrir para leitura
            $stream = [System.IO.File]::OpenRead($InputPath)
            $stream.Close()
            $stream.Dispose()
        }
    } catch [System.UnauthorizedAccessException] {
        Write-Host ''
        Write-Host '  [ERRO] Acesso negado ao caminho informado.' -ForegroundColor Red
        Write-Host "  $InputPath" -ForegroundColor Yellow
        return $false
    } catch {
        # Outros erros de permissao: deixar vault.exe reportar com detalhes
    }

    return $true
}

# =============================================================================
# FUNCOES DE ENTRADA DO USUARIO
# =============================================================================

function Get-EncryptionKey {
    <#
    .SYNOPSIS
        Solicita a chave ao usuario com entrada mascarada (SecureString).
    .DESCRIPTION
        Usa Read-Host -AsSecureString para que a chave nao seja exibida
        durante a digitacao. Retorna $null se o usuario deixar a entrada vazia.
    .PARAMETER OperationName
        Nome da operacao exibido no prompt (ex: 'Criptografar').
    .OUTPUTS
        [System.Security.SecureString] Chave, ou $null se entrada vazia.
    #>
    param (
        [string]$OperationName = 'operacao'
    )

    Write-Host ''
    Write-Divider
    Write-Host '   Informe a chave  (entrada mascarada com asteriscos):' -ForegroundColor White
    Write-Divider
    Write-Host ''

    $secureKey = Read-Host -AsSecureString -Prompt "  Chave de $OperationName"

    if ($secureKey.Length -eq 0) {
        Write-Host ''
        Write-Host '  [AVISO] Nenhuma chave informada. Operacao cancelada.' -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return $null
    }

    return $secureKey
}

function Get-UserInputPath {
    <#
    .SYNOPSIS
        Solicita, limpa e valida o caminho informado pelo usuario.
    .DESCRIPTION
        Remove aspas externas inseridas ao colar caminhos com espacos.
        Repete o prompt ate receber um caminho valido ou entrada vazia.
    .OUTPUTS
        [string] Caminho validado, ou $null se o usuario cancelou.
    #>
    while ($true) {
        Write-Host ''
        Write-Divider
        Write-Host '   Informe o caminho do arquivo ou pasta:' -ForegroundColor White
        Write-Divider
        Write-Host ''
        Write-Host '   Dica: voce pode colar o caminho diretamente nesta janela.' -ForegroundColor DarkGray
        Write-Host '   Entrada vazia = cancelar e voltar ao menu principal.' -ForegroundColor DarkGray
        Write-Host ''

        $rawInput = Read-Host '    Caminho'

        # Remover aspas externas inseridas ao colar caminhos com espacos
        $cleanPath = $rawInput.Trim().Trim('"').Trim("'")

        # Entrada vazia: usuario cancelou a operacao
        if ([string]::IsNullOrWhiteSpace($cleanPath)) {
            Write-Host ''
            Write-Host '  Operacao cancelada.' -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            return $null
        }

        # Validar o caminho antes de prosseguir
        if (Test-UserPath -InputPath $cleanPath) {
            return $cleanPath
        }

        # Caminho invalido: informar e oferecer nova tentativa
        Write-Host ''
        Write-Host '  Verifique o caminho e tente novamente.' -ForegroundColor Yellow
        Start-Sleep -Seconds 3
    }
}

# =============================================================================
# FUNCAO CENTRAL DE EXECUCAO DO VAULT
# =============================================================================

function Invoke-VaultCommand {
    <#
    .SYNOPSIS
        Constroi e executa vault.exe com os parametros fornecidos.
    .DESCRIPTION
        Funcao centralizada responsavel por toda a interacao com vault.exe.

        O SecureString e convertido para texto plano apenas aqui, imediatamente
        antes da execucao, e a memoria BSTR e zerada com ZeroFreeBSTR logo apos.

        *** AREA DE CONFIGURACAO DOS ARGUMENTOS DA CLI ***
        Os nomes dos parametros e flags estao declarados como variaveis locais
        no inicio desta funcao. Ajuste-os aqui caso a interface da ferramenta mude,
        sem necessidade de alterar o restante do script.

    .PARAMETER Path
        Caminho do arquivo ou pasta a processar.
    .PARAMETER Key
        Chave de criptografia como SecureString.
    .PARAMETER Operation
        'encrypt' para criptografar, 'decrypt' para descriptografar.
    .PARAMETER Recursive
        Switch. Quando presente, adiciona a flag de recursao ao comando.
    .OUTPUTS
        [int] Codigo de retorno do vault.exe (0 = sucesso).
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [System.Security.SecureString]$Key,

        [Parameter(Mandatory)]
        [ValidateSet('encrypt', 'decrypt')]
        [string]$Operation,

        [switch]$Recursive
    )

    # =========================================================================
    # MAPEAMENTO DOS ARGUMENTOS DA CLI — AJUSTE AQUI SE NECESSARIO
    # =========================================================================
    $paramPath     = '--path'       # Argumento de caminho
    $paramKey      = '--key'        # Argumento da chave
    $flagEncrypt   = '--encrypt'    # Flag de criptografia
    $flagDecrypt   = '--decrypt'    # Flag de descriptografia
    $flagRecursive = '--recursive'  # Flag de recursao (subpastas)
    # =========================================================================

    $bstr     = $null
    $plainKey = $null

    try {
        # Converter SecureString para texto plano apenas no momento de execucao.
        # O BSTR alocado pela conversao contem a chave em texto puro na memoria;
        # ZeroFreeBSTR no bloco finally garante que esses bytes sejam zerados.
        $bstr     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
        $plainKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        # Selecionar flag de operacao
        $operationFlag = if ($Operation -eq 'encrypt') { $flagEncrypt } else { $flagDecrypt }

        # Construir lista de argumentos como array
        $argList = @($paramPath, $Path, $paramKey, $plainKey, $operationFlag)
        if ($Recursive) {
            $argList += $flagRecursive
        }

        # Executar vault.exe repassando os argumentos como elementos separados.
        # O splatting com @argList garante que espacos em caminhos sejam tratados
        # corretamente, sem necessidade de escapamento manual.
        & $script:VaultExe @argList

        return $LASTEXITCODE

    } catch {
        Write-Host ''
        Write-Host '  [ERRO] Falha ao executar vault.exe:' -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        return -1

    } finally {
        # Zerar os bytes da chave na memoria antes de liberar o BSTR
        if ($null -ne $bstr) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        # Remover referencia ao texto plano
        $plainKey = $null
    }
}

# =============================================================================
# MENUS
# =============================================================================

function Show-MainMenu {
    <#
    .SYNOPSIS
        Exibe o menu principal e retorna a opcao escolhida pelo usuario.
    .OUTPUTS
        [string] '0' a '4' correspondendo a opcao selecionada.
    #>
    while ($true) {
        Clear-Host
        Write-Host ''
        Write-Host '  ============================================================' -ForegroundColor Cyan
        Write-Host '   VaultCrypt  -  Interface de Criptografia' -ForegroundColor White
        Write-Host '  ============================================================' -ForegroundColor Cyan
        Write-Host ''
        Write-Host "   Pasta padrao : $script:FixedPath" -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '  ------------------------------------------------------------' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '   [1]  Criptografar          (pasta padrao, recursivo)' -ForegroundColor White
        Write-Host '   [2]  Descriptografar        (pasta padrao, recursivo)' -ForegroundColor White
        Write-Host '   [3]  Criptografar            (informar caminho)' -ForegroundColor White
        Write-Host '   [4]  Descriptografar          (informar caminho)' -ForegroundColor White
        Write-Host ''
        Write-Host '   [0]  Sair' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '  ============================================================' -ForegroundColor Cyan
        Write-Host ''

        $choice = Read-Host '    Selecione uma opcao'

        if ($choice -in @('0', '1', '2', '3', '4')) {
            return $choice
        }

        Write-Host ''
        Write-Host '   Opcao invalida. Use os numeros de 0 a 4.' -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
}

function Show-RecursionMenu {
    <#
    .SYNOPSIS
        Exibe o submenu de recursao e retorna a escolha do usuario.
    .OUTPUTS
        [bool]  $true  — processar todos os subniveis recursivamente
        [bool]  $false — somente o nivel do caminho informado
        $null          — usuario escolheu Voltar ao menu principal
    #>
    while ($true) {
        Write-Host ''
        Write-Divider
        Write-Host '   Processar subpastas recursivamente?' -ForegroundColor White
        Write-Divider
        Write-Host ''
        Write-Host '   [1]  Sim  -  incluir todos os subniveis' -ForegroundColor White
        Write-Host '   [2]  Nao  -  somente o nivel do caminho informado' -ForegroundColor White
        Write-Host '   [0]  Voltar ao menu principal' -ForegroundColor DarkGray
        Write-Host ''

        $choice = Read-Host '    Selecione'

        switch ($choice) {
            '1' { return [bool]$true  }
            '2' { return [bool]$false }
            '0' { return $null        }
            default {
                Write-Host ''
                Write-Host '   Opcao invalida. Use 1, 2 ou 0.' -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            }
        }
    }
}

# =============================================================================
# FUNCOES DE OPERACAO
# =============================================================================

function Invoke-FixedPathOperation {
    <#
    .SYNOPSIS
        Executa uma operacao (encrypt ou decrypt) na pasta fixa configurada.
        Chamado por Invoke-EncryptFixedPath e Invoke-DecryptFixedPath.
    .PARAMETER Operation
        'encrypt' ou 'decrypt'.
    .PARAMETER OperationName
        Nome legivel exibido nos prompts e cabecalhos.
    #>
    param (
        [Parameter(Mandatory)]
        [ValidateSet('encrypt', 'decrypt')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$OperationName
    )

    Clear-Host
    Write-Header -Title "$OperationName  -  Pasta Padrao"
    Write-Host "   Pasta : $script:FixedPath" -ForegroundColor White
    Write-Host ''

    # Verificar se a pasta fixa existe antes de prosseguir
    if (-not (Test-Path -LiteralPath $script:FixedPath -PathType Container)) {
        Write-Host '  [ERRO] A pasta configurada nao existe:' -ForegroundColor Red
        Write-Host ''
        Write-Host "  $script:FixedPath" -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  Edite a variavel $script:FixedPath no inicio do arquivo vault.ps1.' -ForegroundColor Yellow
        Wait-KeyPress
        return
    }

    # Solicitar a chave com entrada mascarada
    $key = Get-EncryptionKey -OperationName $OperationName
    if ($null -eq $key) { return }

    # Executar vault.exe com recursao sempre habilitada para a pasta fixa
    Write-Host ''
    Write-Divider
    $exitCode = Invoke-VaultCommand -Path $script:FixedPath -Key $key -Operation $Operation -Recursive
    $key = $null

    Write-ResultPanel -ExitCode $exitCode
    Wait-KeyPress
}

function Invoke-EncryptFixedPath {
    <#
    .SYNOPSIS
        Criptografa a pasta fixa configurada no script, com recursao automatica.
    #>
    Invoke-FixedPathOperation -Operation 'encrypt' -OperationName 'Criptografar'
}

function Invoke-DecryptFixedPath {
    <#
    .SYNOPSIS
        Descriptografa a pasta fixa configurada no script, com recursao automatica.
    #>
    Invoke-FixedPathOperation -Operation 'decrypt' -OperationName 'Descriptografar'
}

function Invoke-CustomPathOperation {
    <#
    .SYNOPSIS
        Executa uma operacao em um caminho informado pelo usuario.
        Chamado por Invoke-EncryptCustomPath e Invoke-DecryptCustomPath.
    .PARAMETER Operation
        'encrypt' ou 'decrypt'.
    .PARAMETER OperationName
        Nome legivel exibido nos prompts e cabecalhos.
    #>
    param (
        [Parameter(Mandatory)]
        [ValidateSet('encrypt', 'decrypt')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$OperationName
    )

    Clear-Host
    Write-Header -Title "$OperationName  -  Informar Caminho"

    # Passo 1: Escolha de recursao
    $recursive = Show-RecursionMenu
    if ($null -eq $recursive) { return }   # Usuario escolheu [0] Voltar

    # Passo 2: Solicitar e validar o caminho
    $targetPath = Get-UserInputPath
    if ($null -eq $targetPath) { return }  # Usuario cancelou (entrada vazia)

    # Passo 3: Solicitar a chave
    $key = Get-EncryptionKey -OperationName $OperationName
    if ($null -eq $key) { return }

    # Passo 4: Executar vault.exe com ou sem recursao conforme escolha do usuario
    Write-Host ''
    Write-Divider
    $exitCode = Invoke-VaultCommand -Path $targetPath -Key $key -Operation $Operation -Recursive:$recursive
    $key = $null

    Write-ResultPanel -ExitCode $exitCode
    Wait-KeyPress
}

function Invoke-EncryptCustomPath {
    <#
    .SYNOPSIS
        Criptografa um arquivo ou pasta informado pelo usuario.
    #>
    Invoke-CustomPathOperation -Operation 'encrypt' -OperationName 'Criptografar'
}

function Invoke-DecryptCustomPath {
    <#
    .SYNOPSIS
        Descriptografa um arquivo ou pasta informado pelo usuario.
    #>
    Invoke-CustomPathOperation -Operation 'decrypt' -OperationName 'Descriptografar'
}

# =============================================================================
# PONTO DE ENTRADA
# =============================================================================

function Main {
    <#
    .SYNOPSIS
        Ponto de entrada principal do script.
        Valida o ambiente e inicia o loop do menu principal.
    #>

    # Verificar vault.exe antes de qualquer interacao com o usuario
    if (-not (Test-VaultExecutable)) {
        exit 1
    }

    # Loop principal: exibir menu e despachar para a funcao de operacao correta
    $running = $true
    while ($running) {
        $choice = Show-MainMenu

        switch ($choice) {
            '1' { Invoke-EncryptFixedPath  }
            '2' { Invoke-DecryptFixedPath  }
            '3' { Invoke-EncryptCustomPath }
            '4' { Invoke-DecryptCustomPath }
            '0' {
                Clear-Host
                Write-Host ''
                Write-Host '   VaultCrypt encerrado.' -ForegroundColor DarkGray
                Write-Host ''
                $running = $false
            }
        }
    }
}

# Iniciar
Main