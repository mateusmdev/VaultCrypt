@echo off
:: ===========================================================================
::  vault.bat  -  Launcher para vault.ps1
::
::  Responsabilidade unica: localizar e executar vault.ps1 no mesmo diretorio.
::  Nenhuma logica adicional e implementada neste arquivo.
:: ===========================================================================
setlocal

:: Construir o caminho do script PowerShell usando %~dp0.
:: %~dp0 expande para o drive + caminho do diretorio do proprio .bat,
:: sempre com barra invertida no final (ex: C:\Projeto\), garantindo
:: funcionamento independente da unidade ou do local de instalacao.
set "PS_SCRIPT=%~dp0vault.ps1"

:: Verificar se vault.ps1 existe antes de tentar executa-lo.
:: Sem esta verificacao, o PowerShell exibiria uma mensagem de erro tecnica
:: pouco clara para o usuario final.
if not exist "%PS_SCRIPT%" (
    echo.
    echo  [ERRO] Arquivo nao encontrado:
    echo  %PS_SCRIPT%
    echo.
    echo  Certifique-se de que vault.ps1 esta no mesmo diretorio que vault.bat.
    echo.
    pause
    exit /b 1
)

:: Executar vault.ps1 via Windows PowerShell (powershell.exe = versao 5.1).
::
:: -NoLogo              Suprime o cabecalho de versao exibido ao iniciar o PS.
:: -NoProfile           Ignora o perfil pessoal do usuario ($PROFILE), evitando
::                      que customizacoes locais interfiram na execucao.
:: -ExecutionPolicy Bypass  Permite executar o script neste processo sem alterar
::                          a politica de execucao global do sistema. Nao requer
::                          privilegios de administrador.
:: -File                Indica que o proximo argumento e um script a executar,
::                      e nao um bloco de comandos inline.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"

:: Repassar o codigo de saida retornado pelo script PowerShell.
:: Permite que processos chamadores (agendadores, outros scripts) detectem
:: se a execucao foi encerrada com sucesso (0) ou com falha (diferente de 0).
exit /b %ERRORLEVEL%