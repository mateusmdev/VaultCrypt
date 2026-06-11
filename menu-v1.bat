@echo off
:: ===========================================================================
::
::  vault.bat  -  VaultCrypt Interface Interativa
::  Versao 1.0
::
::  Wrapper interativo para dist\vault.exe.
::  Abstrai flags e argumentos, expondo apenas o necessario ao usuario.
::
::  CONFIGURACAO RAPIDA
::  -------------------
::  Edite a variavel FIXED_PATH na secao "CONFIGURACOES" abaixo
::  para definir a pasta usada pelas opcoes 1 e 2.
::
::  REQUISITOS
::  ----------
::  - Windows 10 ou superior
::  - PowerShell 5.1+ (incluido no Windows 10 por padrao)
::  - dist\vault.exe presente no mesmo diretorio deste script
::
::  ESTRUTURA ESPERADA
::  ------------------
::  Projeto\
::  |-- vault.bat          <- este arquivo
::  +-- dist\
::      +-- vault.exe
::
::  LIMITACOES CONHECIDAS
::  ---------------------
::  - Chaves ou caminhos contendo o caractere "!" podem nao funcionar
::    corretamente (limitacao do Batch com expansao atrasada ativada).
::  - A chave e brevemente visivel no historico de processos do Windows
::    ao ser repassada para vault.exe (limitacao da propria ferramenta).
::
:: ===========================================================================

setlocal enabledelayedexpansion

:: ===========================================================================
:: CONFIGURACOES  -  EDITE AQUI
:: ===========================================================================

:: Caminho do executavel (relativo a este script, nao altere a referencia %~dp0)
set "VAULT_EXE=%~dp0dist\vault.exe"

:: Caminho fixo utilizado pelas opcoes 1 (Criptografar) e 2 (Descriptografar).
:: >>> Substitua pelo caminho completo da pasta que deseja proteger. <<<
:: Exemplo: set "FIXED_PATH=C:\Users\joao\Documents\Notas"
set "FIXED_PATH=%~dp0vault_data"

:: ===========================================================================
:: INICIALIZACAO
:: ===========================================================================

title VaultCrypt

:: Verificar a existencia do executavel antes de exibir qualquer menu.
:: Sem vault.exe nao ha nada a fazer - encerrar com mensagem clara.
if not exist "%VAULT_EXE%" (
    cls
    echo.
    echo  ============================================================
    echo   ERRO  -  Executavel nao encontrado
    echo  ============================================================
    echo.
    echo   vault.exe nao foi localizado em:
    echo.
    echo   %VAULT_EXE%
    echo.
    echo   Certifique-se de que a pasta dist\ existe e contem
    echo   o arquivo vault.exe, depois execute vault.bat novamente.
    echo.
    echo  ============================================================
    echo.
    pause
    exit /b 1
)

:: ===========================================================================
:: MENU PRINCIPAL
:: ===========================================================================

:menu
cls
echo.
echo  ============================================================
echo   VaultCrypt  -  Interface de Criptografia
echo  ============================================================
echo.
echo   Pasta padrao : !FIXED_PATH!
echo.
echo  ------------------------------------------------------------
echo.
echo    [1]  Criptografar          (pasta padrao, recursivo)
echo    [2]  Descriptografar       (pasta padrao, recursivo)
echo    [3]  Criptografar          (informar caminho)
echo    [4]  Descriptografar       (informar caminho)
echo.
echo    [0]  Sair
echo.
echo  ============================================================
echo.
set "OPT="
set /p "OPT=    Selecione uma opcao: "

:: Despachar para o bloco de execucao correto,
:: definindo _OP (flag da CLI) e _OPNAME (nome para exibicao).
if "!OPT!"=="1" ( set "_OP=encrypt" & set "_OPNAME=Criptografar"    & goto _op_fixo  )
if "!OPT!"=="2" ( set "_OP=decrypt" & set "_OPNAME=Descriptografar"  & goto _op_fixo  )
if "!OPT!"=="3" ( set "_OP=encrypt" & set "_OPNAME=Criptografar"    & goto _op_custom )
if "!OPT!"=="4" ( set "_OP=decrypt" & set "_OPNAME=Descriptografar"  & goto _op_custom )
if "!OPT!"=="0" goto _sair

:: Opcao invalida: avisar e retornar ao menu
echo.
echo    Opcao invalida. Use os numeros de 0 a 4.
timeout /t 2 /nobreak >nul
goto menu

:: ===========================================================================
:: BLOCO DE EXECUCAO  -  CAMINHO FIXO  (opcoes 1 e 2)
::
:: Compartilhado pelas duas opcoes. O comportamento (encrypt/decrypt)
:: e determinado pelas variaveis _OP e _OPNAME definidas no despacho acima.
:: Recursao e sempre habilitada para a pasta fixa.
:: ===========================================================================

:_op_fixo
cls
echo.
echo  ============================================================
echo   !_OPNAME!  -  Pasta Padrao
echo  ============================================================
echo.
echo   Pasta : !FIXED_PATH!
echo.

:: Verificar se a pasta fixa existe antes de prosseguir.
:: O operador "\" no final forca a verificacao de diretorio.
if not exist "!FIXED_PATH!\" (
    echo   [ERRO] A pasta configurada nao existe:
    echo.
    echo   !FIXED_PATH!
    echo.
    echo   Edite a variavel FIXED_PATH no inicio do arquivo vault.bat.
    echo.
    pause
    goto menu
)

:: Solicitar a chave com entrada mascarada
call :get_key "!_OPNAME!"

:: get_key retorna VAULT_KEY="" se a entrada foi vazia: cancelar e voltar
if "!VAULT_KEY!"=="" goto menu

:: Executar vault.exe
:: --!_OP!   expande para --encrypt ou --decrypt conforme a opcao escolhida
:: --recursive e sempre aplicado para a pasta fixa
echo.
echo  ------------------------------------------------------------
echo   Executando...
echo  ------------------------------------------------------------
echo.
"%VAULT_EXE%" --path "!FIXED_PATH!" --key "!VAULT_KEY!" --!_OP! --recursive

:: Capturar o codigo de retorno antes de qualquer outro comando
set "RES=!ERRORLEVEL!"

:: Limpar a chave da memoria imediatamente apos o uso
set "VAULT_KEY="

:: Exibir o resultado da operacao e aguardar confirmacao do usuario
call :show_result !RES!
goto menu

:: ===========================================================================
:: BLOCO DE EXECUCAO  -  CAMINHO INFORMADO  (opcoes 3 e 4)
::
:: Compartilhado pelas duas opcoes. Fluxo em tres passos:
:: (1) Submenu de recursao  (2) Solicitacao de caminho  (3) Solicitacao de chave
:: ===========================================================================

:_op_custom
cls
echo.
echo  ============================================================
echo   !_OPNAME!  -  Informar Caminho
echo  ============================================================

:: --- Passo 1: Submenu de recursao ---
call :ask_recursion

:: Se o usuario escolheu [0] Voltar, _BACK sera 1: retornar ao menu
if "!_BACK!"=="1" goto menu

:: --- Passo 2: Solicitar e validar o caminho ---
call :ask_path

:: Se o usuario cancelou (entrada vazia), _BACK sera 1: retornar ao menu
if "!_BACK!"=="1" goto menu

:: --- Passo 3: Solicitar a chave ---
call :get_key "!_OPNAME!"

if "!VAULT_KEY!"=="" goto menu

:: Executar vault.exe com ou sem --recursive conforme escolha do usuario
echo.
echo  ------------------------------------------------------------
echo   Executando...
echo  ------------------------------------------------------------
echo.
if "!USE_RECURSIVE!"=="1" (
    "%VAULT_EXE%" --path "!USER_PATH!" --key "!VAULT_KEY!" --!_OP! --recursive
) else (
    "%VAULT_EXE%" --path "!USER_PATH!" --key "!VAULT_KEY!" --!_OP!
)

set "RES=!ERRORLEVEL!"
set "VAULT_KEY="

call :show_result !RES!
goto menu

:: ===========================================================================
:: ENCERRAMENTO
:: ===========================================================================

:_sair
cls
echo.
echo   VaultCrypt encerrado.
echo.
endlocal
exit /b 0

:: ===========================================================================
:: SUBROTINAS
:: ===========================================================================

:: ---------------------------------------------------------------------------
:: :get_key  "<nome_da_operacao>"
::
:: Solicita a chave ao usuario com entrada mascarada (caracteres exibidos
:: como asteriscos), utilizando PowerShell como auxiliar.
::
:: Mecanismo:
::   1. Grava um script .ps1 temporario em %TEMP% com o codigo de leitura.
::      O arquivo temporario contem APENAS logica — nunca a chave em si.
::   2. Executa o script via PowerShell. O prompt e os asteriscos sao
::      exibidos diretamente no console pelo PowerShell (nao capturados).
::   3. O valor convertido (texto plano) e capturado via FOR /F do stdout.
::   4. O arquivo temporario e apagado imediatamente apos o uso.
::
:: Saida:
::   VAULT_KEY = valor digitado (ou "" se entrada vazia)
::
:: Observacao:
::   Se PowerShell nao estiver disponivel ou falhar, VAULT_KEY sera vazio
::   e a operacao sera cancelada com uma mensagem de aviso.
:: ---------------------------------------------------------------------------
:get_key
set "VAULT_KEY="

:: Gerar nome unico para o script temporario usando %RANDOM%
set "_PS=%TEMP%\vc_%RANDOM%.ps1"

:: Gravar o codigo PowerShell de leitura mascarada no arquivo temporario.
:: Dentro de blocos () do Batch, os parenteses devem ser escapados com ^.
(
    echo $s = Read-Host -AsSecureString -Prompt '  Chave de %~1'
    echo if ^($s.Length -gt 0^) {
    echo     $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR^($s^)
    echo     [Runtime.InteropServices.Marshal]::PtrToStringAuto^($b^)
    echo }
) > "%_PS%"

:: Executar o script e capturar apenas o stdout (o valor da chave).
:: 2>nul suprime mensagens de erro do PowerShell no console.
for /f "delims=" %%k in ('powershell -NoProfile -ExecutionPolicy Bypass -File "%_PS%" 2^>nul') do set "VAULT_KEY=%%k"

:: Apagar o script temporario imediatamente apos a captura
del "%_PS%" 2>nul
set "_PS="

echo.

:: Validar: chave vazia significa cancelamento da operacao
if "!VAULT_KEY!"=="" (
    echo   [AVISO] Nenhuma chave informada. Operacao cancelada.
    timeout /t 2 /nobreak >nul
)
goto :eof

:: ---------------------------------------------------------------------------
:: :ask_recursion
::
:: Exibe o submenu para escolha de recursao e aguarda uma opcao valida.
::
:: Saida:
::   USE_RECURSIVE = 1 (processar subpastas) ou 0 (somente o nivel informado)
::   _BACK         = 1 se o usuario escolheu [0] Voltar
:: ---------------------------------------------------------------------------
:ask_recursion
set "_BACK=0"
set "USE_RECURSIVE=0"

:_rec_loop
echo.
echo  ------------------------------------------------------------
echo   Processar subpastas recursivamente?
echo  ------------------------------------------------------------
echo.
echo    [1]  Sim  -  incluir todos os subniveis
echo    [2]  Nao  -  somente o nivel do caminho informado
echo    [0]  Voltar ao menu principal
echo.
set "RC="
set /p "RC=    Selecione: "

if "!RC!"=="1" ( set "USE_RECURSIVE=1" & goto :eof )
if "!RC!"=="2" ( set "USE_RECURSIVE=0" & goto :eof )
if "!RC!"=="0" ( set "_BACK=1"         & goto :eof )

echo.
echo    Opcao invalida. Use 1, 2 ou 0.
timeout /t 2 /nobreak >nul
goto _rec_loop

:: ---------------------------------------------------------------------------
:: :ask_path
::
:: Solicita o caminho do arquivo ou pasta ao usuario,
:: remove aspas externas inseridas ao arrastar para o terminal
:: e valida a existencia do caminho antes de retornar.
::
:: Saida:
::   USER_PATH = caminho validado
::   _BACK     = 1 se entrada vazia (usuario cancelou)
:: ---------------------------------------------------------------------------
:ask_path
set "USER_PATH="
set "_BACK=0"

:_path_loop
echo.
echo  ------------------------------------------------------------
echo   Informe o caminho do arquivo ou pasta:
echo  ------------------------------------------------------------
echo.
echo   Dica: voce pode arrastar o arquivo ou pasta para esta janela.
echo   Deixe em branco e pressione Enter para cancelar.
echo.
set /p "USER_PATH=    Caminho: "

:: Remover aspas externas que o Windows insere ao arrastar para o terminal
set "USER_PATH=!USER_PATH:"=!"

:: Verificar se o usuario cancelou (entrada vazia apos remocao de aspas)
if "!USER_PATH!"=="" (
    echo.
    echo   Operacao cancelada.
    set "_BACK=1"
    timeout /t 2 /nobreak >nul
    goto :eof
)

:: Verificar existencia do caminho como arquivo ou como pasta.
:: A variante com "\" final forca a verificacao exclusiva de diretorio.
set "_EX=0"
if exist "!USER_PATH!"  set "_EX=1"
if exist "!USER_PATH!\" set "_EX=1"

if "!_EX!"=="0" (
    echo.
    echo   [ERRO] Caminho nao encontrado:
    echo.
    echo   !USER_PATH!
    echo.
    echo   Verifique o caminho e tente novamente.
    set "_EX="
    set "USER_PATH="
    timeout /t 3 /nobreak >nul
    goto _path_loop
)

set "_EX="
goto :eof

:: ---------------------------------------------------------------------------
:: :show_result  <exit_code>
::
:: Exibe mensagem de conclusao com base no codigo de retorno do vault.exe.
:: Codigo 0 = sucesso. Qualquer outro valor = falha.
:: Sempre aguarda confirmacao do usuario antes de retornar.
:: ---------------------------------------------------------------------------
:show_result
echo.
echo  ============================================================
if "%~1"=="0" (
    echo   Operacao concluida com sucesso.
) else (
    echo   A operacao terminou com falha.
    echo.
    echo   Codigo de retorno : %~1
    echo   Consulte as mensagens acima para mais detalhes.
)
echo  ============================================================
echo.
pause
goto :eof