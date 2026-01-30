<#
    Made by t3hc0nnect10n (c) 2026
    Version 1.0.0.0 - GUI Edition

    Для работы сценария требуется настроенная служба - Windows Remote Management (WinRM).
    https://learn.microsoft.com/en-us/windows/win32/winrm/portal

    Перед первым запуском может потребоваться установить политику выполнения PowerShell, например:
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    (при изменении политики для всей системы могут потребоваться права администратора).

    Сценарий предназначен для работы с серверной средой *ПО "1С:Предприятие".
    Взаимодействует с сервером, с каталогом Active Directory, осуществляет контроль
    пользовательского ввода и выполняет функции:

         0. Устанавливает подключение к серверу.
         1. Вывод информации о COM-объекте.
         2. Вывод информации о версиях платформы.
         3. Вывод информации о службе.
         4. Работа со службой:
            - запуск;
            - остановка;
            - перезапуск.
         5. Работа с COM-объектом:
            - регистрация;
            - отмена регистрации.
         6. Удаление активных сессий:
            - из выбранных баз (формируется лог);
            - все сессии на кластере (формируется лог).
         7. Удаление временных файлов.
         8. Удаление сервера и службы.
         9. Установка сервера и службы.

    *ПО - программное обеспечение.
#>

# Параметры
param(
    $LabelYaerAutor = (Get-Date).Year,
    $LabelVersAutor = "1.0.0.0",
    $Global:SetServer = $null,
    $Global:MainForm = $null,
    $Global:OutputTextBox = $null,
    $Global:ServerTextBox = $null,
    $Global:ProgressForm = $null,
    $Global:ProgressBar = $null,
    $Global:ProgressLabel = $null,
    $Global:CancelOperation = $false
)

# Загрузка необходимых сборок для Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# |========================================|
# |   Вспомогательные функции              |
# |========================================|
# |                                        |
# | Вывод и форматирование:                |
# | - Write-DebugWithTime                  |
# | - Write-OutputResults                  |
# | - Write-ToOutputColored                |
# | - Write-ToOutputColoredMulti           |
# | - Write-ToOutputSegments               |
# | - Write-ToOutput                       |
# | - Write-Host (переопределение для GUI) |
# |                                        |
# | Безопасность:                          |
# | - Encrypt-Password                     |
# | - Decrypt-Password                     |
# | - Test-WinRMPasswordInLogs             |
# |                                        |
# | GUI элементы:                          |
# | - Create-MainForm                      |
# | - Show-SelectionDialog                 |
# | - Show-InputDialog                     |
# | - Show-BasesCheckBoxDialog             |
# | - Show-BasesInputDialog                |
# | - Show-PasswordDialog                  |
# |                                        |
# | Прогресс-бары:                         |
# | - Show-ProgressBar                     |
# | - Update-ProgressBar                   |
# | - Hide-ProgressBar                     |
# | - Start-ProgressBarAnimation           |
# | - Stop-ProgressBarAnimation            |
# | - Start-AnimatedProgressBar            |
# | - Show-FolderDeletionProgressBar       |
# | - Update-FolderDeletionProgressBar     |
# | - Hide-FolderDeletionProgressBar       |
# |                                        |
# | Подключение и выполнение:              |
# | - Test-IsLocalServer                   |
# | - Connect-ToServer                     |
# | - Execute-Function                     |
# | - Execute-JobService1CWithGUI          |
# | - Execute-JobComObject1CWithGUI        |
# | - Execute-DisactivateSession1CWithGUI  |
# | - Execute-InstallServer1CWithGUI       |
# |                                        |
# | Проверка учетных данных:               |
# | - Test-DomainCredentials               |
# |                                        |
# |========================================|

# Функция для вывода результатов с обработкой маркеров [OK] и [ОШИБКА]
# Вспомогательная функция для форматирования DEBUG сообщений с датой и временем
function Write-DebugWithTime {
    param(
        [string]$Message,
        [string]$Color = "Cyan"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $debugMsg = "[DEBUG $timestamp] $Message|$Color"
    # Write-OutputResults -OutputLines @($debugMsg)  # DEBUG: закомментировано, чтобы не отображалось в GUI
}

# Функция вывода массива строк в GUI с разноцветным форматированием по маркерам ([ОШИБКА], [OK]) и указанному цвету
function Write-OutputResults {
    param([array]$OutputLines)
    
    foreach ($line in $OutputLines) {
        if (-not [string]::IsNullOrEmpty($line)) {
            # DEBUG: не отображать в GUI (код закомментирован по запросу, не удалять)
            if ($line -match '\[DEBUG') { continue }
            $parts = $line -split '\|', 2
            $text = $parts[0]
            $colorName = if ($parts.Length -gt 1) { $parts[1] } else { "White" }
            
            # Проверяем, содержит ли текст маркеры [ОШИБКА] или [OK]
            if ($text -match '\[ОШИБКА\]') {
                Write-ToOutputColored $text "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
            }
			elseif ($text -match '\[OK\]') {
				# Специальная обработка для сообщений с "Установлены" - выделяем и [OK] и "Установлены" зеленым
				if ($text -match 'Установлены') {
					Write-ToOutputColoredMulti $text @("[OK]", "Установлены") ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
				}
				# Специальная обработка для сообщений с "Удалено" в конце - выделяем и [OK] и "Удалено" зеленым
				elseif ($text -match '\[OK\]\s+(.+?)\s+Удалено') {
					# Используем прямой доступ к RichTextBox для вывода без переводов строк между частями
					try {
						if ($Global:OutputTextBox -ne $null -and -not $Global:OutputTextBox.IsDisposed) {
							$Global:OutputTextBox.SelectionStart = $Global:OutputTextBox.TextLength
							$Global:OutputTextBox.SelectionLength = 0
							
							# Выводим [OK] зеленым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
							$Global:OutputTextBox.AppendText("[OK] ")
							
							# Выводим текст между [OK] и "Удалено" белым
							$textBetween = $text -replace '\[OK\]\s+', '' -replace '\s+Удалено$', ''
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::White
							$Global:OutputTextBox.AppendText("$textBetween ")
							
							# Выводим "Удалено" зеленым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
							$Global:OutputTextBox.AppendText("Удалено")
							
							# Добавляем перевод строки и сбрасываем цвет
							$Global:OutputTextBox.AppendText("`r`n")
							$Global:OutputTextBox.SelectionColor = $Global:OutputTextBox.ForeColor
							$Global:OutputTextBox.ScrollToCaret()
							[System.Windows.Forms.Application]::DoEvents()
						}
					}
					catch {
						# Если ошибка, используем стандартный вывод
						Write-ToOutputColored $text "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
					}
				}
				# Специальная обработка для сообщений с "Удалена" в конце - выделяем и [OK] и "Удалена" зеленым
				elseif ($text -match '\[OK\]\s+(.+?)\s+Удалена') {
					# Используем прямой доступ к RichTextBox для вывода без переводов строк между частями
					try {
						if ($Global:OutputTextBox -ne $null -and -not $Global:OutputTextBox.IsDisposed) {
							$Global:OutputTextBox.SelectionStart = $Global:OutputTextBox.TextLength
							$Global:OutputTextBox.SelectionLength = 0
							
							# Выводим [OK] зеленым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
							$Global:OutputTextBox.AppendText("[OK] ")
							
							# Выводим текст между [OK] и "Удалена" белым
							$textBetween = $text -replace '\[OK\]\s+', '' -replace '\s+Удалена$', ''
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::White
							$Global:OutputTextBox.AppendText("$textBetween ")
							
							# Выводим "Удалена" зеленым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
							$Global:OutputTextBox.AppendText("Удалена")
							
							# Добавляем перевод строки и сбрасываем цвет
							$Global:OutputTextBox.AppendText("`r`n")
							$Global:OutputTextBox.SelectionColor = $Global:OutputTextBox.ForeColor
							$Global:OutputTextBox.ScrollToCaret()
							[System.Windows.Forms.Application]::DoEvents()
						}
					}
					catch {
						# Если ошибка, используем стандартный вывод
						Write-ToOutputColored $text "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
					}
				}
				# Специальная обработка для сообщений с "Установлено" в конце - выделяем и [OK] и "Установлено" зеленым
				elseif ($text -match '\[OK\]\s+(.+?)\s+Установлено') {
					# Используем прямой доступ к RichTextBox для вывода без переводов строк между частями
					try {
						if ($Global:OutputTextBox -ne $null -and -not $Global:OutputTextBox.IsDisposed) {
							$Global:OutputTextBox.SelectionStart = $Global:OutputTextBox.TextLength
							$Global:OutputTextBox.SelectionLength = 0
							
							# Выводим [OK] зеленым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
							$Global:OutputTextBox.AppendText("[OK] ")
							
							# Выводим текст между [OK] и "Установлено" белым
							$textBetween = $text -replace '\[OK\]\s+', '' -replace '\s+Установлено$', ''
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::White
							$Global:OutputTextBox.AppendText("$textBetween ")
							
							# Выводим "Установлено" зеленым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
							$Global:OutputTextBox.AppendText("Установлено")
							
							# Добавляем перевод строки и сбрасываем цвет
							$Global:OutputTextBox.AppendText("`r`n")
							$Global:OutputTextBox.SelectionColor = $Global:OutputTextBox.ForeColor
							$Global:OutputTextBox.ScrollToCaret()
							[System.Windows.Forms.Application]::DoEvents()
						}
					}
					catch {
						# Если ошибка, используем стандартный вывод
						Write-ToOutputColored $text "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
					}
				}
				# Специальная обработка для сообщений с "Остановлена" - выделяем [OK] зеленым, "Остановлена" красным
				elseif ($text -match '\[OK\]\s+(.+?)\s+Остановлена') {
					$serviceOrProductName = $matches[1]
					
					# Используем прямой доступ к RichTextBox для вывода без переводов строк между частями
					try {
						if ($Global:OutputTextBox -ne $null -and -not $Global:OutputTextBox.IsDisposed) {
							$Global:OutputTextBox.SelectionStart = $Global:OutputTextBox.TextLength
							$Global:OutputTextBox.SelectionLength = 0
							
							# Выводим [OK] зеленым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
							$Global:OutputTextBox.AppendText("[OK] ")
							
							# Выводим название службы/продукта белым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::White
							$Global:OutputTextBox.AppendText("$serviceOrProductName ")
							
							# Выводим "Остановлена" красным
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Red
							$Global:OutputTextBox.AppendText("Остановлена")
							
							# Добавляем перевод строки и сбрасываем цвет
							$Global:OutputTextBox.AppendText("`r`n")
							$Global:OutputTextBox.SelectionColor = $Global:OutputTextBox.ForeColor
							$Global:OutputTextBox.ScrollToCaret()
							[System.Windows.Forms.Application]::DoEvents()
						}
					}
					catch {
						# Если ошибка, используем стандартный вывод
						Write-ToOutputColored $text "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
					}
				}
				# Специальная обработка для сообщений с "Удалена", "Удален" - выделяем и [OK] и слово зеленым
				elseif ($text -match '\[OK\]\s+(.+?)\s+(Удалена|Удален)') {
					$serviceOrProductName = $matches[1]
					$actionWord = $matches[2]
					
					# Используем прямой доступ к RichTextBox для вывода без переводов строк между частями
					try {
						if ($Global:OutputTextBox -ne $null -and -not $Global:OutputTextBox.IsDisposed) {
							$Global:OutputTextBox.SelectionStart = $Global:OutputTextBox.TextLength
							$Global:OutputTextBox.SelectionLength = 0
							
							# Выводим [OK] зеленым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
							$Global:OutputTextBox.AppendText("[OK] ")
							
							# Выводим название службы/продукта белым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::White
							$Global:OutputTextBox.AppendText("$serviceOrProductName ")
							
							# Выводим слово действия (Удалена/Удален) зеленым
							$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
							$Global:OutputTextBox.AppendText("$actionWord")
							
							# Добавляем перевод строки и сбрасываем цвет
							$Global:OutputTextBox.AppendText("`r`n")
							$Global:OutputTextBox.SelectionColor = $Global:OutputTextBox.ForeColor
							$Global:OutputTextBox.ScrollToCaret()
							[System.Windows.Forms.Application]::DoEvents()
						}
					}
					catch {
						# Если ошибка, используем стандартный вывод
						Write-ToOutputColored $text "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
					}
				}
				else {
					Write-ToOutputColored $text "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
				}
			}
            else {
                # Для остальных случаев используем стандартный вывод
                $color = switch ($colorName) {
                    "Green" { [System.Drawing.Color]::Green }
                    "Red" { [System.Drawing.Color]::Red }
                    "Yellow" { [System.Drawing.Color]::Yellow }
                    "Cyan" { [System.Drawing.Color]::Cyan }
                    "Gray" { [System.Drawing.Color]::Gray }
                    "Magenta" { [System.Drawing.Color]::Magenta }
                    default { [System.Drawing.Color]::White }
                }
                
                Write-ToOutput $text $color
            }
        }
    }
}

# Функция для разноцветного вывода текста (например, [OK] зеленым, остальное белым)
function Write-ToOutputColored {
    param(
        [string]$Text,
        [string]$ColoredMarker,  # Маркер, который нужно выделить цветом (например, "[OK]" или "[ОШИБКА]")
        [System.Drawing.Color]$MarkerColor,  # Цвет маркера
        [System.Drawing.Color]$DefaultColor = [System.Drawing.Color]::White  # Цвет остального текста
    )
    
    # Безопасная проверка и использование GUI элемента
    try {
        if ($Global:OutputTextBox -ne $null) {
            $isDisposed = $false
            try {
                $isDisposed = $Global:OutputTextBox.IsDisposed
            }
            catch {
                $isDisposed = $true
            }
            
            if (-not $isDisposed) {
                $Global:OutputTextBox.SelectionStart = $Global:OutputTextBox.TextLength
                $Global:OutputTextBox.SelectionLength = 0
                
                # Проверяем, содержит ли текст маркер
                if ($Text -match [regex]::Escape($ColoredMarker)) {
                    # Разделяем текст на части до и после маркера
                    $parts = $Text -split ([regex]::Escape($ColoredMarker), 2)
                    
                    # Выводим текст до маркера белым цветом
                    if ($parts[0] -ne "") {
                        $Global:OutputTextBox.SelectionColor = $DefaultColor
                        $Global:OutputTextBox.AppendText($parts[0])
                    }
                    
                    # Выводим маркер цветным
                    $Global:OutputTextBox.SelectionColor = $MarkerColor
                    $Global:OutputTextBox.AppendText($ColoredMarker)
                    
                    # Выводим текст после маркера белым цветом
                    if ($parts.Count -gt 1 -and $parts[1] -ne "") {
                        $Global:OutputTextBox.SelectionColor = $DefaultColor
                        $Global:OutputTextBox.AppendText($parts[1])
                    }
                } else {
                    # Если маркера нет, выводим весь текст цветом по умолчанию
                    $Global:OutputTextBox.SelectionColor = $DefaultColor
                    $Global:OutputTextBox.AppendText($Text)
                }
                
                # Добавляем перевод строки и сбрасываем цвет
                $Global:OutputTextBox.AppendText("`r`n")
                $Global:OutputTextBox.SelectionColor = $Global:OutputTextBox.ForeColor
                $Global:OutputTextBox.ScrollToCaret()
                [System.Windows.Forms.Application]::DoEvents()
                return
            }
        }
    }
    catch {
        # Если произошла ошибка, выводим в консоль
        Write-Host $Text
    }
}

# Функция для разноцветного вывода текста с несколькими маркерами (например, [OK] и "Установлены" зеленым)
function Write-ToOutputColoredMulti {
    param(
        [string]$Text,
        [string[]]$ColoredMarkers,  # Массив маркеров, которые нужно выделить цветом
        [System.Drawing.Color]$MarkerColor,  # Цвет маркеров
        [System.Drawing.Color]$DefaultColor = [System.Drawing.Color]::White  # Цвет остального текста
    )
    
    # Безопасная проверка и использование GUI элемента
    try {
        if ($Global:OutputTextBox -ne $null) {
            $isDisposed = $false
            try {
                $isDisposed = $Global:OutputTextBox.IsDisposed
            }
            catch {
                $isDisposed = $true
            }
            
            if (-not $isDisposed) {
                $Global:OutputTextBox.SelectionStart = $Global:OutputTextBox.TextLength
                $Global:OutputTextBox.SelectionLength = 0
                
                # Разбиваем текст на части по маркерам
                $remainingText = $Text
                $positions = @()
                
                # Находим все позиции маркеров в тексте
                foreach ($marker in $ColoredMarkers) {
                    $escapedMarker = [regex]::Escape($marker)
                    $markerMatches = [regex]::Matches($remainingText, $escapedMarker)
                    foreach ($match in $markerMatches) {
                        $positions += [PSCustomObject]@{
                            Index = $match.Index
                            Length = $match.Length
                            Text = $match.Value
                        }
                    }
                }
                
                # Сортируем позиции по индексу
                $positions = $positions | Sort-Object Index
                
                # Выводим текст по частям
                $currentIndex = 0
                foreach ($pos in $positions) {
                    # Выводим текст до маркера белым цветом
                    if ($pos.Index -gt $currentIndex) {
                        $Global:OutputTextBox.SelectionColor = $DefaultColor
                        $Global:OutputTextBox.AppendText($remainingText.Substring($currentIndex, $pos.Index - $currentIndex))
                    }
                    
                    # Выводим маркер зеленым цветом
                    $Global:OutputTextBox.SelectionColor = $MarkerColor
                    $Global:OutputTextBox.AppendText($pos.Text)
                    
                    $currentIndex = $pos.Index + $pos.Length
                }
                
                # Выводим оставшийся текст белым цветом
                if ($currentIndex -lt $remainingText.Length) {
                    $Global:OutputTextBox.SelectionColor = $DefaultColor
                    $Global:OutputTextBox.AppendText($remainingText.Substring($currentIndex))
                }
                
                # Добавляем перевод строки и сбрасываем цвет
                $Global:OutputTextBox.AppendText("`r`n")
                $Global:OutputTextBox.SelectionColor = $Global:OutputTextBox.ForeColor
                $Global:OutputTextBox.ScrollToCaret()
                [System.Windows.Forms.Application]::DoEvents()
                return
            }
        }
    }
    catch {
        # Если произошла ошибка, выводим в консоль
        Write-Host $Text
    }
}

# Функция для шифрования пароля с использованием AES-256
function Encrypt-Password {
    param(
        [string]$Password,
        [ref]$EncryptionKey,
        [ref]$IV
    )
    
    try {
        # Генерируем случайный ключ и IV для AES-256
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.KeySize = 256
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateKey()
        $aes.GenerateIV()
        
        # Сохраняем ключ и IV для передачи на удаленный сервер
        $EncryptionKey.Value = $aes.Key
        $IV.Value = $aes.IV
        
        # Шифруем пароль
        $encryptor = $aes.CreateEncryptor()
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
        $encryptedBytes = $encryptor.TransformFinalBlock($passwordBytes, 0, $passwordBytes.Length)
        
        # Очищаем память
        $passwordBytes = $null
        $encryptor.Dispose()
        $aes.Dispose()
        
        # Возвращаем зашифрованные данные в Base64
        return [Convert]::ToBase64String($encryptedBytes)
    }
    catch {
        throw "Ошибка при шифровании пароля: $($_.Exception.Message)"
    }
}

# Функция для расшифровки пароля с использованием AES-256
function Decrypt-Password {
    param(
        [string]$EncryptedPasswordBase64,
        [byte[]]$EncryptionKey,
        [byte[]]$IV
    )
    
    try {
        # Создаем объект AES для расшифровки
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.KeySize = 256
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $EncryptionKey
        $aes.IV = $IV
        
        # Расшифровываем пароль
        $decryptor = $aes.CreateDecryptor()
        $encryptedBytes = [Convert]::FromBase64String($EncryptedPasswordBase64)
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
        $decryptedPassword = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        
        # Очищаем память
        $encryptedBytes = $null
        $decryptedBytes = $null
        $decryptor.Dispose()
        $aes.Dispose()
        
        return $decryptedPassword
    }
    catch {
        throw "Ошибка при расшифровке пароля: $($_.Exception.Message)"
    }
}

# Функция для проверки логов WinRM на наличие паролей после установки службы
# Работает как локально, так и на удаленном сервере через Invoke-Command
function Test-WinRMPasswordInLogs {
    param(
        [string]$Server = $null,  # Имя сервера для удаленной проверки (если null - проверка локальная)
        [int]$CheckPeriodMinutes = 15  # Период проверки в минутах (по умолчанию последние 15 минут)
    )
    
    try {
        # Определяем текст для вывода: имя удаленного сервера или локального
        if ($null -ne $Server -and $Server.Trim() -ne "") {
            $serverText = "на сервере $Server "
        }
        else {
            $localServerName = $env:COMPUTERNAME
            $serverText = "на сервере $localServerName "
        }
        Write-ToOutput "Проверка логов WinRM $serverText на наличие паролей за последние $CheckPeriodMinutes минут..." ([System.Drawing.Color]::Yellow)
        
        $startTime = (Get-Date).AddMinutes(-$CheckPeriodMinutes)
        $endTime = Get-Date
        
        # Определяем, выполнять проверку локально или на удаленном сервере
        if ($null -ne $Server -and $Server.Trim() -ne "") {
            # Проверка на удаленном сервере через Invoke-Command
            $checkResult = Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $startTime, $endTime -ScriptBlock {
                param([DateTime]$StartTime, [DateTime]$EndTime)
                
                $result = @{
                    Success = $false
                    Message = ""
                    EventsCount = 0
                    CheckedEvents = 0
                    RealPasswordFound = $false
                    PasswordEventTime = $null
                    PasswordEventId = $null
                }
                
                try {
                    # Проверяем доступность журнала событий WinRM Operational
                    $winrmLogExists = Get-WinEvent -ListLog "Microsoft-Windows-WinRM/Operational" -ErrorAction SilentlyContinue
                    if ($null -eq $winrmLogExists) {
                        $result.Message = "Журнал событий WinRM Operational недоступен"
                        return $result
                    }
                    
                    # Получаем события WinRM за указанный период
                    $winrmEvents = Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -ErrorAction SilentlyContinue | 
                        Where-Object { $_.TimeCreated -ge $StartTime -and $_.TimeCreated -le $EndTime }
                    
                    if ($null -eq $winrmEvents -or $winrmEvents.Count -eq 0) {
                        $result.Success = $true
                        $result.Message = "Событий WinRM не найдено"
                        return $result
                    }
                    
                    $result.EventsCount = $winrmEvents.Count
                    
                    # Ключевые слова, которые могут указывать на пароль
                    $passwordKeywords = @("password", "пароль", "pwd", "pass", "sc.exe config", "obj=", "password=")
                    
                    # Проверяем события на наличие реальных паролей (не переменных PowerShell)
                    foreach ($event in $winrmEvents | Select-Object -First 100) {
                        $result.CheckedEvents++
                        $message = $event.Message
                        $toXml = $event | Format-List -Property * | Out-String
                        
                        foreach ($keyword in $passwordKeywords) {
                            if ($message -match $keyword -or $toXml -match $keyword) {
                                # Проверяем, что это не просто код PowerShell с переменными
                                if ($message -notmatch '\$[a-zA-Z_][a-zA-Z0-9_]*|\$Input|\$Output|\$service|\$user|\$password|\$Name|\$Path|\$ImagePath') {
                                    # Проверка password= с реальным значением
                                    if ($message -match "password\s*=\s*([^\s]+)") {
                                        $passwordValue = $matches[1]
                                        if ($passwordValue -notmatch '^\$[a-zA-Z_][a-zA-Z0-9_]*$' -and 
                                            $passwordValue.Length -ge 4 -and
                                            $passwordValue -notmatch '\$Input|\$Output|\$service|\$user|\$password') {
                                            $result.RealPasswordFound = $true
                                            $result.PasswordEventTime = $event.TimeCreated
                                            $result.PasswordEventId = $event.Id
                                            return $result
                                        }
                                    }
                                    # Проверка sc.exe config с password=
                                    elseif ($message -match "sc\.exe\s+config.*password\s*=\s*([^\s]+)") {
                                        $passwordValue = $matches[1]
                                        if ($passwordValue -notmatch '^\$[a-zA-Z_][a-zA-Z0-9_]*$' -and 
                                            $passwordValue.Length -ge 4 -and
                                            $passwordValue -notmatch '\$Input|\$Output|\$service|\$user|\$password') {
                                            $result.RealPasswordFound = $true
                                            $result.PasswordEventTime = $event.TimeCreated
                                            $result.PasswordEventId = $event.Id
                                            return $result
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    $result.Success = $true
                    $result.Message = "Реальные пароли не обнаружены"
                    return $result
                }
                catch {
                    $result.Message = "Ошибка при проверке: $($_.Exception.Message)"
                    return $result
                }
            }
            
            # Обрабатываем результат удаленной проверки
            if ($checkResult.Success -and -not $checkResult.RealPasswordFound) {
                if ($checkResult.EventsCount -eq 0) {
                    Write-ToOutputColored "[OK] Событий WinRM за последние $CheckPeriodMinutes минут не найдено. Пароль не попал в логи." "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
                }
                else {
                    Write-ToOutputColored "[OK] Проверено событий: $($checkResult.CheckedEvents). Реальные пароли в логах WinRM не обнаружены (переменные PowerShell отфильтрованы)." "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
                }
                return $true
            }
            elseif ($checkResult.RealPasswordFound) {
                Write-ToOutputColored "[ОШИБКА] ВНИМАНИЕ: В логах WinRM на сервере $Server обнаружен возможный реальный пароль!" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
                Write-ToOutput "Время события: $($checkResult.PasswordEventTime)" ([System.Drawing.Color]::Red)
                Write-ToOutput "ID события: $($checkResult.PasswordEventId)" ([System.Drawing.Color]::Red)
                Write-ToOutput "Проверьте событие вручную на сервере $Server через Event Viewer: eventvwr.msc -> Applications and Services Logs -> Microsoft -> Windows -> WinRM -> Operational" ([System.Drawing.Color]::Yellow)
                return $false
            }
            else {
                Write-ToOutputColored "[ПРЕДУПРЕЖДЕНИЕ] $($checkResult.Message)" "[ПРЕДУПРЕЖДЕНИЕ]" ([System.Drawing.Color]::Yellow) ([System.Drawing.Color]::White)
                return $false
            }
        }
        else {
            # Локальная проверка (оригинальный код)
            # Проверяем доступность журнала событий WinRM Operational
            $winrmLogExists = Get-WinEvent -ListLog "Microsoft-Windows-WinRM/Operational" -ErrorAction SilentlyContinue
            if ($null -eq $winrmLogExists) {
                Write-ToOutputColored "[ПРЕДУПРЕЖДЕНИЕ] Журнал событий WinRM Operational недоступен. Проверка логов невозможна." "[ПРЕДУПРЕЖДЕНИЕ]" ([System.Drawing.Color]::Yellow) ([System.Drawing.Color]::White)
                return $false
            }
            
            # Получаем события WinRM за указанный период
            $winrmEvents = Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -ErrorAction SilentlyContinue | 
                Where-Object { $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime }
            
            if ($null -eq $winrmEvents -or $winrmEvents.Count -eq 0) {
                Write-ToOutputColored "[OK] Событий WinRM за последние $CheckPeriodMinutes минут не найдено. Пароль не попал в логи." "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
                return $true
            }
            
            Write-ToOutput "Найдено событий WinRM за последние $CheckPeriodMinutes минут: $($winrmEvents.Count)" ([System.Drawing.Color]::White)
            
            # Ключевые слова, которые могут указывать на пароль
            $passwordKeywords = @("password", "пароль", "pwd", "pass", "sc.exe config", "obj=", "password=")
            $realPasswordFound = $false
            $checkedEvents = 0
            
            # Проверяем события на наличие реальных паролей (не переменных PowerShell)
            foreach ($event in $winrmEvents | Select-Object -First 100) {
                $checkedEvents++
                $message = $event.Message
                $toXml = $event | Format-List -Property * | Out-String
                
                foreach ($keyword in $passwordKeywords) {
                    if ($message -match $keyword -or $toXml -match $keyword) {
                        # Проверяем, что это не просто код PowerShell с переменными
                        if ($message -notmatch '\$[a-zA-Z_][a-zA-Z0-9_]*|\$Input|\$Output|\$service|\$user|\$password|\$Name|\$Path|\$ImagePath') {
                            # Проверка password= с реальным значением
                            if ($message -match "password\s*=\s*([^\s]+)") {
                                $passwordValue = $matches[1]
                                if ($passwordValue -notmatch '^\$[a-zA-Z_][a-zA-Z0-9_]*$' -and 
                                    $passwordValue.Length -ge 4 -and
                                    $passwordValue -notmatch '\$Input|\$Output|\$service|\$user|\$password') {
                                    $realPasswordFound = $true
                                    Write-ToOutputColored "[ОШИБКА] ВНИМАНИЕ: В логах WinRM обнаружен возможный реальный пароль!" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
                                    Write-ToOutput "Время события: $($event.TimeCreated)" ([System.Drawing.Color]::Red)
                                    Write-ToOutput "ID события: $($event.Id)" ([System.Drawing.Color]::Red)
                                    Write-ToOutput "Проверьте событие вручную через Event Viewer: eventvwr.msc -> Applications and Services Logs -> Microsoft -> Windows -> WinRM -> Operational" ([System.Drawing.Color]::Yellow)
                                    break
                                }
                            }
                            # Проверка sc.exe config с password=
                            elseif ($message -match "sc\.exe\s+config.*password\s*=\s*([^\s]+)") {
                                $passwordValue = $matches[1]
                                if ($passwordValue -notmatch '^\$[a-zA-Z_][a-zA-Z0-9_]*$' -and 
                                    $passwordValue.Length -ge 4 -and
                                    $passwordValue -notmatch '\$Input|\$Output|\$service|\$user|\$password') {
                                    $realPasswordFound = $true
                                    Write-ToOutputColored "[ОШИБКА] ВНИМАНИЕ: В логах WinRM обнаружен возможный реальный пароль в команде sc.exe config!" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
                                    Write-ToOutput "Время события: $($event.TimeCreated)" ([System.Drawing.Color]::Red)
                                    Write-ToOutput "ID события: $($event.Id)" ([System.Drawing.Color]::Red)
                                    Write-ToOutput "Проверьте событие вручную через Event Viewer" ([System.Drawing.Color]::Yellow)
                                    break
                                }
                            }
                        }
                    }
                }
                
                if ($realPasswordFound) {
                    break
                }
            }
            
            if (-not $realPasswordFound) {
                Write-ToOutputColored "[OK] Проверено событий: $checkedEvents. Реальные пароли в логах WinRM не обнаружены (переменные PowerShell отфильтрованы)." "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
                return $true
            }
            else {
                return $false
            }
        }
    }
    catch {
        Write-ToOutputColored "[ПРЕДУПРЕЖДЕНИЕ] Ошибка при проверке логов WinRM: $($_.Exception.Message)" "[ПРЕДУПРЕЖДЕНИЕ]" ([System.Drawing.Color]::Yellow) ([System.Drawing.Color]::White)
        return $false
    }
}

# Функция для вывода текста в текстовое поле
function Write-ToOutput {
    param([string]$Text, [System.Drawing.Color]$Color = [System.Drawing.Color]::Black)
    
    # Безопасная проверка и использование GUI элемента
    try {
        # Проверка что элемент существует и не уничтожен
        if ($Global:OutputTextBox -ne $null) {
            # Проверка IsDisposed также обернута в try-catch, так как обращение к свойству уничтоженного объекта может вызвать исключение
            $isDisposed = $false
            try {
                $isDisposed = $Global:OutputTextBox.IsDisposed
            }
            catch {
                $isDisposed = $true
            }
            
            if (-not $isDisposed) {
                $Global:OutputTextBox.SelectionStart = $Global:OutputTextBox.TextLength
                $Global:OutputTextBox.SelectionLength = 0
                $Global:OutputTextBox.SelectionColor = $Color
                $Global:OutputTextBox.AppendText($Text + "`r`n")
                $Global:OutputTextBox.SelectionColor = $Global:OutputTextBox.ForeColor
                $Global:OutputTextBox.ScrollToCaret()
                [System.Windows.Forms.Application]::DoEvents()
                return
            }
        }
    }
    catch {
        # Если произошла любая ошибка при работе с GUI, выводим в консоль
    }
    
    # Если GUI элемент не создан или произошла ошибка, выводим в консоль
    Write-Host $Text -ForegroundColor $Color.Name
}

# Функция вывода нескольких сегментов разным цветом в одну строку (завершается переводом строки)
function Write-ToOutputSegments {
    param([array]$Segments)
    try {
        if ($null -eq $Global:OutputTextBox) { return }
        $isDisposed = $false
        try { $isDisposed = $Global:OutputTextBox.IsDisposed } catch { $isDisposed = $true }
        if ($isDisposed) { return }
        $Global:OutputTextBox.SelectionStart = $Global:OutputTextBox.TextLength
        $Global:OutputTextBox.SelectionLength = 0
        foreach ($seg in $Segments) {
            $Global:OutputTextBox.SelectionColor = $seg.Color
            $Global:OutputTextBox.AppendText($seg.Text)
        }
        $Global:OutputTextBox.AppendText("`r`n")
        $Global:OutputTextBox.SelectionColor = $Global:OutputTextBox.ForeColor
        $Global:OutputTextBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    } catch { }
}

# Функция создания главной формы
function Create-MainForm {
    # Создание главной формы
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "GUI Edition"
    
    # Получаем размер рабочей области экрана для автоматического определения размера монитора
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen
    $workingArea = $screen.WorkingArea
    
    # Устанавливаем минимальный размер формы
    $form.MinimumSize = New-Object System.Drawing.Size(900, 700)
    
    # Устанавливаем начальный размер формы равным минимальному размеру
    # Пользователь сможет изменить размер окна вручную
    $form.Size = New-Object System.Drawing.Size(1300, 700)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "Sizable"
    $form.MaximizeBox = $true
    $form.MinimizeBox = $true
    
    # Окно открывается в нормальном размере (не максимизировано), но пользователь может изменить размер
    $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    
    # Окно открывается поверх всех других окон
    $form.TopMost = $true
    
    # Заголовок
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "1C: Enterprise 8 - Automation Tool"
    $headerLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 14, [System.Drawing.FontStyle]::Bold)
    $headerLabel.Location = New-Object System.Drawing.Point(20, 10)
    $headerLabel.Size = New-Object System.Drawing.Size(850, 30)
    $headerLabel.ForeColor = [System.Drawing.Color]::DarkMagenta
    $headerLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $form.Controls.Add($headerLabel)
    
    # Информация о версии и авторе
    $versionLabel = New-Object System.Windows.Forms.Label
    $versionLabel.Text = "Made by t3hc0nnect10n (c) $($LabelYaerAutor) | Version $($LabelVersAutor)"
    $versionLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 8)
    $versionLabel.Location = New-Object System.Drawing.Point(20, 40)
    $versionLabel.Size = New-Object System.Drawing.Size(850, 20)
    $versionLabel.ForeColor = [System.Drawing.Color]::Gray
    $versionLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $form.Controls.Add($versionLabel)
    
    # Поле для ввода сервера
    $serverLabel = New-Object System.Windows.Forms.Label
    $serverLabel.Text = "Сервер:"
    $serverLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 8)
    $serverLabel.Location = New-Object System.Drawing.Point(20, 70)
    $serverLabel.Size = New-Object System.Drawing.Size(50, 20)
    $serverLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $form.Controls.Add($serverLabel)
    
    $Global:ServerTextBox = New-Object System.Windows.Forms.TextBox
    $Global:ServerTextBox.Location = New-Object System.Drawing.Point(70, 68)
    $Global:ServerTextBox.Size = New-Object System.Drawing.Size(220, 23)
    $Global:ServerTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $form.Controls.Add($Global:ServerTextBox)
    
    $connectButton = New-Object System.Windows.Forms.Button
    $connectButton.Text = "Подключиться"
    $connectButton.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $connectButton.Location = New-Object System.Drawing.Point(300, 67)
    $connectButton.Size = New-Object System.Drawing.Size(120, 23)
    $connectButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $connectButton.Add_Click({
        Connect-ToServer
    })
    $form.Controls.Add($connectButton)
    
    # Устанавливаем кнопку подключения как AcceptButton формы
    # Это стандартный механизм Windows Forms для обработки Enter
    # Когда поле ввода сервера в фокусе и нажимается Enter, автоматически активируется эта кнопка
    $form.AcceptButton = $connectButton
    
    # Дополнительный обработчик нажатия Enter в поле ввода сервера
    # Используем KeyPress для гарантированной обработки Enter
    $Global:ServerTextBox.Add_KeyPress({
        if ($_.KeyChar -eq [char]13) {  # 13 - это код клавиши Enter
            $_.Handled = $true  # Предотвращаем стандартную обработку Enter (звуковой сигнал)
            # Вызываем функцию подключения напрямую
            Connect-ToServer
        }
    })
    
    $serverStatusLabel = New-Object System.Windows.Forms.Label
    $serverStatusLabel.Text = "Не подключено"
    $serverStatusLabel.Location = New-Object System.Drawing.Point(450, 70)
    $serverStatusLabel.Size = New-Object System.Drawing.Size(300, 20)
    $serverStatusLabel.ForeColor = [System.Drawing.Color]::Red
    $serverStatusLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
    $serverStatusLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $form.Controls.Add($serverStatusLabel)
        
    # Кнопки функций
    $yPos = 100
    $buttonWidth = 400
    $buttonHeight = 30
    $buttonSpacing = 35
    
    # Параметры черного окна (RichTextBox) - можно менять в одном месте
    $outputTextBoxHeightOffset = 180  # Отступ для вычисления высоты черного окна (верхний отступ + место для кнопок)
    $outputTextBoxWidthOffset = 470  # Отступ для вычисления ширины черного окна (левая панель с кнопками + отступы)
    $outputTextBoxX = 450  # Горизонтальная позиция черного окна (можно менять в одном месте)
    $outputTextBoxY = 100  # Вертикальная позиция черного окна (можно менять в одном месте)
    
    # Функция 1
    $btn1 = New-Object System.Windows.Forms.Button
    $btn1.Text = "Информация о COM-объекте"
    $btn1.Location = New-Object System.Drawing.Point(20, $yPos)
    $btn1.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $btn1.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $btn1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $btn1.Add_Click({ Execute-Function -FunctionNumber 1 })
    $form.Controls.Add($btn1)
    
    # Функция 2
    $yPos += $buttonSpacing
    $btn2 = New-Object System.Windows.Forms.Button
    $btn2.Text = "Информация о версиях платформы"
    $btn2.Location = New-Object System.Drawing.Point(20, $yPos)
    $btn2.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $btn2.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $btn2.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $btn2.Add_Click({ Execute-Function -FunctionNumber 2 })
    $form.Controls.Add($btn2)
    
    # Функция 3
    $yPos += $buttonSpacing
    $btn3 = New-Object System.Windows.Forms.Button
    $btn3.Text = "Информация о службе"
    $btn3.Location = New-Object System.Drawing.Point(20, $yPos)
    $btn3.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $btn3.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $btn3.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $btn3.Add_Click({ Execute-Function -FunctionNumber 3 })
    $form.Controls.Add($btn3)
    
    # Функция 4
    $yPos += $buttonSpacing
    $btn4 = New-Object System.Windows.Forms.Button
    $btn4.Text = "Работа со службой"
    $btn4.Location = New-Object System.Drawing.Point(20, $yPos)
    $btn4.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $btn4.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $btn4.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $btn4.Add_Click({ Execute-Function -FunctionNumber 4 })
    $form.Controls.Add($btn4)
    
    # Функция 5
    $yPos += $buttonSpacing
    $btn5 = New-Object System.Windows.Forms.Button
    $btn5.Text = "Работа с COM-объектом"
    $btn5.Location = New-Object System.Drawing.Point(20, $yPos)
    $btn5.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $btn5.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $btn5.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $btn5.Add_Click({ Execute-Function -FunctionNumber 5 })
    $form.Controls.Add($btn5)
    
    # Функция 6
    $yPos += $buttonSpacing
    $btn6 = New-Object System.Windows.Forms.Button
    $btn6.Text = "Удаление активных сессий"
    $btn6.Location = New-Object System.Drawing.Point(20, $yPos)
    $btn6.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $btn6.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $btn6.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $btn6.Add_Click({ Execute-Function -FunctionNumber 6 })
    $form.Controls.Add($btn6)
    
    # Функция 7
    $yPos += $buttonSpacing
    $btn7 = New-Object System.Windows.Forms.Button
    $btn7.Text = "Удаление временных файлов"
    $btn7.Location = New-Object System.Drawing.Point(20, $yPos)
    $btn7.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $btn7.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $btn7.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $btn7.Add_Click({ Execute-Function -FunctionNumber 7 })
    $form.Controls.Add($btn7)
    
    # Функция 8
    $yPos += $buttonSpacing
    $btn8 = New-Object System.Windows.Forms.Button
    $btn8.Text = "Удаление сервера"
    $btn8.Location = New-Object System.Drawing.Point(20, $yPos)
    $btn8.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $btn8.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $btn8.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $btn8.Add_Click({ Execute-Function -FunctionNumber 8 })
    $form.Controls.Add($btn8)
    
    # Функция 9
    $yPos += $buttonSpacing
    $btn9 = New-Object System.Windows.Forms.Button
    $btn9.Text = "Установка сервера"
    $btn9.Location = New-Object System.Drawing.Point(20, $yPos)
    $btn9.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $btn9.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $btn9.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $btn9.Add_Click({ Execute-Function -FunctionNumber 9 })
    $form.Controls.Add($btn9)
    
    # Область вывода результатов
    # Позиционируем метку относительно RichTextBox - она будет автоматически перемещаться при изменении размера окна
    #$outputLabel = New-Object System.Windows.Forms.Label
    #$outputLabel.Text = "Вывод результатов"
    #$outputLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10, [System.Drawing.FontStyle]::Bold)
    #$outputLabel.Location = New-Object System.Drawing.Point(450, 125)
    #$outputLabel.Size = New-Object System.Drawing.Size(200, 20)
    # НЕ используем Anchor - позиция полностью контролируется обработчиком Resize для согласованности с RichTextBox
    #$form.Controls.Add($outputLabel)
    
    # RichTextBox для вывода - будет растягиваться автоматически
    $Global:OutputTextBox = New-Object System.Windows.Forms.RichTextBox
    # Начальная позиция будет установлена в обработчике Load для гарантии правильного позиционирования
    # $outputTextBoxX и $outputTextBoxY определены выше в параметрах (строка ~184-185) - можно менять в одном месте
    # Временно устанавливаем позицию, но она будет переопределена в обработчике Load
    $Global:OutputTextBox.Location = New-Object System.Drawing.Point($outputTextBoxX, $outputTextBoxY)
    # Используем фиксированные начальные размеры для минимального размера окна (900x700)
    # Anchor автоматически изменит размер при изменении формы
    # Высота учитывает место для кнопок внутри внизу (10px отступ + 30px высота кнопки = 40px)
    $outputTextBoxWidth = 420
    $initialFormHeight = 700  # Минимальная высота формы
    $outputTextBoxHeight = $initialFormHeight - $outputTextBoxHeightOffset  # Высота формы - отступ (используется переменная $outputTextBoxHeightOffset)
    $Global:OutputTextBox.Size = New-Object System.Drawing.Size($outputTextBoxWidth, $outputTextBoxHeight)
    $Global:OutputTextBox.Font = New-Object System.Drawing.Font("Consolas", 11)
    $Global:OutputTextBox.ReadOnly = $true
    $Global:OutputTextBox.BackColor = [System.Drawing.Color]::Black
    $Global:OutputTextBox.ForeColor = [System.Drawing.Color]::White
    $Global:OutputTextBox.ScrollBars = "Both"  # Включаем горизонтальную и вертикальную прокрутку
    $Global:OutputTextBox.WordWrap = $false  # Отключаем перенос слов для лучшего отображения длинных строк
    # НЕ используем Anchor - позиция и размер полностью контролируются обработчиками Load и Resize
    # Это гарантирует правильное позиционирование относительно переменных $outputTextBoxX и $outputTextBoxY
    $form.Controls.Add($Global:OutputTextBox)
    
    # Кнопка очистки вывода
    # Позиционируем внутри черного окна внизу слева, выровнена по левому краю RichTextBox
    # НЕ используем Anchor - позиция полностью контролируется обработчиком Resize для согласованности
    $clearButton = New-Object System.Windows.Forms.Button
    $clearButton.Text = "Очистить вывод"
    # Позиция: внутри RichTextBox, снизу слева, выровнена по левому краю
    $buttonMargin = -50  # Отступ снизу от края черного окна
    $buttonHeight = 30
    $clearButtonX = $outputTextBoxX  # Выровнена по левому краю RichTextBox (без отступа слева)
    $clearButtonY = $outputTextBoxY + $outputTextBoxHeight - $buttonHeight - $buttonMargin  # Внизу RichTextBox с отступом снизу
    $clearButton.Location = New-Object System.Drawing.Point($clearButtonX, $clearButtonY)
    $clearButton.Size = New-Object System.Drawing.Size(120, $buttonHeight)
    # НЕ используем Anchor - позиция полностью контролируется обработчиком Resize
    $clearButton.BackColor = [System.Drawing.Color]::LightGreen
    $clearButton.ForeColor = [System.Drawing.Color]::Black
    $clearButton.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9) #, [System.Drawing.FontStyle]::Bold)
    $clearButton.Add_Click({
        $Global:OutputTextBox.Clear()
    })
    $form.Controls.Add($clearButton)
    $clearButton.BringToFront()  # Поднимаем кнопку на передний план, чтобы она была видна поверх RichTextBox
    
    # Кнопка выхода
    # Позиционируем внутри черного окна внизу справа, выровнена по правому краю RichTextBox
    # НЕ используем Anchor, так как позиция будет полностью контролироваться обработчиком Resize
    $exitButton = New-Object System.Windows.Forms.Button
    $exitButton.Text = "Выход"
    # Позиция: внутри RichTextBox, снизу справа, выровнена по правому краю
    $exitButtonWidth = 120
    $exitButtonX = $outputTextBoxX + $outputTextBoxWidth - $exitButtonWidth  # Правый край RichTextBox - ширина кнопки
    $exitButtonY = $outputTextBoxY + $outputTextBoxHeight - $buttonHeight - $buttonMargin  # Внизу RichTextBox с отступом снизу
    $exitButton.Location = New-Object System.Drawing.Point($exitButtonX, $exitButtonY)
    $exitButton.Size = New-Object System.Drawing.Size($exitButtonWidth, $buttonHeight)
    # НЕ используем Anchor - позиция полностью контролируется обработчиком Resize
    # Это гарантирует, что кнопка всегда будет выровнена по правому краю RichTextBox
    $exitButton.BackColor = [System.Drawing.Color]::LightCoral
    $exitButton.ForeColor = [System.Drawing.Color]::Black
    $exitButton.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9) #, [System.Drawing.FontStyle]::Bold)
    $exitButton.Add_Click({
        # Закрываем форму; в ISE процесс не завершаем — окно ISE остаётся открытым
        try {
            if ($Global:ProgressForm -ne $null -and -not $Global:ProgressForm.IsDisposed) {
                try { $Global:ProgressForm.Close(); $Global:ProgressForm.Dispose() } catch { }
            }
            if ($Global:MainForm -ne $null -and -not $Global:MainForm.IsDisposed) {
                $Global:MainForm.Close()
            }
        } catch { }
        if ($Host.Name -ne "Windows PowerShell ISE Host") {
            [Environment]::Exit(0)
        }
    })
    $form.Controls.Add($exitButton)
    $exitButton.BringToFront()  # Поднимаем кнопку на передний план, чтобы она была видна поверх RichTextBox
    
    # Обработчик события Load для первоначального позиционирования кнопок
    # Сохраняем параметры позиции и размера в переменные формы для доступа в обработчиках
    $form.Tag = @{
        OutputTextBoxX = $outputTextBoxX
        OutputTextBoxY = $outputTextBoxY
        OutputTextBoxHeightOffset = $outputTextBoxHeightOffset
        OutputTextBoxWidthOffset = $outputTextBoxWidthOffset
    }
    
    # Обработчик события Resize для предотвращения минимизации формы во время выполнения операций
    $form.Add_Resize({
        # Если форма минимизирована и есть активная операция (прогресс-бар виден), восстанавливаем форму
        if ($this.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
            if ($Global:ProgressForm -ne $null -and -not $Global:ProgressForm.IsDisposed -and $Global:ProgressForm.Visible) {
                # Восстанавливаем форму, если идет выполнение операции
                $this.WindowState = [System.Windows.Forms.FormWindowState]::Normal
                $this.BringToFront()
                $this.Activate()
                [System.Windows.Forms.Application]::DoEvents()
            }
        }
    })
    
    # Обработчик события Activated для активации формы при переключении на неё
    $form.Add_Activated({
        # Убеждаемся, что форма видима и активна
        if ($this.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
            $this.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        }
        $this.BringToFront()
        [System.Windows.Forms.Application]::DoEvents()
    })
    
    $form.Add_Load({
        # Вызываем обработчик Resize для первоначального позиционирования кнопок
        if ($Global:OutputTextBox -ne $null -and -not $Global:OutputTextBox.IsDisposed) {
            $formWidth = [int]$this.ClientSize.Width
            $formHeight = [int]$this.ClientSize.Height
            $params = $this.Tag
            
            if ($params -ne $null -and $formWidth -gt $params.OutputTextBoxWidthOffset -and $formHeight -gt 235) {
                # Устанавливаем позицию RichTextBox ПЕРВЫМ ДЕЛОМ используя параметры из Tag
                $Global:OutputTextBox.Location = New-Object System.Drawing.Point([int]$params.OutputTextBoxX, [int]$params.OutputTextBoxY)
                # Затем устанавливаем размер используя параметры из Tag
                $Global:OutputTextBox.Width = $formWidth - [int]$params.OutputTextBoxWidthOffset
                $Global:OutputTextBox.Height = $formHeight - [int]$params.OutputTextBoxHeightOffset
                
                $outputTextBoxBottom = [int]($Global:OutputTextBox.Top + $Global:OutputTextBox.Height)
                $outputTextBoxRight = [int]($Global:OutputTextBox.Left + $Global:OutputTextBox.Width)
                $buttonMargin = -50
                $buttonHeight = 30
                
                foreach ($control in $this.Controls) {
                    if ($control -is [System.Windows.Forms.Button]) {
                        if ($control.Text -eq "Очистить вывод") {
                            $newX = [int]$Global:OutputTextBox.Left
                            $newY = [int]($outputTextBoxBottom - $buttonHeight - $buttonMargin)
                            $control.Location = New-Object System.Drawing.Point($newX, $newY)
                            $control.BringToFront()
                        }
                        elseif ($control.Text -eq "Выход") {
                            $newX = [int]($outputTextBoxRight - $control.Width)
                            $newY = [int]($outputTextBoxBottom - $buttonHeight - $buttonMargin)
                            $control.Location = New-Object System.Drawing.Point($newX, $newY)
                            $control.BringToFront()
                        }
                    }
                    elseif ($control -is [System.Windows.Forms.Label] -and $control.Text -eq "Вывод результатов") {
                        # Позиционируем метку "Вывод результатов" относительно RichTextBox
                        # Метка должна быть слева от RichTextBox на том же уровне по вертикали
                        $newX = [int]$Global:OutputTextBox.Left
                        $newY = [int]($Global:OutputTextBox.Top - 30)  # На 30px выше верхнего края RichTextBox
                        $control.Location = New-Object System.Drawing.Point($newX, $newY)
                    }
                }
            }
        }
    })
    
    # Обработчик события Resize для динамического изменения размеров элементов
    $form.Add_Resize({
        try {
            # Проверяем, что форма уже загружена и элементы инициализированы
            if ($this.WindowState -ne [System.Windows.Forms.FormWindowState]::Minimized -and 
                $Global:OutputTextBox -ne $null -and -not $Global:OutputTextBox.IsDisposed) {
                
                # Явно преобразуем в int для избежания ошибок op_Subtraction
                $formWidth = [int]$this.ClientSize.Width
                $formHeight = [int]$this.ClientSize.Height
                
                # Проверяем, что размеры валидны
                $params = $this.Tag
                if ($params -ne $null -and $formWidth -gt $params.OutputTextBoxWidthOffset -and $formHeight -gt 235) {
                    # Устанавливаем позицию RichTextBox ПЕРВЫМ ДЕЛОМ используя параметры из Tag
                    $Global:OutputTextBox.Location = New-Object System.Drawing.Point([int]$params.OutputTextBoxX, [int]$params.OutputTextBoxY)
                    # Затем пересчитываем размер RichTextBox используя параметры из Tag
                    # Учитываем место для кнопок внутри внизу (10px отступ + 30px высота кнопки = 40px)
                    $Global:OutputTextBox.Width = $formWidth - [int]$params.OutputTextBoxWidthOffset
                    $Global:OutputTextBox.Height = $formHeight - [int]$params.OutputTextBoxHeightOffset  # Высота формы - отступ (используется переменная из Tag)
                    
                    # Пересчитываем позиции кнопок внутри RichTextBox внизу, выровненных по краям
                    # Это критически важно для правильного позиционирования при изменении размера окна
                    $outputTextBoxBottom = [int]($Global:OutputTextBox.Top + $Global:OutputTextBox.Height)
                    $outputTextBoxRight = [int]($Global:OutputTextBox.Left + $Global:OutputTextBox.Width)
                    $buttonMargin = -50  # Отступ снизу от края черного окна
                    $buttonHeight = 30
                    
                    foreach ($control in $this.Controls) {
                        if ($control -is [System.Windows.Forms.Button]) {
                            if ($control.Text -eq "Очистить вывод") {
                                # Позиция: внутри RichTextBox, снизу слева, выровнена по левому краю
                                $newX = [int]$Global:OutputTextBox.Left
                                $newY = [int]($outputTextBoxBottom - $buttonHeight - $buttonMargin)
                                $control.Location = New-Object System.Drawing.Point($newX, $newY)
                                $control.BringToFront()  # Поднимаем кнопку на передний план
                            }
                            elseif ($control.Text -eq "Выход") {
                                # Позиция: внутри RichTextBox, снизу справа, выровнена по правому краю RichTextBox
                                # Это гарантирует, что кнопка всегда будет видна и правильно позиционирована
                                $newX = [int]($outputTextBoxRight - $control.Width)
                                $newY = [int]($outputTextBoxBottom - $buttonHeight - $buttonMargin)
                                $control.Location = New-Object System.Drawing.Point($newX, $newY)
                                $control.BringToFront()  # Поднимаем кнопку на передний план
                            }
                        }
                        elseif ($control -is [System.Windows.Forms.Label]) {
                            if ($control.Text -eq "1C: Enterprise 8 - Automation Tool") {
                                $control.Width = $formWidth - 40
                            }
                            elseif ($control.Text -like "*Made by*") {
                                $control.Width = $formWidth - 40
                            }
                            elseif ($control.Text -eq "Вывод результатов") {
                                # Позиционируем метку "Вывод результатов" относительно RichTextBox
                                # Метка должна быть слева от RichTextBox на том же уровне по вертикали
                                $newX = [int]$Global:OutputTextBox.Left
                                $newY = [int]($Global:OutputTextBox.Top - 30)  # На 30px выше верхнего края RichTextBox
                                $control.Location = New-Object System.Drawing.Point($newX, $newY)
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Игнорируем ошибки при изменении размера, чтобы не блокировать работу формы
            # Ошибки могут возникать при инициализации формы
        }
    })
    
    return $form
}

# Вспомогательная функция для проверки, является ли сервер локальным
function Test-IsLocalServer {
	param([string]$ServerName)
	
	if ([string]::IsNullOrEmpty($ServerName)) {
		return $false
	}
	
	# Приводим к верхнему регистру для сравнения
	$serverUpper = $ServerName.ToUpper().Trim()
	$currentComputerUpper = $env:COMPUTERNAME.ToUpper()
	
	# Проверяем различные варианты локального сервера
	if ($serverUpper -eq $currentComputerUpper -or 
		$serverUpper -eq "LOCALHOST" -or 
		$serverUpper -eq "127.0.0.1" -or
		$serverUpper -eq "." -or
		$serverUpper -eq $env:COMPUTERNAME) {
		return $true
	}
	
	# Проверяем через IP адрес текущего компьютера
	try {
		$localIPs = @()
		Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
			$localIPs += $_.IPAddress
		}
		if ($localIPs -contains $serverUpper) {
			return $true
		}
	}
	catch {
		# Игнорируем ошибки при проверке IP
	}
	
	return $false
}

# Функция подключения к серверу
function Connect-ToServer {
    $serverName = $Global:ServerTextBox.Text.Trim().ToUpper()
    
    if ([string]::IsNullOrEmpty($serverName)) {
        Write-ToOutputColored "[ОШИБКА] Введите имя сервера" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
        return
    }
    
    Write-ToOutput "Проверка подключения к серверу: $serverName" ([System.Drawing.Color]::Cyan)
    
    try {
        # Проверка существования сервера в AD через System.DirectoryServices (без RSAT)
        $computerFoundInAD = $false
        try {
            Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
            $ldapPath = $null
            try {
                $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $ldapPath = "LDAP://$($domainObj.Name)"
            }
            catch {
                if (-not [string]::IsNullOrEmpty($env:USERDNSDOMAIN)) {
                    $ldapPath = "LDAP://$env:USERDNSDOMAIN"
                }
            }
            if ($ldapPath) {
                $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($de)
                $searcher.Filter = "(&(objectCategory=computer)(|(name=$serverName)(sAMAccountName=$serverName`$)))"
                $searcher.PropertiesToLoad.Add("name") | Out-Null
                $result = $searcher.FindOne()
                if ($null -ne $result) {
                    $computerFoundInAD = $true
                }
                if ($null -ne $de) { try { $de.Dispose() } catch { } }
            }
        }
        catch {
            # Если проверка через AD недоступна (не в домене и т.п.), считаем что проверку AD пропускаем — проверяем только ping
            $computerFoundInAD = $true
        }
        
        if ($computerFoundInAD) {
            # Проверка доступности сервера (ping)
            $TestConnection = Test-Connection $serverName -Count 1 -ErrorAction Stop
            if (-not $TestConnection) {
                throw "Сервер недоступен (ping)"
            }
            # Проверка WinRM: простая команда через Invoke-Command; без успешного ответа подключение не считаем установленным
            try {
                $null = Invoke-Command -ComputerName $serverName -ScriptBlock { $true } -ErrorAction Stop
            }
            catch {
                throw "WinRM"
            }
            $Global:SetServer = $serverName
            Write-OutputResults -OutputLines @("[OK] Подключение к серверу $serverName Установлено|White")
            Write-ToOutput "" ([System.Drawing.Color]::White)
            
            # Обновление статуса
            $statusLabel = $Global:MainForm.Controls | Where-Object { $_.Text -like "*Не подключено*" -or $_.Text -like "*Подключено*" }
            if ($statusLabel) {
                $statusLabel.Text = "Подключено: $serverName"
                $statusLabel.ForeColor = [System.Drawing.Color]::Green
                $statusLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
            }
            
            # Очистка поля ввода сервера после успешного подключения
            if ($Global:ServerTextBox -ne $null -and -not $Global:ServerTextBox.IsDisposed) {
                $Global:ServerTextBox.Text = ""
            }
        }
        else {
            throw "Компьютер не найден в Active Directory."
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        $isWinRMError = ($errMsg -eq "WinRM" -or $errMsg -match "WinRM|WS-Management")
        if ($isWinRMError) {
            Write-ToOutputColored "[ОШИБКА] Сервер $serverName недоступен. Служба WinRM на сервере не отвечает или недоступна." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
            $script:winrmFormShown = $false
            # Форма рекомендации WinRM: создание и показ выполняем в scriptblock (на потоке GUI через Invoke при необходимости)
            $showWinrmForm = {
                try {
                    # Создание формы рекомендации
                    $winrmForm = New-Object System.Windows.Forms.Form
                    $winrmForm.Text = "Рекомендация: настройка WinRM"
                    $winrmForm.Size = New-Object System.Drawing.Size(620, 380)
                    $winrmForm.StartPosition = "CenterScreen"
                    $winrmForm.FormBorderStyle = "FixedDialog"
                    $winrmForm.MaximizeBox = $false
                    $winrmForm.MinimizeBox = $false
                    $winrmForm.ShowInTaskbar = $false
                    $winrmForm.BackColor = [System.Drawing.Color]::LightGray
                    $winrmForm.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
                    $formFont = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
                    
                    # Иконка восклицательного знака слева
                    $picIcon = New-Object System.Windows.Forms.PictureBox
                    $picIcon.Location = New-Object System.Drawing.Point(16, 18)
                    $picIcon.Size = New-Object System.Drawing.Size(32, 32)
                    $picIcon.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::CenterImage
                    try { $picIcon.Image = [System.Drawing.SystemIcons]::Exclamation.ToBitmap() } catch { }
                    $winrmForm.Controls.Add($picIcon)
                    
                    # Заголовок формы
                    $labelTitle = New-Object System.Windows.Forms.Label
                    $labelTitle.Text = "Работа ""1C:Enterprise 8 - Automation Tool"" на удалённом узле невозможна."
                    $labelTitle.Location = New-Object System.Drawing.Point(56, 28)
                    $labelTitle.Size = New-Object System.Drawing.Size(542, 25)
                    $labelTitle.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10, [System.Drawing.FontStyle]::Bold)
                    $labelTitle.ForeColor = [System.Drawing.Color]::DarkBlue
                    $labelTitle.AutoSize = $false
                    $winrmForm.Controls.Add($labelTitle)
                    
                    # Подсказка: запустить локально или настроить WinRM
                    $labelHint = New-Object System.Windows.Forms.Label
                    $labelHint.Text = "Пожалуйста, запустите программу локально или настройте службу WinRM на удалённом компьютере."
                    $labelHint.Location = New-Object System.Drawing.Point(56, 54)
                    $labelHint.Size = New-Object System.Drawing.Size(542, 34)
                    $labelHint.ForeColor = [System.Drawing.Color]::Black
                    $labelHint.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10)
                    $labelHint.AutoSize = $false
                    $winrmForm.Controls.Add($labelHint)
                    
                    # Текст перед командой PowerShell
                    $labelPs = New-Object System.Windows.Forms.Label
                    $labelPs.Text = "Для настройки WinRM откройте PowerShell от имени администратора на удалённой машине и выполните команду:"
                    $labelPs.Location = New-Object System.Drawing.Point(56, 92)
                    $labelPs.Size = New-Object System.Drawing.Size(542, 34)
                    $labelPs.ForeColor = [System.Drawing.Color]::Black
                    $labelPs.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10)
                    $labelPs.AutoSize = $false
                    $winrmForm.Controls.Add($labelPs)
                    
                    # Поле с командой PowerShell и кнопка «Копировать»
                    $textBoxPs = New-Object System.Windows.Forms.TextBox
                    $textBoxPs.Text = "Enable-PSRemoting -Force"
                    $textBoxPs.Location = New-Object System.Drawing.Point(56, 138)
                    $textBoxPs.Size = New-Object System.Drawing.Size(434, 23)
                    $textBoxPs.ReadOnly = $true
                    $textBoxPs.BackColor = [System.Drawing.Color]::White
                    $textBoxPs.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10)
                    $textBoxPs.Font = $formFont
                    $winrmForm.Controls.Add($textBoxPs)
                    $btnCopyPs = New-Object System.Windows.Forms.Button
                    $btnCopyPs.Text = "Копировать"
                    $btnCopyPs.Location = New-Object System.Drawing.Point(496, 136)
                    $btnCopyPs.Size = New-Object System.Drawing.Size(90, 26)
                    $btnCopyPs.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
                    $btnCopyPs.BackColor = [System.Drawing.Color]::DodgerBlue
                    $btnCopyPs.ForeColor = [System.Drawing.Color]::White
                    $btnCopyPs.Add_Click({ [System.Windows.Forms.Clipboard]::SetText("Enable-PSRemoting -Force") })
                    $winrmForm.Controls.Add($btnCopyPs)
                    
                    # Текст перед командой cmd
                    $labelCmd = New-Object System.Windows.Forms.Label
                    $labelCmd.Text = "Либо выполните в командной строке (cmd) от имени администратора:"
                    $labelCmd.Location = New-Object System.Drawing.Point(56, 174)
                    $labelCmd.Size = New-Object System.Drawing.Size(542, 34)
                    $labelCmd.ForeColor = [System.Drawing.Color]::Black
                    $labelCmd.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10)
                    $labelCmd.AutoSize = $false
                    $winrmForm.Controls.Add($labelCmd)
                    
                    # Поле с командой cmd и кнопка «Копировать»
                    $textBoxCmd = New-Object System.Windows.Forms.TextBox
                    $textBoxCmd.Text = "winrm quickconfig"
                    $textBoxCmd.Location = New-Object System.Drawing.Point(56, 208)
                    $textBoxCmd.Size = New-Object System.Drawing.Size(434, 23)
                    $textBoxCmd.ReadOnly = $true
                    $textBoxCmd.BackColor = [System.Drawing.Color]::White
                    $textBoxCmd.Font = $formFont
                    $winrmForm.Controls.Add($textBoxCmd)
                    $btnCopyCmd = New-Object System.Windows.Forms.Button
                    $btnCopyCmd.Text = "Копировать"
                    $btnCopyCmd.Location = New-Object System.Drawing.Point(496, 206)
                    $btnCopyCmd.Size = New-Object System.Drawing.Size(90, 26)
                    $btnCopyCmd.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
                    $btnCopyCmd.BackColor = [System.Drawing.Color]::DodgerBlue
                    $btnCopyCmd.ForeColor = [System.Drawing.Color]::White
                    $btnCopyCmd.Add_Click({ [System.Windows.Forms.Clipboard]::SetText("winrm quickconfig") })
                    $winrmForm.Controls.Add($btnCopyCmd)
                    
                    # Кнопка OK и показ формы
                    $btnOk = New-Object System.Windows.Forms.Button
                    $btnOk.Text = "OK"
                    $btnOk.Location = New-Object System.Drawing.Point(496, 308)
                    $btnOk.Size = New-Object System.Drawing.Size(94, 28)
                    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
                    $btnOk.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
                    $btnOk.BackColor = [System.Drawing.Color]::Green
                    $btnOk.ForeColor = [System.Drawing.Color]::White
                    $winrmForm.AcceptButton = $btnOk
                    $winrmForm.Controls.Add($btnOk)
                    
                    # Показ формы модально (владелец — MainForm, если доступна)
                    if ($null -ne $Global:MainForm -and -not $Global:MainForm.IsDisposed) {
                        $winrmForm.ShowDialog($Global:MainForm) | Out-Null
                    } else {
                        $winrmForm.ShowDialog() | Out-Null
                    }
                    $script:winrmFormShown = $true
                    $winrmForm.Dispose()
                } catch {
                    $script:winrmFormShown = $false
                }
            }
            # Выполняем scriptblock на потоке GUI: через Invoke, если вызваны не из потока формы, иначе напрямую
            try {
                if ($null -ne $Global:MainForm -and -not $Global:MainForm.IsDisposed -and $Global:MainForm.InvokeRequired) {
                    [void]$Global:MainForm.Invoke([Action]$showWinrmForm)
                } else {
                    & $showWinrmForm
                }
            } catch {
                $script:winrmFormShown = $false
            }
            # Если форма не показалась — выводим рекомендацию в MessageBox
            if (-not $script:winrmFormShown) {
                $msg = "Работа ""1C:Enterprise 8 - Automation Tool"" на удалённом узле невозможна.`n`nПожалуйста, запустите программу локально или настройте службу WinRM на удалённом компьютере.`n`nДля настройки WinRM откройте PowerShell от имени администратора на удалённой машине и выполните команду:`nEnable-PSRemoting -Force`n`nЛибо выполните в командной строке:`nwinrm quickconfig"
                [System.Windows.Forms.MessageBox]::Show($msg, "Рекомендация: настройка WinRM", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
        }
        else {
            Write-ToOutputColored "[ОШИБКА] Сервер $serverName не найден или недоступен. $errMsg" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
        }
        # Очистка поля ввода сервера после ошибки подключения
        if ($Global:ServerTextBox -ne $null -and -not $Global:ServerTextBox.IsDisposed) {
            $Global:ServerTextBox.Text = ""
        }
    }
}

# Функция выполнения выбранной функции
function Execute-Function {
    param([int]$FunctionNumber)
    
    if ([string]::IsNullOrEmpty($Global:SetServer)) {
        Write-ToOutputColored "[ОШИБКА] Сначала подключитесь к серверу!" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
        return
    }
    
    # Убеждаемся, что главная форма активна и видима перед началом операций
    if ($Global:MainForm -ne $null -and -not $Global:MainForm.IsDisposed) {
        try {
            if ($Global:MainForm.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
                $Global:MainForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
            }
            $Global:MainForm.BringToFront()
            $Global:MainForm.Activate()
            $Global:MainForm.Focus()
            [System.Windows.Forms.Application]::DoEvents()
        } catch {
            # Игнорируем ошибки активации
        }
    }
    
    #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
    
    # Показываем прогресс-бар для длительных операций
    $showProgress = @(1, 2, 3, 6, 7, 8, 9) -contains $FunctionNumber
    
    if ($showProgress) {
        Show-ProgressBar -Title "Выполнение операции" -Status "Подготовка к выполнению..."
    }
    
    try {
        switch ($FunctionNumber) {
            1 {
                Write-ToOutput "" ([System.Drawing.Color]::White)
                Write-ToOutput "Выполнение: Информация о COM-объекте" ([System.Drawing.Color]::Magenta)
                #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
                if ($showProgress) { Update-ProgressBar -Status "Получение информации о COM-объекте..." }
                Get-ComObject1C -Server $Global:SetServer
            }
            2 {
                Write-ToOutput "" ([System.Drawing.Color]::White)
                Write-ToOutput "Выполнение: Информация о версиях платформы" ([System.Drawing.Color]::Magenta)
                #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
                if ($showProgress) { Update-ProgressBar -Status "Получение информации о версиях платформы..." }
                Get-Platform1C -Server $Global:SetServer
            }
            3 {
                Write-ToOutput "" ([System.Drawing.Color]::White)
                Write-ToOutput "Выполнение: Информация о службе" ([System.Drawing.Color]::Magenta)
                #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
                if ($showProgress) { Update-ProgressBar -Status "Получение информации о службе..." }
                Get-Service1C -Server $Global:SetServer
            }
            4 {
                Write-ToOutput "" ([System.Drawing.Color]::White)
                Write-ToOutput "Выполнение: Работа со службой" ([System.Drawing.Color]::Magenta)
                #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
                # Функция 4 требует интерактивного ввода - диалоги будут показаны внутри функции
                Execute-JobService1CWithGUI
            }
            5 {
                Write-ToOutput "" ([System.Drawing.Color]::White)
                Write-ToOutput "Выполнение: Работа с COM-объектом" ([System.Drawing.Color]::Magenta)
                #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
                # Функция 5 требует интерактивного ввода - диалоги будут показаны внутри функции
                Execute-JobComObject1CWithGUI
            }
            6 {
                Write-ToOutput "" ([System.Drawing.Color]::White)
                Write-ToOutput "Выполнение: Удаление активных сессий" ([System.Drawing.Color]::Magenta)
                #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
                if ($showProgress) { Update-ProgressBar -Status "Подключение к кластеру 1С..." }
                # Функция 6 требует интерактивного ввода - диалоги будут показаны внутри функции
                Execute-DisactivateSession1CWithGUI
            }
            7 {
                Write-ToOutput "" ([System.Drawing.Color]::White)
                Write-ToOutput "Выполнение: Удаление временных файлов" ([System.Drawing.Color]::Magenta)
                #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
                if ($showProgress) { Update-ProgressBar -Status "Удаление временных файлов..." }
                Remove-TempFiles1C -Server $Global:SetServer
            }
            8 {
                Write-ToOutput "" ([System.Drawing.Color]::White)
                Write-ToOutput "Выполнение: Удаление сервера" ([System.Drawing.Color]::Magenta)
                #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
                if ($showProgress) { Update-ProgressBar -Status "Удаление сервера и службы..." }
                Remove-Server1C -Server $Global:SetServer
            }
            9 {
                Write-ToOutput "" ([System.Drawing.Color]::White)
                Write-ToOutput "Выполнение: Установка сервера" ([System.Drawing.Color]::Magenta)
                #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
                if ($showProgress) { Update-ProgressBar -Status "Подготовка к установке сервера..." }
                # Функция 9 требует интерактивного ввода - диалоги будут показаны внутри функции
                Execute-InstallServer1CWithGUI
            }
        }
        
        if ($showProgress) {
            Update-ProgressBar -Status "Операция завершена успешно!" -PercentComplete 100
            Start-Sleep -Milliseconds 500
        }
    }
    catch {
        Write-ToOutputColored "[ОШИБКА] $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
        if ($showProgress) {
            Update-ProgressBar -Status "[ОШИБКА] $($_.Exception.Message)"
            Start-Sleep -Milliseconds 1000
        }
    }
    finally {
        if ($showProgress) {
            Hide-ProgressBar
        }
    }
    
    #Write-ToOutput "___________________________________________________________" ([System.Drawing.Color]::Magenta)
    Write-ToOutput "" ([System.Drawing.Color]::Black)
}

# Обёртка 1 для функций с GUI диалогами
function Execute-JobService1CWithGUI {
    Job-Service1C -Server $Global:SetServer
}

# Обёртка 2 для функций с GUI диалогами
function Execute-JobComObject1CWithGUI {
    Job-ComObject1C -Server $Global:SetServer
}

# Обёртка 3 для функций с GUI диалогами
function Execute-DisactivateSession1CWithGUI {
    Disactivate-Session1C -Server $Global:SetServer
}

# Обёртка 4 для функций с GUI диалогами
function Execute-InstallServer1CWithGUI {
    Install-Server1C -Server $Global:SetServer
}

# Функция создания диалога выбора из списка: одна опция из Items. С Modeless диалог не блокирует главное окно.
# Возвращает номер выбранного пункта (1-based) или $null при отмене.
function Show-SelectionDialog {
    param(
        [string]$Title,
        [string]$Prompt,
        [array]$Items,
        [string]$CancelText = "Отмена",
        [switch]$Modeless  # При включении диалог не блокирует главное окно — можно переключиться на вывод
    )
    
    # Модальное окно; шрифт — системный для диалогов
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = $Title
    $dialog.Size = New-Object System.Drawing.Size(700, 350)
    $dialog.StartPosition = "CenterParent"
    $dialog.FormBorderStyle = "FixedDialog"
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.ShowInTaskbar = $false
    try {
        $dialogFont = [System.Drawing.SystemFonts]::MessageBoxFont
    } catch {
        $dialogFont = New-Object System.Drawing.Font("Microsoft Sans Serif", 10)
    }
    $dialog.Font = $dialogFont
    
    # Подсказка над списком
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $label.Size = New-Object System.Drawing.Size(680, 30)
    $label.Font = $dialogFont
    $dialog.Controls.Add($label)
    
    # Список вариантов; по умолчанию выбран первый элемент
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10, 45)
    $listBox.Size = New-Object System.Drawing.Size(680, 230)
    $listBox.Font = $dialogFont
    foreach ($item in $Items) {
        $listBox.Items.Add($item) | Out-Null
    }
    $listBox.SelectedIndex = 0
    $dialog.Controls.Add($listBox)
    
    # Для Modeless сохраняем результат в script-переменную; ListBox храним в Tag формы
    $script:selectionDialogResult = $null
    $dialog.Tag = $listBox
    
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point(520, 285)
    $okButton.Size = New-Object System.Drawing.Size(75, 25)
    $dialog.Controls.Add($okButton)
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = $CancelText
    $cancelButton.Location = New-Object System.Drawing.Point(605, 285)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 25)
    $dialog.Controls.Add($cancelButton)
    
    # Режим без блокировки главного окна: кнопки закрывают форму и пишут результат в script:selectionDialogResult
    if ($Modeless) {
        $okButton.Add_Click({
            $f = $this.FindForm()
            $lb = $f.Tag
            if ($lb -ne $null) { $script:selectionDialogResult = $lb.SelectedIndex + 1 }
            $f.Close()
        })
        $cancelButton.Add_Click({
            $script:selectionDialogResult = $null
            $this.FindForm().Close()
        })
        
        $timerWasRunning = $false
        if ($Global:ProgressTimer -ne $null -and $Global:ProgressTimer.Enabled) {
            $timerWasRunning = $true
            Stop-ProgressBarAnimation
        }
        
        $dialog.Show($Global:MainForm)
        while ($dialog.Visible) {
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 50
        }
        
        if ($timerWasRunning -and $Global:ProgressForm -ne $null -and $Global:ProgressForm.Visible) {
            Start-ProgressBarAnimation
        }
        return $script:selectionDialogResult
    }
    
    # Модальный режим: DialogResult и Accept/Cancel кнопки
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dialog.AcceptButton = $okButton
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dialog.CancelButton = $cancelButton
    
    $timerWasRunning = $false
    if ($Global:ProgressTimer -ne $null -and $Global:ProgressTimer.Enabled) {
        $timerWasRunning = $true
        Stop-ProgressBarAnimation
    }
    
    $result = $dialog.ShowDialog($Global:MainForm)
    
    if ($timerWasRunning -and $Global:ProgressForm -ne $null -and $Global:ProgressForm.Visible) {
        Start-ProgressBarAnimation
    }
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $listBox.SelectedIndex + 1
    } else {
        return $null
    }
}

# Функция создания диалога ввода текста: заголовок, подсказка, поле ввода и кнопки OK/Отмена.
# Возвращает введённую строку или $null при отмене.
function Show-InputDialog {
    param(
        [string]$Title,
        [string]$Prompt,
        [string]$DefaultValue = "",
        [string]$CancelText = "Отмена"
    )
    
    # Модальное окно с фиксированным размером
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = $Title
    $dialog.Size = New-Object System.Drawing.Size(400, 150)
    $dialog.StartPosition = "CenterParent"
    $dialog.FormBorderStyle = "FixedDialog"
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.ShowInTaskbar = $false
    
    # Подсказка над полем ввода
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $label.Size = New-Object System.Drawing.Size(380, 30)
    $label.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $dialog.Controls.Add($label)
    
    # Текстовое поле с начальным значением; при открытии фокус в поле
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10, 45)
    $textBox.Size = New-Object System.Drawing.Size(380, 23)
    $textBox.Text = $DefaultValue
    $textBox.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $dialog.Controls.Add($textBox)
    $dialog.Add_Shown({$textBox.Select()})
    
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point(220, 80)
    $okButton.Size = New-Object System.Drawing.Size(75, 25)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dialog.AcceptButton = $okButton
    $dialog.Controls.Add($okButton)
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = $CancelText
    $cancelButton.Location = New-Object System.Drawing.Point(305, 80)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 25)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dialog.CancelButton = $cancelButton
    $dialog.Controls.Add($cancelButton)
    
    # Останавливаем таймер анимации перед показом модального диалога
    $timerWasRunning = $false
    if ($Global:ProgressTimer -ne $null -and $Global:ProgressTimer.Enabled) {
        $timerWasRunning = $true
        Stop-ProgressBarAnimation
    }
    
    $result = $dialog.ShowDialog($Global:MainForm)
    
    # Возобновляем таймер анимации после закрытия диалога, если он был запущен и прогресс-бар виден
    if ($timerWasRunning -and $Global:ProgressForm -ne $null -and $Global:ProgressForm.Visible) {
        Start-ProgressBarAnimation
    }
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $textBox.Text
    } else {
        return $null
    }
}

# Функция создания диалога выбора баз по CheckBox: показывает список доступных баз с флажками,
# кнопки «Выбрать все» / «Снять все», OK/Отмена. Возвращает массив выбранных имён баз или $null при отмене.
function Show-BasesCheckBoxDialog {
    param(
        [string]$Title = "Выбор баз данных",
        [string]$Prompt = "Отметьте базы, из которых нужно удалить сессии:",
        [array]$AvailableBases
    )
    
    # Если список баз пуст — диалог не показываем
    if ($null -eq $AvailableBases -or $AvailableBases.Count -eq 0) {
        return $null
    }
    
    # Создание модального окна; шрифт — системный для диалогов
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = $Title
    $dialog.Size = New-Object System.Drawing.Size(500, 450)
    $dialog.StartPosition = "CenterParent"
    $dialog.FormBorderStyle = "FixedDialog"
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.ShowInTaskbar = $false
    try {
        $dialogFont = [System.Drawing.SystemFonts]::MessageBoxFont
     
    } catch {
        $dialogFont = New-Object System.Drawing.Font("Microsoft Sans Serif", 10)
    }
    $dialog.Font = $dialogFont
    
    # Текстовая подсказка над списком
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $label.Size = New-Object System.Drawing.Size(480, 25)
    $label.Font = $dialogFont
    $dialog.Controls.Add($label)
    
    # Список с флажками: шрифт как у формы — тот же, что в окне «Действие со службой»
    $checkedListBox = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox.Location = New-Object System.Drawing.Point(10, 40)
    $checkedListBox.Size = New-Object System.Drawing.Size(480, 330)
    $checkedListBox.Font = $dialogFont
    $checkedListBox.CheckOnClick = $true
    foreach ($base in $AvailableBases) {
        [void]$checkedListBox.Items.Add($base, $false)
    }
    $dialog.Controls.Add($checkedListBox)
    
    # Кнопка «Выбрать все» — отмечает все элементы списка
    $selectAllButton = New-Object System.Windows.Forms.Button
    $selectAllButton.Text = "Выбрать все"
    $selectAllButton.Location = New-Object System.Drawing.Point(10, 378)
    $selectAllButton.Size = New-Object System.Drawing.Size(100, 25)
    $selectAllButton.Add_Click({
        $clb = $this.Parent.Controls | Where-Object { $_ -is [System.Windows.Forms.CheckedListBox] } | Select-Object -First 1
        if ($clb) { for ($i = 0; $i -lt $clb.Items.Count; $i++) { $clb.SetItemChecked($i, $true) } }
    })
    $dialog.Controls.Add($selectAllButton)
    
    # Кнопка «Снять все» — снимает отметки со всех элементов
    $deselectAllButton = New-Object System.Windows.Forms.Button
    $deselectAllButton.Text = "Снять все"
    $deselectAllButton.Location = New-Object System.Drawing.Point(115, 378)
    $deselectAllButton.Size = New-Object System.Drawing.Size(100, 25)
    $deselectAllButton.Add_Click({
        $clb = $this.Parent.Controls | Where-Object { $_ -is [System.Windows.Forms.CheckedListBox] } | Select-Object -First 1
        if ($clb) { for ($i = 0; $i -lt $clb.Items.Count; $i++) { $clb.SetItemChecked($i, $false) } }
    })
    $dialog.Controls.Add($deselectAllButton)
    
    $script:basesCheckBoxDialogResult = $null
    
    # Кнопка OK — закрывает диалог с результатом OK
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point(320, 378)
    $okButton.Size = New-Object System.Drawing.Size(75, 25)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dialog.AcceptButton = $okButton
    $dialog.Controls.Add($okButton)
    
    # Кнопка Отмена — закрывает диалог без выбора
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Отмена"
    $cancelButton.Location = New-Object System.Drawing.Point(405, 378)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 25)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dialog.CancelButton = $cancelButton
    $dialog.Controls.Add($cancelButton)
    
    # Останавливаем таймер анимации прогресс-бара перед показом диалога
    $timerWasRunning = $false
    if ($Global:ProgressTimer -ne $null -and $Global:ProgressTimer.Enabled) {
        $timerWasRunning = $true
        Stop-ProgressBarAnimation
    }
    
    $result = $dialog.ShowDialog($Global:MainForm)
    
    # Возобновляем таймер анимации после закрытия диалога, если прогресс-бар был виден
    if ($timerWasRunning -and $Global:ProgressForm -ne $null -and $Global:ProgressForm.Visible) {
        Start-ProgressBarAnimation
    }
    
    # При нажатии OK собираем массив отмеченных баз и возвращаем его; при Отмена — $null
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $selected = @()
        for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
            if ($checkedListBox.GetItemChecked($i)) {
                $selected += $checkedListBox.Items[$i]
            }
        }
        return $selected
    }
    return $null
}

# Функция создания диалога ввода списка баз: в цикле показывается Show-InputDialog; пользователь вводит
# имена баз по одному, «Готово» завершает ввод. Пустые значения и дубликаты отклоняются. Возвращает ArrayList имён или $null.
function Show-BasesInputDialog {
    param(
        [string]$Title = "Ввод баз данных",
        [string]$Prompt = "Вводите имя базы по одному. Для завершения нажмите 'Готово'."
    )
    
    $bases = New-Object System.Collections.ArrayList
    $currentBase = ""
    
    while ($true) {
        $input = Show-InputDialog -Title $Title -Prompt "$Prompt`n`nТекущий список баз: $(if ($bases.Count -eq 0) { 'пусто' } else { $bases -join ', ' })`n`nВведите имя базы:" -DefaultValue $currentBase -CancelText "Готово"
        
        if ($null -eq $input) {
            # Нажата кнопка "Готово" или отмена: если список не пуст — возвращаем его, иначе $null
            if ($bases.Count -gt 0) {
                break
            } else {
                return $null
            }
        }
        
        $input = $input.Trim()
        if ([string]::IsNullOrEmpty($input)) {
            [System.Windows.Forms.MessageBox]::Show("Введите имя базы или нажмите 'Готово' для завершения.", "Пустое значение", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            continue
        }
        
        # Не допускаем дубликаты
        if ($bases -contains $input) {
            [System.Windows.Forms.MessageBox]::Show("База '$input' уже добавлена в список.", "Дубликат", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            $currentBase = ""
            continue
        }
        
        $bases.Add($input) | Out-Null
        $currentBase = ""
        Write-ToOutputSegments -Segments @(
            [PSCustomObject]@{ Text = "[OK]"; Color = [System.Drawing.Color]::Green },
            [PSCustomObject]@{ Text = " Добавлена база:"; Color = [System.Drawing.Color]::White },
            [PSCustomObject]@{ Text = " $input"; Color = [System.Drawing.Color]::Gray }
        )
    }
    
    return $bases
}

# Функция проверки доменной учётной записи и пароля (System.DirectoryServices, без модуля RSAT-AD-PowerShell)
function Test-DomainCredentials {
    param(
        [string]$Username,
        [System.Security.SecureString]$SecurePassword
    )
    
    $isValid = $false
    $plainPassword = $null
    $bstr = [IntPtr]::Zero
    $de = $null
    
    try {
        # Извлекаем пароль из SecureString для проверки
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        
        # Извлекаем домен и имя пользователя
        if ($Username -match "\\") {
            $domainParts = $Username -split "\\", 2
            $domainNetBios = $domainParts[0]
            $userNameOnly = $domainParts[1]
        } else {
            $domainNetBios = $null
            $userNameOnly = $Username
        }
        
        # Получаем LDAP-путь и имя домена (FQDN или NetBIOS) через System.DirectoryServices.ActiveDirectory или переменные окружения
        $ldapPath = $null
        $bindUserName = $null
        try {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $domainFqdn = $domainObj.Name
            $ldapPath = "LDAP://$domainFqdn"
            if ($null -ne $domainNetBios) {
                $bindUserName = "$domainNetBios\$userNameOnly"
            } else {
                $bindUserName = "$userNameOnly@$domainFqdn"
            }
        }
        catch {
            # Не присоединён к домену или ошибка — используем переменные окружения / WMI
            if ($null -ne $domainNetBios) {
                $ldapPath = "LDAP://$domainNetBios"
                $bindUserName = "$domainNetBios\$userNameOnly"
            } else {
                $domainFromEnv = $env:USERDNSDOMAIN
                if ([string]::IsNullOrEmpty($domainFromEnv)) {
                    $domainFromEnv = $env:USERDOMAIN
                }
                if ([string]::IsNullOrEmpty($domainFromEnv)) {
                    try {
                        $domainFromEnv = (Get-WmiObject Win32_ComputerSystem).Domain
                    }
                    catch { }
                }
                if ([string]::IsNullOrEmpty($domainFromEnv)) {
                    return $false
                }
                $ldapPath = "LDAP://$domainFromEnv"
                $bindUserName = "$userNameOnly@$domainFromEnv"
            }
        }
        
        if ([string]::IsNullOrEmpty($ldapPath) -or [string]::IsNullOrEmpty($bindUserName)) {
            return $false
        }
        
        # Проверка учётных данных через привязку (bind) к LDAP
        try {
            Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
            $de = New-Object System.DirectoryServices.DirectoryEntry(
                $ldapPath,
                $bindUserName,
                $plainPassword
            )
            $null = $de.RefreshCache()
            $isValid = $true
        }
        catch {
            $isValid = $false
        }
        finally {
            if ($null -ne $de) {
                try { $de.Dispose() } catch { }
                $de = $null
            }
        }
    }
    catch {
        $isValid = $false
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            $bstr = [IntPtr]::Zero
        }
        if ($null -ne $plainPassword) {
            $plainPassword = $null
        }
        [System.GC]::Collect()
    }
    
    return $isValid
}

# Функция создания диалога ввода пароля: поле с маскировкой символов, OK/Отмена. Возвращает SecureString или $null при отмене/пустом вводе.
function Show-PasswordDialog {
    param(
        [string]$Title = "Ввод пароля",
        [string]$Prompt = "Введите пароль:",
        [string]$CancelText = "Отмена"
    )
    
    # Модальное окно поверх других, фиксированный размер
    $passwordDialog = New-Object System.Windows.Forms.Form
    $passwordDialog.Text = $Title
    $passwordDialog.Size = New-Object System.Drawing.Size(400, 150)
    $passwordDialog.StartPosition = "CenterParent"
    $passwordDialog.FormBorderStyle = "FixedDialog"
    $passwordDialog.MaximizeBox = $false
    $passwordDialog.MinimizeBox = $false
    $passwordDialog.ShowInTaskbar = $false
    $passwordDialog.TopMost = $true
    
    # Подсказка над полем пароля
    $passwordLabel = New-Object System.Windows.Forms.Label
    $passwordLabel.Text = $Prompt
    $passwordLabel.Location = New-Object System.Drawing.Point(10, 10)
    $passwordLabel.Size = New-Object System.Drawing.Size(380, 30)
    $passwordLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $passwordDialog.Controls.Add($passwordLabel)
    
    # Поле ввода с маскировкой символов (звёздочки), при открытии фокус в поле
    $passwordTextBox = New-Object System.Windows.Forms.TextBox
    $passwordTextBox.PasswordChar = '*'
    $passwordTextBox.UseSystemPasswordChar = $true
    $passwordTextBox.Location = New-Object System.Drawing.Point(10, 45)
    $passwordTextBox.Size = New-Object System.Drawing.Size(380, 23)
    $passwordTextBox.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $passwordDialog.Controls.Add($passwordTextBox)
    $passwordDialog.Add_Shown({$passwordTextBox.Select()})
    
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point(220, 80)
    $okButton.Size = New-Object System.Drawing.Size(75, 25)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $passwordDialog.AcceptButton = $okButton
    $passwordDialog.Controls.Add($okButton)
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = $CancelText
    $cancelButton.Location = New-Object System.Drawing.Point(305, 80)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 25)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $passwordDialog.CancelButton = $cancelButton
    $passwordDialog.Controls.Add($cancelButton)
    
    # Останавливаем таймер анимации перед показом модального диалога
    $timerWasRunning = $false
    if ($Global:ProgressTimer -ne $null -and $Global:ProgressTimer.Enabled) {
        $timerWasRunning = $true
        Stop-ProgressBarAnimation
    }
    
    $result = $passwordDialog.ShowDialog($Global:MainForm)
    
    # Возобновляем таймер анимации после закрытия диалога, если он был запущен и прогресс-бар виден
    if ($timerWasRunning -and $Global:ProgressForm -ne $null -and $Global:ProgressForm.Visible) {
        Start-ProgressBarAnimation
    }
    
    $securePassword = $null
    
    # Читаем значение из TextBox ДО очистки и закрытия диалога
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $plainPassword = $passwordTextBox.Text
        
        # Проверяем, что пароль не пустой
        if (-not [string]::IsNullOrEmpty($plainPassword)) {
            # Конвертируем в SecureString
            $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
            
            # Очищаем обычную строку из памяти
            # Заполняем строку нулями перед очисткой (если возможно)
            if ($null -ne $plainPassword) {
                $plainPassword = $null
            }
        }
    }
    
    # Очищаем TextBox из памяти после чтения значения
    if ($null -ne $passwordTextBox) {
        $passwordTextBox.Text = ""
        $passwordTextBox.Clear()
        $passwordTextBox = $null
    }
    
    # Закрываем и очищаем диалог
    if ($null -ne $passwordDialog) {
        $passwordDialog.Dispose()
        $passwordDialog = $null
    }
    
    # Очищаем буфер обмена на случай, если там случайно остался пароль
    try {
        [System.Windows.Forms.Clipboard]::Clear()
    }
    catch {
        # Игнорируем ошибки очистки буфера обмена
    }
    
    # Принудительная сборка мусора для очистки памяти
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    
    return $securePassword
}

# Функция создания прогресс-бара
function Show-ProgressBar {
    param(
        [string]$Title = "Выполнение операции",
        [string]$Status = "Ожидание..."
    )
    
    # Убеждаемся, что главная форма активна и видима перед показом прогресс-бара
    if ($Global:MainForm -ne $null -and -not $Global:MainForm.IsDisposed) {
        try {
            if ($Global:MainForm.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
                $Global:MainForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
            }
            $Global:MainForm.BringToFront()
            $Global:MainForm.Activate()
            [System.Windows.Forms.Application]::DoEvents()
        } catch {
            # Игнорируем ошибки активации
        }
    }
    
    $Global:ProgressForm = New-Object System.Windows.Forms.Form
    $Global:ProgressForm.Text = $Title
    $Global:ProgressForm.Size = New-Object System.Drawing.Size(500, 150)
    $Global:ProgressForm.StartPosition = "CenterParent"
    $Global:ProgressForm.FormBorderStyle = "FixedDialog"
    $Global:ProgressForm.MaximizeBox = $false
    $Global:ProgressForm.MinimizeBox = $false
    $Global:ProgressForm.ShowInTaskbar = $false
    $Global:ProgressForm.TopMost = $true
    
    $Global:ProgressLabel = New-Object System.Windows.Forms.Label
    $Global:ProgressLabel.Text = $Status
    $Global:ProgressLabel.Location = New-Object System.Drawing.Point(10, 10)
    $Global:ProgressLabel.Size = New-Object System.Drawing.Size(480, 30)
    $Global:ProgressLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $Global:ProgressForm.Controls.Add($Global:ProgressLabel)
    
    $Global:ProgressBar = New-Object System.Windows.Forms.ProgressBar
    $Global:ProgressBar.Location = New-Object System.Drawing.Point(10, 50)
    $Global:ProgressBar.Size = New-Object System.Drawing.Size(480, 30)
    $Global:ProgressBar.Style = "Marquee"
    $Global:ProgressBar.MarqueeAnimationSpeed = 50
    $Global:ProgressForm.Controls.Add($Global:ProgressBar)
    
    $Global:ProgressForm.Show($Global:MainForm)
    [System.Windows.Forms.Application]::DoEvents()
    
    # Запускаем таймер для анимации прогресс-бара
    Start-ProgressBarAnimation
}

# Функция обновления прогресс-бара
function Update-ProgressBar {
    param(
        [string]$Status,
        [int]$PercentComplete = -1
    )
    
    if ($Global:ProgressForm -ne $null -and $Global:ProgressForm.Visible) {
        if ($Status) {
            $Global:ProgressLabel.Text = $Status
        }
        if ($PercentComplete -ge 0 -and $PercentComplete -le 100) {
            $Global:ProgressBar.Style = "Continuous"
            $Global:ProgressBar.Value = $PercentComplete
        }
        [System.Windows.Forms.Application]::DoEvents()
        
        # Периодически активируем главную форму, чтобы она не теряла фокус
        if ($Global:MainForm -ne $null -and -not $Global:MainForm.IsDisposed) {
            try {
                if ($Global:MainForm.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
                    $Global:MainForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
                }
                # Активируем только если форма не в фокусе (чтобы не мешать пользователю)
                if (-not $Global:MainForm.Focused) {
                    $Global:MainForm.BringToFront()
                }
            } catch {
                # Игнорируем ошибки активации
            }
        }
    }
}

# Функция закрытия прогресс-бара
function Hide-ProgressBar {
    # Write-ToOutput "[DEBUG] Hide-ProgressBar: Начало выполнения" ([System.Drawing.Color]::Cyan)
    # [System.Windows.Forms.Application]::DoEvents()
    if ($Global:ProgressForm -ne $null) {
        # Write-ToOutput "[DEBUG] Hide-ProgressBar: ProgressForm не null, IsDisposed = $($Global:ProgressForm.IsDisposed), Visible = $($Global:ProgressForm.Visible)" ([System.Drawing.Color]::Cyan)
        # [System.Windows.Forms.Application]::DoEvents()
        try {
            # Останавливаем таймер анимации, если он запущен
            if ($Global:ProgressTimer -ne $null) {
                # Write-ToOutput "[DEBUG] Hide-ProgressBar: Останавливаем таймер" ([System.Drawing.Color]::Cyan)
                # [System.Windows.Forms.Application]::DoEvents()
                $Global:ProgressTimer.Stop()
                $Global:ProgressTimer.Dispose()
                $Global:ProgressTimer = $null
                # Write-ToOutput "[DEBUG] Hide-ProgressBar: Таймер остановлен и очищен" ([System.Drawing.Color]::Cyan)
                # [System.Windows.Forms.Application]::DoEvents()
            } else {
                # Write-ToOutput "[DEBUG] Hide-ProgressBar: Таймер уже null" ([System.Drawing.Color]::Cyan)
                # [System.Windows.Forms.Application]::DoEvents()
            }
            
            # Активируем главную форму перед закрытием прогресс-бара
            if ($Global:MainForm -ne $null -and -not $Global:MainForm.IsDisposed) {
                try {
                    $Global:MainForm.BringToFront()
                    $Global:MainForm.Activate()
                    $Global:MainForm.Focus()
                    $Global:MainForm.Invalidate()
                    $Global:MainForm.Refresh()
                    $Global:MainForm.Update()
                    [System.Windows.Forms.Application]::DoEvents()
                } catch {
                    # Игнорируем ошибки при активации главной формы
                }
            }
            
            # Принудительно обновляем форму перед закрытием
            if (-not $Global:ProgressForm.IsDisposed) {
                try {
                    # Отключаем TopMost перед закрытием
                    try {
                        $Global:ProgressForm.TopMost = $false
                        [System.Windows.Forms.Application]::DoEvents()
                    } catch { }
                    
                    # Отключаем ShowInTaskbar перед закрытием
                    try {
                        $Global:ProgressForm.ShowInTaskbar = $false
                        [System.Windows.Forms.Application]::DoEvents()
                    } catch { }
                    
                    # Убираем Owner перед закрытием
                    try {
                        $Global:ProgressForm.Owner = $null
                        [System.Windows.Forms.Application]::DoEvents()
                    } catch { }
                    
                    # Минимизируем форму перед закрытием для гарантированного скрытия
                    try {
                        $Global:ProgressForm.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
                        [System.Windows.Forms.Application]::DoEvents()
                        Start-Sleep -Milliseconds 100
                    } catch { }
                    
                    # Перемещаем форму за пределы экрана
                    try {
                        $Global:ProgressForm.Location = New-Object System.Drawing.Point(-10000, -10000)
                        [System.Windows.Forms.Application]::DoEvents()
                        Start-Sleep -Milliseconds 50
                    } catch { }
                    
                    # Устанавливаем размер 0x0
                    try {
                        $Global:ProgressForm.Size = New-Object System.Drawing.Size(0, 0)
                        [System.Windows.Forms.Application]::DoEvents()
                        Start-Sleep -Milliseconds 50
                    } catch { }
                    
                    $Global:ProgressForm.Refresh()
                    $Global:ProgressForm.Update()
                    for ($i = 0; $i -lt 10; $i++) {
                        [System.Windows.Forms.Application]::DoEvents()
                    }
                } catch {
                    # Игнорируем ошибки при обновлении
                }
                
                # Скрываем форму перед закрытием
                if ($Global:ProgressForm.Visible) {
                    # Write-ToOutput "[DEBUG] Hide-ProgressBar: Устанавливаем Visible = false" ([System.Drawing.Color]::Cyan)
                    # [System.Windows.Forms.Application]::DoEvents()
                    $Global:ProgressForm.Visible = $false
                    # Множественные вызовы DoEvents() для гарантированного обновления
                    for ($i = 0; $i -lt 20; $i++) {
                        [System.Windows.Forms.Application]::DoEvents()
                    }
                    Start-Sleep -Milliseconds 200
                    # Write-ToOutput "[DEBUG] Hide-ProgressBar: Visible установлен в false, Visible = $($Global:ProgressForm.Visible)" ([System.Drawing.Color]::Cyan)
                    # [System.Windows.Forms.Application]::DoEvents()
                }
                
                # Многократный вызов Hide() для гарантированного скрытия
                # Write-ToOutput "[DEBUG] Hide-ProgressBar: Вызываем Hide()" ([System.Drawing.Color]::Cyan)
                # [System.Windows.Forms.Application]::DoEvents()
                for ($hideAttempt = 0; $hideAttempt -lt 3; $hideAttempt++) {
                    try {
                        $Global:ProgressForm.Hide()
                        [System.Windows.Forms.Application]::DoEvents()
                        Start-Sleep -Milliseconds 50
                    } catch { }
                }
                # Множественные вызовы DoEvents() для гарантированного обновления
                for ($i = 0; $i -lt 20; $i++) {
                    [System.Windows.Forms.Application]::DoEvents()
                }
                Start-Sleep -Milliseconds 200
                # Write-ToOutput "[DEBUG] Hide-ProgressBar: Hide() выполнен, Visible = $($Global:ProgressForm.Visible)" ([System.Drawing.Color]::Cyan)
                # [System.Windows.Forms.Application]::DoEvents()
                
                # Write-ToOutput "[DEBUG] Hide-ProgressBar: Вызываем Close()" ([System.Drawing.Color]::Cyan)
                # [System.Windows.Forms.Application]::DoEvents()
                $Global:ProgressForm.Close()
                # Множественные вызовы DoEvents() для гарантированного обновления
                for ($i = 0; $i -lt 30; $i++) {
                    [System.Windows.Forms.Application]::DoEvents()
                }
                Start-Sleep -Milliseconds 300
                # Write-ToOutput "[DEBUG] Hide-ProgressBar: Close() выполнен, IsDisposed = $($Global:ProgressForm.IsDisposed)" ([System.Drawing.Color]::Cyan)
                # [System.Windows.Forms.Application]::DoEvents()
                
                # Write-ToOutput "[DEBUG] Hide-ProgressBar: Вызываем Dispose()" ([System.Drawing.Color]::Cyan)
                # [System.Windows.Forms.Application]::DoEvents()
                
                $Global:ProgressForm.Dispose()
                # Множественные вызовы DoEvents() для гарантированного обновления
                for ($i = 0; $i -lt 30; $i++) {
                    [System.Windows.Forms.Application]::DoEvents()
                }
                Start-Sleep -Milliseconds 300
                # Write-ToOutput "[DEBUG] Hide-ProgressBar: Dispose() выполнен" ([System.Drawing.Color]::Cyan)
                # [System.Windows.Forms.Application]::DoEvents()
                
                # Финальная активация главной формы после закрытия прогресс-бара
                if ($Global:MainForm -ne $null -and -not $Global:MainForm.IsDisposed) {
                    try {
                        # Многократная активация главной формы для гарантированного переключения фокуса
                        for ($activateAttempt = 0; $activateAttempt -lt 3; $activateAttempt++) {
                            $Global:MainForm.BringToFront()
                            $Global:MainForm.Activate()
                            $Global:MainForm.Focus()
                            [System.Windows.Forms.Application]::DoEvents()
                            Start-Sleep -Milliseconds 50
                        }
                        $Global:MainForm.Invalidate()
                        $Global:MainForm.Refresh()
                        $Global:MainForm.Update()
                        for ($i = 0; $i -lt 20; $i++) {
                            [System.Windows.Forms.Application]::DoEvents()
                        }
                        Start-Sleep -Milliseconds 100
                    } catch {
                        # Игнорируем ошибки
                    }
                }
            } else {
                # Write-ToOutput "[DEBUG] Hide-ProgressBar: Форма уже disposed" ([System.Drawing.Color]::Cyan)
                # [System.Windows.Forms.Application]::DoEvents()
            }
            
            # Write-ToOutput "[DEBUG] Hide-ProgressBar: Очищаем переменные" ([System.Drawing.Color]::Cyan)
            # [System.Windows.Forms.Application]::DoEvents()
            $Global:ProgressForm = $null
            $Global:ProgressBar = $null
            $Global:ProgressLabel = $null
            # Множественные вызовы DoEvents() для гарантированного обновления
            for ($i = 0; $i -lt 10; $i++) {
                [System.Windows.Forms.Application]::DoEvents()
            }
            # Write-ToOutput "[DEBUG] Hide-ProgressBar: Переменные очищены" ([System.Drawing.Color]::Cyan)
            # [System.Windows.Forms.Application]::DoEvents()
        } catch {
            # Write-ToOutput "[DEBUG] Hide-ProgressBar: ОШИБКА при закрытии: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
            # [System.Windows.Forms.Application]::DoEvents()
            # Write-ToOutput "[DEBUG] Hide-ProgressBar: StackTrace: $($_.ScriptStackTrace)" ([System.Drawing.Color]::Red)
            # [System.Windows.Forms.Application]::DoEvents()
            # Игнорируем ошибки при закрытии
            $Global:ProgressForm = $null
            $Global:ProgressBar = $null
            $Global:ProgressLabel = $null
            $Global:ProgressTimer = $null
            # Write-ToOutput "[DEBUG] Hide-ProgressBar: Переменные очищены после ошибки" ([System.Drawing.Color]::Cyan)
            # [System.Windows.Forms.Application]::DoEvents()
        }
    } else {
        # Write-ToOutput "[DEBUG] Hide-ProgressBar: ProgressForm уже null" ([System.Drawing.Color]::Cyan)
        # [System.Windows.Forms.Application]::DoEvents()
    }
    # Write-ToOutput "[DEBUG] Hide-ProgressBar: Конец выполнения" ([System.Drawing.Color]::Cyan)
    [System.Windows.Forms.Application]::DoEvents()
}

# Функция для запуска таймера анимации прогресс-бара
function Start-ProgressBarAnimation {
    # Проверяем, что прогресс-бар виден перед запуском таймера
    if ($Global:ProgressForm -eq $null -or -not $Global:ProgressForm.Visible) {
        return
    }
    
    # Останавливаем существующий таймер, если он есть
    if ($Global:ProgressTimer -ne $null) {
        $Global:ProgressTimer.Stop()
        $Global:ProgressTimer.Dispose()
        $Global:ProgressTimer = $null
    }
    
    # Создаем новый таймер
    $Global:ProgressTimer = New-Object System.Windows.Forms.Timer
    $Global:ProgressTimer.Interval = 20  # Уменьшен интервал до 20 мс для более плавной анимации
    $Global:ProgressTimer.Add_Tick({
        if ($Global:ProgressForm -ne $null -and $Global:ProgressForm.Visible) {
            # Принудительно обновляем прогресс-бар для анимации Marquee
            if ($Global:ProgressBar -ne $null) {
                # Убеждаемся, что прогресс-бар в режиме Marquee
                if ($Global:ProgressBar.Style -ne "Marquee") {
                    $Global:ProgressBar.Style = "Marquee"
                }
                # Устанавливаем скорость анимации
                $Global:ProgressBar.MarqueeAnimationSpeed = 50
                # Принудительно обновляем прогресс-бар и форму
                $Global:ProgressBar.Update()
                $Global:ProgressForm.Update()
            }
            # Множественные вызовы DoEvents() для обеспечения отзывчивости
            [System.Windows.Forms.Application]::DoEvents()
            [System.Windows.Forms.Application]::DoEvents()
        } else {
            # Если форма закрыта, останавливаем таймер
            if ($Global:ProgressTimer -ne $null) {
                $Global:ProgressTimer.Stop()
            }
        }
    })
    $Global:ProgressTimer.Start()
}

# Функция для остановки таймера анимации прогресс-бара
function Stop-ProgressBarAnimation {
    if ($Global:ProgressTimer -ne $null) {
        $Global:ProgressTimer.Stop()
        $Global:ProgressTimer.Dispose()
        $Global:ProgressTimer = $null
    }
}

# Функция для анимированного прогресс-бара во время длительной операции
function Start-AnimatedProgressBar {
    param(
        [string]$Status = "Выполнение операции..."
    )
    
    # Убеждаемся, что прогресс-бар отображается с анимацией Marquee
    if ($Global:ProgressForm -ne $null -and $Global:ProgressForm.Visible) {
        $Global:ProgressBar.Style = "Marquee"
        $Global:ProgressBar.MarqueeAnimationSpeed = 50
        if ($Status) {
            $Global:ProgressLabel.Text = $Status
        }
        [System.Windows.Forms.Application]::DoEvents()
    }
}

# Функция создания прогресс-бара для детального отображения удаления папки
function Show-FolderDeletionProgressBar {
    # Write-Host "[DEBUG] Show-FolderDeletionProgressBar: Начало создания формы" -ForegroundColor Cyan
    
    $Global:FolderDeletionProgressForm = New-Object System.Windows.Forms.Form
    $Global:FolderDeletionProgressForm.Text = "Прогресс удаления папки"
    $Global:FolderDeletionProgressForm.Size = New-Object System.Drawing.Size(500, 120)
    $Global:FolderDeletionProgressForm.StartPosition = "CenterScreen"
    $Global:FolderDeletionProgressForm.FormBorderStyle = "FixedDialog"
    $Global:FolderDeletionProgressForm.MaximizeBox = $false
    $Global:FolderDeletionProgressForm.MinimizeBox = $false
    $Global:FolderDeletionProgressForm.ShowInTaskbar = $true
    $Global:FolderDeletionProgressForm.TopMost = $true
    
    # Write-Host "[DEBUG] Show-FolderDeletionProgressBar: Форма создана" -ForegroundColor Cyan
    
    $Global:FolderDeletionProgressBar = New-Object System.Windows.Forms.ProgressBar
    $Global:FolderDeletionProgressBar.Location = New-Object System.Drawing.Point(10, 10)
    $Global:FolderDeletionProgressBar.Size = New-Object System.Drawing.Size(480, 30)
    $Global:FolderDeletionProgressBar.Style = "Continuous"
    $Global:FolderDeletionProgressBar.Minimum = 0
    $Global:FolderDeletionProgressBar.Maximum = 100
    $Global:FolderDeletionProgressBar.Value = 0
    $Global:FolderDeletionProgressForm.Controls.Add($Global:FolderDeletionProgressBar)
    
    # Write-Host "[DEBUG] Show-FolderDeletionProgressBar: Прогресс-бар создан и добавлен" -ForegroundColor Cyan
    
    $Global:FolderDeletionProgressLabel = New-Object System.Windows.Forms.Label
    $Global:FolderDeletionProgressLabel.Text = "Подготовка к удалению..."
    $Global:FolderDeletionProgressLabel.Location = New-Object System.Drawing.Point(10, 50)
    $Global:FolderDeletionProgressLabel.Size = New-Object System.Drawing.Size(480, 30)
    $Global:FolderDeletionProgressLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9)
    $Global:FolderDeletionProgressForm.Controls.Add($Global:FolderDeletionProgressLabel)
    
    # Write-Host "[DEBUG] Show-FolderDeletionProgressBar: Метка создана и добавлена" -ForegroundColor Cyan
    
    # Показываем окно модально, но не блокируя основной поток
    # Write-Host "[DEBUG] Show-FolderDeletionProgressBar: Проверка MainForm (null = $($Global:MainForm -eq $null))" -ForegroundColor Cyan
    if ($Global:MainForm -ne $null) {
        # Write-Host "[DEBUG] Show-FolderDeletionProgressBar: Показываем форму с родителем MainForm" -ForegroundColor Green
        $Global:FolderDeletionProgressForm.Show($Global:MainForm)
    } else {
        # Write-Host "[DEBUG] Show-FolderDeletionProgressBar: Показываем форму без родителя" -ForegroundColor Yellow
        $Global:FolderDeletionProgressForm.Show()
    }
    # Write-Host "[DEBUG] Show-FolderDeletionProgressBar: Форма показана, Visible = $($Global:FolderDeletionProgressForm.Visible)" -ForegroundColor Cyan
    
    $Global:FolderDeletionProgressForm.BringToFront()
    $Global:FolderDeletionProgressForm.Activate()
    [System.Windows.Forms.Application]::DoEvents()
    
    # Write-Host "[DEBUG] Show-FolderDeletionProgressBar: Форма активирована, Visible = $($Global:FolderDeletionProgressForm.Visible)" -ForegroundColor Green
}

# Функция обновления прогресс-бара для удаления папки
function Update-FolderDeletionProgressBar {
    param(
        [int]$DeletedFiles = 0,
        [int]$TotalFiles = 0,
        [double]$DeletedMB = 0,
        [double]$TotalMB = 0
    )
    
    # Write-Host "[DEBUG] Update-FolderDeletionProgressBar: DeletedFiles=$DeletedFiles, TotalFiles=$TotalFiles, DeletedMB=$DeletedMB, TotalMB=$TotalMB" -ForegroundColor Cyan
    # Write-Host "[DEBUG] Update-FolderDeletionProgressBar: Form null = $($Global:FolderDeletionProgressForm -eq $null), Visible = $($Global:FolderDeletionProgressForm.Visible)" -ForegroundColor Cyan
    
    if ($Global:FolderDeletionProgressForm -ne $null -and $Global:FolderDeletionProgressForm.Visible) {
        if ($TotalFiles -gt 0) {
            $percentComplete = [math]::Round(($DeletedFiles / $TotalFiles) * 100)
            $Global:FolderDeletionProgressBar.Value = [math]::Min($percentComplete, 100)
            $statusText = "Удалено {0} из {1} файлов; {2} из {3} Mb" -f $DeletedFiles, $TotalFiles, [math]::Round($DeletedMB, 0), [math]::Round($TotalMB, 0)
            $Global:FolderDeletionProgressLabel.Text = $statusText
            # Write-Host "[DEBUG] Update-FolderDeletionProgressBar: Обновлено - $statusText, Progress = $percentComplete%" -ForegroundColor Green
        } else {
            $Global:FolderDeletionProgressBar.Value = 0
            $Global:FolderDeletionProgressLabel.Text = "Подготовка к удалению..."
            # Write-Host "[DEBUG] Update-FolderDeletionProgressBar: Установлены начальные значения" -ForegroundColor Yellow
        }
        
        # Принудительное обновление всех элементов формы
        $Global:FolderDeletionProgressBar.Refresh()
        $Global:FolderDeletionProgressLabel.Refresh()
        $Global:FolderDeletionProgressForm.Refresh()
        $Global:FolderDeletionProgressBar.Update()
        $Global:FolderDeletionProgressLabel.Update()
        $Global:FolderDeletionProgressForm.Update()
        
        # Множественные вызовы DoEvents() для обработки всех событий UI
        for ($i = 0; $i -lt 5; $i++) {
            [System.Windows.Forms.Application]::DoEvents()
        }
    } else {
        # Write-Host "[DEBUG] Update-FolderDeletionProgressBar: Форма не видна или null, обновление пропущено" -ForegroundColor Yellow
    }
}

# Функция закрытия прогресс-бара для удаления папки
function Hide-FolderDeletionProgressBar {
    # Write-Host "[DEBUG] Hide-FolderDeletionProgressBar: Начало закрытия формы" -ForegroundColor Cyan
    if ($Global:FolderDeletionProgressForm -ne $null) {
        # Write-Host "[DEBUG] Hide-FolderDeletionProgressBar: Форма существует, закрываем..." -ForegroundColor Green
        $Global:FolderDeletionProgressForm.Close()
        $Global:FolderDeletionProgressForm.Dispose()
        $Global:FolderDeletionProgressForm = $null
        $Global:FolderDeletionProgressBar = $null
        $Global:FolderDeletionProgressLabel = $null
        # Write-Host "[DEBUG] Hide-FolderDeletionProgressBar: Форма закрыта" -ForegroundColor Green
    } else {
        # Write-Host "[DEBUG] Hide-FolderDeletionProgressBar: Форма уже null, закрывать нечего" -ForegroundColor Yellow
    }
}

# Переопределение Write-Host для вывода в GUI
function Write-Host {
    param(
        [string]$Object,
        [System.ConsoleColor]$ForegroundColor = [System.ConsoleColor]::White,
        [switch]$NoNewline
    )
    
    $colorMap = @{
        'Black' = [System.Drawing.Color]::Black
        'DarkBlue' = [System.Drawing.Color]::DarkBlue
        'DarkGreen' = [System.Drawing.Color]::DarkGreen
        'DarkCyan' = [System.Drawing.Color]::DarkCyan
        'DarkRed' = [System.Drawing.Color]::DarkRed
        'DarkMagenta' = [System.Drawing.Color]::DarkMagenta
        'DarkYellow' = [System.Drawing.Color]::DarkYellow
        'Gray' = [System.Drawing.Color]::Gray
        'DarkGray' = [System.Drawing.Color]::DarkGray
        'Blue' = [System.Drawing.Color]::Blue
        'Green' = [System.Drawing.Color]::Green
        'Cyan' = [System.Drawing.Color]::Cyan
        'Red' = [System.Drawing.Color]::Red
        'Magenta' = [System.Drawing.Color]::Magenta
        'Yellow' = [System.Drawing.Color]::Yellow
        'White' = [System.Drawing.Color]::White
    }
    
    $guiColor = if ($colorMap.ContainsKey($ForegroundColor.ToString())) {
        $colorMap[$ForegroundColor.ToString()]
    } else {
        [System.Drawing.Color]::White
    }
    
    if ($NoNewline) {
        Write-ToOutput $Object $guiColor
    } else {
        Write-ToOutput $Object $guiColor
    }
}

# |========================================|
# |     Функции 1С:Предприятие 8           |
# |========================================|
# | 1. Информация о COM-объекте            |
# | 2. Информация о версиях платформы      |
# | 3. Информация о службе                 |
# | 4. Работа со службой                   |
# | 5. Работа с COM-объектом               |
# | 6. Удаление активных сессий            |
# | 7. Удаление временных файлов           |
# | 8. Удаление сервера                    |
# | 9. Установка сервера                   |
# |========================================|

# Функция 1. Информация о COM-объекте (исправлена для вывода в GUI)
function Get-ComObject1C {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $Server
	)

	# Проверяем, является ли сервер локальным
	$isLocal = Test-IsLocalServer -ServerName $Server
	
	# Скрипт-блок с логикой выполнения
	$scriptBlock = {
		$result = @()
		
		# Функция для получения версии COM-компоненты из реестра
		function Get-ComComponentVersion {
			param([string]$ProgId)
			
			try {
				# Получаем CLSID из ProgID
				$progIdPath = "Registry::HKEY_CLASSES_ROOT\$ProgId\CLSID"
				if (Test-Path $progIdPath) {
					$clsid = (Get-ItemProperty -Path $progIdPath -Name "(default)" -ErrorAction SilentlyContinue).'(default)'
					if ($clsid) {
						# Получаем путь к DLL из InprocServer32
						$inprocPath = "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid\InprocServer32"
						if (Test-Path $inprocPath) {
							$dllPath = (Get-ItemProperty -Path $inprocPath -Name "(default)" -ErrorAction SilentlyContinue).'(default)'
							if ($dllPath -and (Test-Path $dllPath)) {
								# Извлекаем версию из пути (например, C:\Program Files\1cv8\8.3.27.1859\Bin\comcntr.dll)
								if ($dllPath -match '\\(8\.\d+\.\d+\.\d+)\\') {
									return $matches[1]
								}
								# Если не удалось извлечь из пути, пробуем получить версию файла
								$fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dllPath).FileVersion
								if ($fileVersion) {
									return $fileVersion
								}
							}
						}
					}
				}
			}
			catch {
				# Игнорируем ошибки при чтении реестра
			}
			return $null
		}
		
		try {
			$v82COMConnector = New-Object -COMObject "V82.COMConnector"
			Start-Sleep -Milliseconds 500
			$v82Version = Get-ComComponentVersion -ProgId "V82.COMConnector"
			if ($v82Version) {
				$result += "Компонента V82.COMConnector Зарегистрирована (версия: $v82Version)|Green"
			} else {
				$result += "Компонента V82.COMConnector Зарегистрирована|Green"
			}
		}
		# Ошибка.
		catch {
			Start-Sleep -Milliseconds 500
			$result += "Компонента V82.COMConnector Не зарегистрирована|Red"
		}

		try {
			$v83COMConnector = New-Object -COMObject "V83.COMConnector"
			Start-Sleep -Milliseconds 500
			$v83Version = Get-ComComponentVersion -ProgId "V83.COMConnector"
			if ($v83Version) {
				$result += "Компонента V83.COMConnector Зарегистрирована (версия: $v83Version)|Green"
			} else {
				$result += "Компонента V83.COMConnector Зарегистрирована|Green"
			}
		}
		# Ошибка.
		catch {
			Start-Sleep -Milliseconds 500
			$result += "Компонента V83.COMConnector Не зарегистрирована|Red"
		}
		
		return $result
	}
	
	# Выполняем локально или удалённо в зависимости от результата проверки
	if ($isLocal) {
		# Локальное выполнение - вызываем скрипт-блок напрямую
		$output = & $scriptBlock
	} else {
		# Удалённое выполнение через Invoke-Command
		$output = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlock
	}
	
	# Вывод результатов в GUI
	foreach ($line in $output) {
		if ([string]::IsNullOrEmpty($line)) {
			Write-ToOutput "" ([System.Drawing.Color]::Black)
		} else {
			$parts = $line -split '\|', 2
			$text = $parts[0]
			$colorName = if ($parts.Length -gt 1) { $parts[1] } else { "White" }
			
			$color = switch ($colorName) {
				"Green" { [System.Drawing.Color]::Green }
				"Red" { [System.Drawing.Color]::Red }
				"Yellow" { [System.Drawing.Color]::Yellow }
				"Cyan" { [System.Drawing.Color]::Cyan }
				"Gray" { [System.Drawing.Color]::Gray }
				"Magenta" { [System.Drawing.Color]::Magenta }
				default { [System.Drawing.Color]::White }
			}
			
			Write-ToOutput $text $color
		}
	}
	
	Clear-Variable -Name "Server"
}

# Функция 2. Информация о версиях платформы (исправлена для вывода в GUI)
function Get-Platform1C() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $Server
	)

	# Проверяем, является ли сервер локальным
	$isLocal = Test-IsLocalServer -ServerName $Server
	
	# Скрипт-блок с логикой выполнения
	$scriptBlock = {
		$result = @()
		$ArrayInstalledPlatform1C = [System.Collections.ArrayList]@()

		if (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {($_.DisplayName -like "*1С:Предприятие*") -or ($_.DisplayName -like "*1С:Enterprise*")}) {
			Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
				Where-Object {($_.DisplayName -like "*1С:Предприятие*") -or ($_.DisplayName -like "*1С:Enterprise*")} |
				Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
				ForEach-Object {
					$ArrayInstalledPlatform1C.Add(
						[PSCustomObject] @{
							' DisplayName'     = " $($_.DisplayName)"
							' DisplayVersion'  = " $($_.DisplayVersion)"
							' Publisher'       = " $($_.Publisher)"
							' InstallDate'     = " $($_.InstallDate)"
							' InstallLocation' = " $($_.InstallLocation)"
						}
					) | Out-Null
				}
			# Форматируем таблицу в строки для вывода
			$formattedTable = $ArrayInstalledPlatform1C | Format-Table -AutoSize | Out-String
			$result += $formattedTable
			$ArrayInstalledPlatform1C.Clear()
		}
		elseif (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {($_.DisplayName -like "*1С:Предприятие*") -or ($_.DisplayName -like "*1С:Enterprise*")}) {
			    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
				Where-Object {($_.DisplayName -like "*1С:Предприятие*") -or ($_.DisplayName -like "*1С:Enterprise*")} |
				Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
				ForEach-Object {
					$ArrayInstalledPlatform1C.Add(
						[PSCustomObject] @{
							' DisplayName'     = " $($_.DisplayName)"
							' DisplayVersion'  = " $($_.DisplayVersion)"
							' Publisher'       = " $($_.Publisher)"
							' InstallDate'     = " $($_.InstallDate)"
							' InstallLocation' = " $($_.InstallLocation)"
						}
					) | Out-Null
				}
			$formattedTable = $ArrayInstalledPlatform1C | Format-Table -AutoSize | Out-String
			$result += $formattedTable
			$ArrayInstalledPlatform1C.Clear()
		}
		else {
			$result += ""
			$result += "Не установлен продукт 1С:Предприятие 8|Yellow"
		}
		
		return $result
	}
	
	# Выполняем локально или удалённо в зависимости от результата проверки
	if ($isLocal) {
		# Локальное выполнение - вызываем скрипт-блок напрямую
		$output = & $scriptBlock
	} else {
		# Удалённое выполнение через Invoke-Command
		$output = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlock
	}
	
	# Вывод результатов в GUI
	foreach ($line in $output) {
		if ([string]::IsNullOrEmpty($line)) {
			Write-ToOutput "" ([System.Drawing.Color]::Black)
		} else {
			$parts = $line -split '\|', 2
			$text = $parts[0]
			$colorName = if ($parts.Length -gt 1) { $parts[1] } else { "White" }
			
			$color = switch ($colorName) {
				"Green" { [System.Drawing.Color]::Green }
				"Red" { [System.Drawing.Color]::Red }
				"Yellow" { [System.Drawing.Color]::Yellow }
				"Cyan" { [System.Drawing.Color]::Cyan }
				"Gray" { [System.Drawing.Color]::Gray }
				"Magenta" { [System.Drawing.Color]::Magenta }
				default { [System.Drawing.Color]::White }
			}
			
			Write-ToOutput $text $color
		}
	}
	
	Clear-Variable -Name "Server"
}

# Функция 3. Информация о службе (исправлена для вывода в GUI)
function Get-Service1C() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $Server
	)

	# Проверяем, является ли сервер локальным
	$isLocal = Test-IsLocalServer -ServerName $Server
	# Подавляем вывод булева значения в консоль
	$null = $isLocal

	# Скрипт-блок с логикой получения информации о службах
	$scriptBlock = {
		$result = @()
		
		$services1C = Get-WmiObject win32_service | Where-Object {$_.Name -like '*'} |
			Select Name, DisplayName, State, PathName | Where-Object {$_.PathName -Like "*ragent.exe*"}

		if ($services1C) {
			$obj = [PSCustomObject] @{
				data = @($services1C | % {
					$serviceInfo = $_
					# Исправляем двойной слеш в PathName
					$fixedPathName = $serviceInfo.PathName -replace '\\\\', '\'
					[PSCustomObject] @{
						' Name'        = $serviceInfo.Name
						' State'       = $serviceInfo.State
						' DisplayName' = $serviceInfo.DisplayName
						' PathName'    = $fixedPathName
					}
				})
			}
			$formattedList = $obj.data | Format-List | Out-String -Width 4096
			$result += $formattedList
		}
		else {
			$result += "Не установлена служба 1С:Предприятие 8|Yellow"
		}
		
		return $result
	}
	
	# Выполняем локально или удалённо в зависимости от результата проверки
	if ($isLocal) {
		# Локальное выполнение - вызываем скрипт-блок напрямую
		$output = & $scriptBlock
	} else {
		# Удалённое выполнение через Invoke-Command
		$output = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlock
	}
	
	# Вывод результатов в GUI
	foreach ($line in $output) {
		if ([string]::IsNullOrEmpty($line)) {
			Write-ToOutput "" ([System.Drawing.Color]::Black)
		} else {
			$parts = $line -split '\|', 2
			$text = $parts[0]
			$colorName = if ($parts.Length -gt 1) { $parts[1] } else { "White" }
			
			$color = switch ($colorName) {
				"Green" { [System.Drawing.Color]::Green }
				"Red" { [System.Drawing.Color]::Red }
				"Yellow" { [System.Drawing.Color]::Yellow }
				"Cyan" { [System.Drawing.Color]::Cyan }
				"Gray" { [System.Drawing.Color]::Gray }
				"Magenta" { [System.Drawing.Color]::Magenta }
				default { [System.Drawing.Color]::White }
			}
			
			Write-ToOutput $text $color
		}
	}
	
	Clear-Variable -Name "Server"
}

# Функция 4. Работа со службой (модифицирована для работы с GUI диалогами)
function Job-Service1C() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $Server
	)

	# Проверяем, является ли сервер локальным
	$isLocal = Test-IsLocalServer -ServerName $Server
	# Подавляем вывод булева значения в консоль
	$null = $isLocal
	
	# Получаем список служб локально или удалённо
	$scriptBlockGetServices = {
		$result = @()
		if (Get-Service | Where-Object {($_.Name).StartsWith("1C")}) {
			# Получаем службы напрямую в массив строк, без использования ArrayList
			$GetServices = Get-Service | Where-Object {($_.Name).StartsWith("1C")}
			foreach ($Service in $GetServices) {
				if ($Service.Name -notlike $null) {
					# Добавляем каждый элемент напрямую в результат как строку
					$result += $Service.Name.ToString()
				}
			}
			# Добавляем маркер успешного выполнения
			if ($result.Count -gt 0) {
				$result += "OK"
			} else {
				$result = @("NO_SERVICES")
			}
		} else {
			$result += "NO_SERVICES"
		}
		return $result
	}
	
	# Выполняем локально или удалённо в зависимости от результата проверки
	if ($isLocal) {
		# Локальное выполнение - вызываем скрипт-блок напрямую
		$servicesResult = & $scriptBlockGetServices
	} else {
		# Удалённое выполнение через Invoke-Command
		$servicesResult = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlockGetServices
	}
	
	# Обрабатываем результат - используем foreach для правильного извлечения элементов
	$ArrayServices1C = @()
	$hasNoServices = $false
	foreach ($item in $servicesResult) {
		if ($item -eq "NO_SERVICES") {
			$hasNoServices = $true
			break
		}
		if ($item -ne "OK" -and $item -ne "NO_SERVICES") {
			# Явно преобразуем каждый элемент в строку
			$serviceStr = $item.ToString()
			$ArrayServices1C += $serviceStr
		}
	}
	
	if ($hasNoServices -or $ArrayServices1C.Count -eq 0) {
		Write-ToOutput "Не установлена служба 1С:Предприятие 8" ([System.Drawing.Color]::Yellow)
		return
	}
	
	# Диалог выбора службы
	$serviceItems = @()
	for ($i = 0; $i -lt $ArrayServices1C.Count; $i++) {
		$serviceItems += "$($i+1). $($ArrayServices1C[$i])"
	}
	
	$selectedServiceIndex = Show-SelectionDialog -Title "Выбор службы" -Prompt "Выберите службу:" -Items $serviceItems -CancelText "Отмена"
	
	if ($null -eq $selectedServiceIndex) {
		Write-ToOutputColored "[ОШИБКА] Выбор службы прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	
	$NameService1C = $ArrayServices1C[$selectedServiceIndex - 1]
	
	# Диалог выбора действия
	$actionItems = @("1. Запуск службы", "2. Остановка службы", "3. Перезапуск службы")
	$selectedAction = Show-SelectionDialog -Title "Действие со службой" -Prompt "Служба: $NameService1C`n`nВыберите действие" -Items $actionItems -CancelText "Отмена"
	
	if ($null -eq $selectedAction) {
		Write-ToOutputColored "[ОШИБКА] Выбор действия со службой прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	
	# Определяем текст статуса для прогресс-бара в зависимости от выбранного действия
	$actionStatusText = switch ($selectedAction) {
		1 { "Запуск службы $NameService1C..." }
		2 { "Остановка службы $NameService1C..." }
		3 { "Перезапуск службы $NameService1C..." }
		default { "Выполнение действия со службой..." }
	}
	
	# Скрипт-блок для выполнения действия со службой
	$scriptBlockServiceAction = {
		param($ServiceName, $Action)
		
		$result = @()
		$Service1C = Get-Service -Name $ServiceName -ErrorAction Stop
		
		try {
			if ($Action -eq 1) {
				# Запуск службы
				$CheckService1C = Get-Service -Name $Service1C.Name -ErrorAction Stop
				if ($CheckService1C.Status -like "Stopped") {
					Start-Service -Name $Service1C.Name -ErrorAction Stop
					Start-Sleep -Seconds 5
					$GetStatus1C = Get-Service -Name $Service1C.Name -ErrorAction Stop
					if ($GetStatus1C.Status -like "Running") {
						$result += "Служба: $($Service1C.Name) Запущена|Green"
					}
				} else {
					$result += "Служба: $($Service1C.Name) Запущена|Green"
				}
			}
			elseif ($Action -eq 2) {
				# Остановка службы
				$CheckService1C = Get-Service -Name $Service1C.Name -ErrorAction Stop
				if ($CheckService1C.Status -like "Running") {
					Stop-Service -Name $Service1C.Name -Force -ErrorAction Stop -WarningAction SilentlyContinue
					Start-Sleep -Seconds 5
					$GetStatus1C = Get-Service -Name $Service1C.Name -ErrorAction Stop
					if ($GetStatus1C.Status -like "Stopped") {
						$result += "Служба: $($Service1C.Name) Остановлена|Red"
					}
				} else {
					$result += "Служба: $($Service1C.Name) Остановлена|Red"
				}
			}
			elseif ($Action -eq 3) {
				# Перезапуск службы
				$CheckService1C = Get-Service -Name $Service1C.Name -ErrorAction Stop
				if ($CheckService1C.Status -like "Running") {
					Restart-Service -Name $Service1C.Name -Force -ErrorAction Stop -WarningAction SilentlyContinue
					Start-Sleep -Seconds 5
					$GetStatus1C = Get-Service -Name $Service1C.Name -ErrorAction Stop
					if ($GetStatus1C.Status -like "Running") {
						$result += "Служба: $($Service1C.Name) Перезапущена|Green"
					}
				}
				elseif ($CheckService1C.Status -like "Stopped") {
					Start-Service -Name $Service1C.Name -ErrorAction Stop
					Start-Sleep -Seconds 5
					$GetStatus1C = Get-Service -Name $Service1C.Name -ErrorAction Stop
					if ($GetStatus1C.Status -like "Running") {
						$result += "Служба: $($Service1C.Name) Перезапущена|Green"
					}
				}
			}
		}
		catch {
			$result += "[ОШИБКА] $($_.Exception.Message)|Red"
		}
		
		return $result
	}
	
	# Показываем прогресс-бар перед выполнением действия
	Show-ProgressBar -Title "Работа со службой" -Status $actionStatusText
	
	# Убеждаемся, что прогресс-бар в режиме анимации Marquee и таймер запущен
	if ($Global:ProgressBar -ne $null) {
		$Global:ProgressBar.Style = "Marquee"
		$Global:ProgressBar.MarqueeAnimationSpeed = 50
		# Принудительно обновляем прогресс-бар и форму для немедленного отображения
		$Global:ProgressBar.Update()
		$Global:ProgressForm.Update()
		# Множественные вызовы DoEvents() для обработки всех событий
		for ($i = 0; $i -lt 10; $i++) {
			[System.Windows.Forms.Application]::DoEvents()
		}
	}
	# Запускаем таймер для плавной анимации
	Start-ProgressBarAnimation
	# Дополнительное обновление UI после запуска таймера для немедленного старта анимации
	for ($i = 0; $i -lt 10; $i++) {
		[System.Windows.Forms.Application]::DoEvents()
	}
	
	try {
		# Обновляем статус перед выполнением
		Update-ProgressBar -Status "$actionStatusText Ожидание..."
		
		# Запускаем действие в фоновом Job для возможности обновления UI
		if ($isLocal) {
			# Локальное выполнение - используем Start-Job
			$serviceJob = Start-Job -ScriptBlock $scriptBlockServiceAction -ArgumentList $NameService1C, $selectedAction
		} else {
			# Удалённое выполнение через Invoke-Command -AsJob
			$serviceJob = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlockServiceAction -ArgumentList $NameService1C, $selectedAction -AsJob
		}
		
		# Ждем завершения Job с активным обновлением UI для анимации
		# Используем очень короткие задержки и множественные вызовы DoEvents()
		# для обеспечения плавной анимации прогресс-бара
		while ($serviceJob.State -eq "Running" -or $serviceJob.State -eq "Blocked") {
			# Принудительно обновляем прогресс-бар для анимации Marquee
			if ($Global:ProgressBar -ne $null -and $Global:ProgressForm.Visible) {
				# Убеждаемся, что прогресс-бар в режиме Marquee
				if ($Global:ProgressBar.Style -ne "Marquee") {
					$Global:ProgressBar.Style = "Marquee"
				}
				$Global:ProgressBar.MarqueeAnimationSpeed = 50
				# Принудительно обновляем прогресс-бар и форму
				$Global:ProgressBar.Refresh()  # Используем Refresh вместо Update для более агрессивного обновления
				$Global:ProgressForm.Refresh()
			}
			# Множественные вызовы DoEvents() для обработки всех событий UI
			# Это критически важно для работы анимации Marquee
			for ($i = 0; $i -lt 10; $i++) {
				[System.Windows.Forms.Application]::DoEvents()
			}
			# БЕЗ задержки - это позволяет максимально быстро обновлять UI
		}
		
		# Останавливаем таймер анимации после завершения операции
		Stop-ProgressBarAnimation
		
		# Получаем результат после завершения Job
		$output = Receive-Job -Job $serviceJob -ErrorAction SilentlyContinue
		
		# Получаем ошибки из Job через свойство Error
		$jobErrors = $null
		try {
			if ($serviceJob.HasMoreData) {
				$jobErrors = Receive-Job -Job $serviceJob -ErrorStream -ErrorAction SilentlyContinue
			}
		}
		catch {
			# Игнорируем ошибки при получении ошибок из Job
		}
		
		# Проверяем состояние Job
		if ($serviceJob.State -eq "Failed") {
			$errorMessage = "Job не завершился корректно. Состояние: $($serviceJob.State)"
			if ($jobErrors) {
				$errorMessage += ". Ошибки: $($jobErrors -join ', ')"
			}
			throw New-Object System.Exception($errorMessage)
		}
		
		# Удаляем Job после получения результата
		Remove-Job -Job $serviceJob -Force -ErrorAction SilentlyContinue
		
		# Обновляем статус прогресс-бара перед выводом результатов
		Update-ProgressBar -Status "Операция завершена успешно!" -PercentComplete 100
		[System.Windows.Forms.Application]::DoEvents()
		Start-Sleep -Milliseconds 500
	}
	catch {
		Stop-ProgressBarAnimation
		Write-ToOutputColored "[ОШИБКА] $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		Update-ProgressBar -Status "[ОШИБКА] $($_.Exception.Message)"
		[System.Windows.Forms.Application]::DoEvents()
		Start-Sleep -Milliseconds 1000
	}
	finally {
		# Убеждаемся, что таймер остановлен
		Stop-ProgressBarAnimation
		# Скрываем прогресс-бар после завершения операции
		Hide-ProgressBar
	}
	
	# Вывод результатов в GUI с обработкой маркеров [OK] и [ОШИБКА]
	if ($output) {
		Write-OutputResults -OutputLines $output
	}
	
	Clear-Variable -Name "Server"
}

# Функция 5. Работа с COM-объектом (модифицирована для работы с GUI диалогами)
function Job-ComObject1C() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $Server
	)

	# Проверяем, является ли сервер локальным
	$isLocal = Test-IsLocalServer -ServerName $Server
	# Подавляем вывод булева значения в консоль
	$null = $isLocal
	
	# Скрипт-блок для получения списка служб
	$scriptBlockGetServices = {
		$result = @()
		if (Get-Service -ErrorAction Stop | Where-Object {($_.Name).StartsWith("1C")}) {
			# Получаем службы напрямую в массив строк, без использования ArrayList
			$GetServices = Get-Service -ErrorAction Stop | Where-Object {($_.Name).StartsWith("1C")}
			foreach ($Service in $GetServices) {
				if ($Service.Name -notlike $null) {
					# Добавляем каждый элемент напрямую в результат как строку
					$result += $Service.Name.ToString()
				}
			}
			# Добавляем маркер успешного выполнения
			if ($result.Count -gt 0) {
				$result += "OK"
			} else {
				$result = @("NO_SERVICES")
			}
		} else {
			$result += "NO_SERVICES"
		}
		return $result
	}
	
	# Выполняем локально или удалённо в зависимости от результата проверки
	if ($isLocal) {
		# Локальное выполнение - вызываем скрипт-блок напрямую
		$servicesResult = & $scriptBlockGetServices
	} else {
		# Удалённое выполнение через Invoke-Command
		$servicesResult = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlockGetServices
	}
	
	# Обрабатываем результат - используем foreach для правильного извлечения элементов
	$ArrayServices1C = @()
	$hasNoServices = $false
	foreach ($item in $servicesResult) {
		if ($item -eq "NO_SERVICES") {
			$hasNoServices = $true
			break
		}
		if ($item -ne "OK" -and $item -ne "NO_SERVICES") {
			# Явно преобразуем каждый элемент в строку
			$serviceStr = $item.ToString()
			$ArrayServices1C += $serviceStr
		}
	}
	
	if ($hasNoServices -or $ArrayServices1C.Count -eq 0) {
		Write-ToOutput "Не установлена служба 1С:Предприятие 8" ([System.Drawing.Color]::Yellow)
		return
	}
	
	# Если служб несколько, показываем диалог выбора
	$NameService1C = $null
	if ($ArrayServices1C.Count -eq 1) {
		# Если служба одна, используем её
		$NameService1C = $ArrayServices1C[0]
	} else {
		# Если служб несколько, показываем диалог выбора
		$serviceItems = @()
		for ($i = 0; $i -lt $ArrayServices1C.Count; $i++) {
			$serviceItems += "$($i+1). $($ArrayServices1C[$i])"
		}
		
		$selectedServiceIndex = Show-SelectionDialog -Title "Выбор службы" -Prompt "Выберите службу для работы с COM-объектом" -Items $serviceItems -CancelText "Отмена"
		
		if ($null -eq $selectedServiceIndex) {
			Write-ToOutputColored "[ОШИБКА] Выбор службы прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			return
		}
		
		$NameService1C = $ArrayServices1C[$selectedServiceIndex - 1]
	}
	
	# Получаем информацию о выбранной службе
	$scriptBlockGetServiceInfo = {
		param($ServiceName)
		
		$result = @{}
		try {
			$NameService1C = Get-Service -Name $ServiceName -ErrorAction Stop
			$Service1C = Get-WmiObject win32_service | Where-Object {$_.Name -like $NameService1C.Name} | Select-Object Name, DisplayName, State, PathName | Where-Object {$_.PathName -Like "*ragent.exe*"}
			
			if ($Service1C) {
				$ServiceExecPath = $Service1C.PathName
				$ServiceExecPathRagent = $Service1C.PathName.split('"')[1]
				$ServiceDirectory = [System.IO.Path]::GetDirectoryName($ServiceExecPathRagent)
				$ComCntrPath = "$ServiceDirectory\comcntr.dll"
				$PlatformVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ServiceExecPathRagent).FileVersion
				
				$result["Name"] = $NameService1C.Name
				$result["PlatformVersion"] = $PlatformVersion
				$result["ComCntrPath"] = $ComCntrPath
				$result["Status"] = "OK"
			} else {
				$result["Status"] = "NO_SERVICE"
			}
		}
		catch {
			$result["Status"] = "ERROR"
			$result["ErrorMessage"] = $_.Exception.Message
		}
		
		return $result
	}
	
	# Выполняем получение информации о службе локально или удалённо
	if ($isLocal) {
		# Локальное выполнение - вызываем скрипт-блок напрямую
		$serviceInfo = & $scriptBlockGetServiceInfo -ServiceName $NameService1C
	} else {
		# Удалённое выполнение через Invoke-Command
		$serviceInfo = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlockGetServiceInfo -ArgumentList $NameService1C
	}
	
	if ($serviceInfo["Status"] -ne "OK") {
		if ($serviceInfo["Status"] -eq "ERROR") {
			Write-ToOutputColored "[ОШИБКА] Ошибка при получении информации о службе: $($serviceInfo['ErrorMessage'])" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		} else {
			Write-ToOutput "Не установлена служба 1С:Предприятие 8" ([System.Drawing.Color]::Yellow)
		}
		return
	}
	
	$PlatformVersion = $serviceInfo["PlatformVersion"]
	$ComCntrPath = $serviceInfo["ComCntrPath"]
	
	# Диалог выбора действия
	$actionItems = @("1. Регистрация", "2. Отмена регистрации")
	$prompt = "Компонента: $NameService1C`nВерсия платформы: $PlatformVersion`nПуть к DLL: `"$ComCntrPath`"`n`nВыберите действие:"
	$selectedAction = Show-SelectionDialog -Title "Работа с COM-объектом" -Prompt $prompt -Items $actionItems -CancelText "Отмена"
	
	if ($null -eq $selectedAction) {
		Write-ToOutputColored "[ОШИБКА] Выбор действия с COM-объектом прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	
	# Определяем текст статуса для прогресс-бара в зависимости от выбранного действия
	$actionStatusText = switch ($selectedAction) {
		1 { "Регистрация COM-компоненты $NameService1C..." }
		2 { "Отмена регистрации COM-компоненты $NameService1C..." }
		default { "Выполнение действия с COM-объектом..." }
	}
	
	# Скрипт-блок для выполнения действия с COM-объектом
	$scriptBlockComAction = {
		param($ComCntrPath, $Action, $PlatformVersion)
		
		$result = @()
		
		try {
			if ($Action -eq 1) {
				# Регистрация COM-объекта
				$result += "Начало регистрации COM-компоненты 1С:Предприятия|White"
				$result += "Версия платформы: $PlatformVersion|White"
				$result += "Путь к DLL: `"$ComCntrPath`"|White"
				$result += "Команда регистрации компоненты: regsvr32.exe /s $ComCntrPath|White"
				
				$process = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s `"$ComCntrPath`"" -Wait -PassThru -NoNewWindow
				if ($process.ExitCode -eq 0) {
					$result += "Компонента Зарегистрирована|Green"
				} else {
					$result += "[ОШИБКА] Компонента не зарегистрирована|Red"
				}
			}
			elseif ($Action -eq 2) {
				# Отмена регистрации COM-объекта
				$result += "Начало отмены регистрации COM-компоненты 1С:Предприятия|White"
				$result += "Версия платформы: $PlatformVersion|White"
				$result += "Путь к DLL: `"$ComCntrPath`"|White"
				$result += "Команда отмены регистрации компоненты: regsvr32.exe /u /s $ComCntrPath|White"
				
				$process = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/u /s `"$ComCntrPath`"" -Wait -PassThru -NoNewWindow
				if ($process.ExitCode -eq 0) {
					$result += "Регистрация компоненты Отменена|Red"
				} else {
					$result += "[ОШИБКА] Ошибка при отмене регистрации компоненты|Red"
				}
			}
		}
		catch {
			$result += "[ОШИБКА] $($_.Exception.Message)|Red"
		}
		
		return $result
	}
	
	# Показываем прогресс-бар перед выполнением действия
	Show-ProgressBar -Title "Работа с COM-объектом" -Status $actionStatusText
	
	# Убеждаемся, что прогресс-бар в режиме анимации Marquee и таймер запущен
	if ($Global:ProgressBar -ne $null) {
		$Global:ProgressBar.Style = "Marquee"
		$Global:ProgressBar.MarqueeAnimationSpeed = 50
		# Принудительно обновляем прогресс-бар и форму для немедленного отображения
		$Global:ProgressBar.Update()
		$Global:ProgressForm.Update()
		# Множественные вызовы DoEvents() для обработки всех событий
		for ($i = 0; $i -lt 10; $i++) {
			[System.Windows.Forms.Application]::DoEvents()
		}
	}
	# Запускаем таймер для плавной анимации
	Start-ProgressBarAnimation
	# Дополнительное обновление UI после запуска таймера для немедленного старта анимации
	for ($i = 0; $i -lt 10; $i++) {
		[System.Windows.Forms.Application]::DoEvents()
	}
	
	try {
		# Обновляем статус перед выполнением
		Update-ProgressBar -Status "$actionStatusText Ожидание..."
		
		# Запускаем действие в фоновом Job для возможности обновления UI
		if ($isLocal) {
			# Локальное выполнение - используем Start-Job
			$comJob = Start-Job -ScriptBlock $scriptBlockComAction -ArgumentList $ComCntrPath, $selectedAction, $PlatformVersion
		} else {
			# Удалённое выполнение через Invoke-Command -AsJob
			$comJob = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlockComAction -ArgumentList $ComCntrPath, $selectedAction, $PlatformVersion -AsJob
		}
		
		# Ждем завершения Job с активным обновлением UI для анимации
		# Используем очень короткие задержки и множественные вызовы DoEvents()
		# для обеспечения плавной анимации прогресс-бара
		while ($comJob.State -eq "Running" -or $comJob.State -eq "Blocked") {
			# Принудительно обновляем прогресс-бар для анимации Marquee
			if ($Global:ProgressBar -ne $null -and $Global:ProgressForm.Visible) {
				# Убеждаемся, что прогресс-бар в режиме Marquee
				if ($Global:ProgressBar.Style -ne "Marquee") {
					$Global:ProgressBar.Style = "Marquee"
				}
				$Global:ProgressBar.MarqueeAnimationSpeed = 50
				# Принудительно обновляем прогресс-бар и форму
				$Global:ProgressBar.Refresh()  # Используем Refresh вместо Update для более агрессивного обновления
				$Global:ProgressForm.Refresh()
			}
			# Множественные вызовы DoEvents() для обработки всех событий UI
			# Это критически важно для работы анимации Marquee
			for ($i = 0; $i -lt 10; $i++) {
				[System.Windows.Forms.Application]::DoEvents()
			}
			# БЕЗ задержки - это позволяет максимально быстро обновлять UI
		}
		
		# Останавливаем таймер анимации после завершения операции
		Stop-ProgressBarAnimation
		
		# Получаем результат после завершения Job
		$output = Receive-Job -Job $comJob -ErrorAction SilentlyContinue
		
		# Получаем ошибки из Job через свойство Error
		$jobErrors = $null
		try {
			if ($comJob.HasMoreData) {
				$jobErrors = Receive-Job -Job $comJob -ErrorStream -ErrorAction SilentlyContinue
			}
		}
		catch {
			# Игнорируем ошибки при получении ошибок из Job
		}
		
		# Проверяем состояние Job
		if ($comJob.State -eq "Failed") {
			$errorMessage = "Job не завершился корректно. Состояние: $($comJob.State)"
			if ($jobErrors) {
				$errorMessage += ". Ошибки: $($jobErrors -join ', ')"
			}
			throw New-Object System.Exception($errorMessage)
		}
		
		# Удаляем Job после получения результата
		Remove-Job -Job $comJob -Force -ErrorAction SilentlyContinue
		
		# Обновляем статус прогресс-бара перед выводом результатов
		Update-ProgressBar -Status "Операция завершена успешно!" -PercentComplete 100
		[System.Windows.Forms.Application]::DoEvents()
		Start-Sleep -Milliseconds 500
	}
	catch {
		Stop-ProgressBarAnimation
		Write-ToOutputColored "[ОШИБКА] $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		Update-ProgressBar -Status "[ОШИБКА] $($_.Exception.Message)"
		[System.Windows.Forms.Application]::DoEvents()
		Start-Sleep -Milliseconds 1000
	}
	finally {
		# Убеждаемся, что таймер остановлен
		Stop-ProgressBarAnimation
		# Скрываем прогресс-бар после завершения операции
		Hide-ProgressBar
	}
	
	# Вывод результатов в GUI с обработкой маркеров [OK] и [ОШИБКА]
	if ($output) {
		Write-OutputResults -OutputLines $output
	}
	
	Clear-Variable -Name "Server"
}

# Функция 6. Удаление активных сессий (модифицирована для работы с GUI диалогами)
# Эта функция очень сложная и требует множества диалогов
# Встроена полностью из основного скрипта с модификациями для GUI
function Disactivate-Session1C() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $Server
	)

	# Проверяем, является ли сервер локальным
	$isLocal = Test-IsLocalServer -ServerName $Server
	$null = $isLocal

	# Проверяем наличие службы локально или удалённо
	$scriptBlockHasService = {
		return (Get-Service | Where-Object {($_.Name).StartsWith("1C")}) -ne $null
	}
	if ($isLocal) {
		$hasService = & $scriptBlockHasService
	} else {
		$hasService = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlockHasService
	}
	
	if (-not $hasService) {
		Write-ToOutput "Не установлена служба 1С:Предприятие 8" ([System.Drawing.Color]::Yellow)
		return
	}
	
	# Диалог выбора компоненты
	$componentItems = @("1. V82.COMConnector", "2. V83.COMConnector")
	$selectedComponent = Show-SelectionDialog -Title "Выбор компоненты" -Prompt "Выберите компоненту 1С" -Items $componentItems -CancelText "Отмена"
	
	if ($null -eq $selectedComponent) {
		Write-ToOutputColored "[ОШИБКА] Выбор компоненты прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	
	$componentName = if ($selectedComponent -eq 1) { "V82.COMConnector" } else { "V83.COMConnector" }
	
	# Диалог ввода порта
	# Ввод порта с проверкой на пустое значение
	$portInput = $null
	do {
		$portInput = Show-InputDialog -Title "Ввод порта" -Prompt "Введите порт сервера:`nПример: 1740" -DefaultValue "" -CancelText "Отмена"
		
		# Если нажата кнопка "Отмена", выходим из функции
		if ($null -eq $portInput) {
			Write-ToOutputColored "[ОШИБКА] Ввод порта прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			return
		}
		
		# Если введено пустое значение, показываем ошибку и продолжаем цикл
		if ($portInput -eq "") {
			Write-ToOutputColored "[ОШИБКА] Не введено значение порта. Пожалуйста, введите порт." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		}
	} while ($portInput -eq "")
	
	[int]$port = 0
	if (-not [int]::TryParse($portInput, [ref]$port)) {
		Write-ToOutputColored "[ОШИБКА] Неверно указан порт" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	
	# Папка для лога: при локальной работе — папка скрипта, при удалённой — на сервере (потом копируем в папку скрипта)
	$sessionLogFolder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
	$sessionLogDest = Join-Path $sessionLogFolder "log-1C.txt"

	# Копирование лога в папку скрипта и вывод сообщения (при отмене или по завершении)
	$copyOrReportSessionLog = {
		if ($isLocal) {
			if (Test-Path $sessionLogDest -ErrorAction SilentlyContinue) {
				Write-ToOutputColored "[OK] Создан лог: $sessionLogDest" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
			}
		} else {
			$sessionLogSource = "\\$Server\C$\Users\Администратор\Documents\log-1C.txt"
			if (Test-Path $sessionLogSource -ErrorAction SilentlyContinue) {
				try {
					Copy-Item -Path $sessionLogSource -Destination $sessionLogDest -Force
					Start-Sleep -Seconds 1
					if (Test-Path $sessionLogDest -ErrorAction SilentlyContinue) {
						Remove-Item -Path $sessionLogSource -Force -ErrorAction SilentlyContinue
						Write-ToOutputColored "[OK] Создан лог: $sessionLogDest" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
					}
				} catch { }
			}
		}
	}

	# Скрипт-блок получения информации о кластере и сессиях
	$scriptBlockGetClusterInfo = {
		param([string]$Server1CName, [string]$ComponentName, [int]$Port, [string]$LogRoot)
		
		$result = @()
		if ($LogRoot) {
			$PathLogFile = Join-Path $LogRoot "log-1C.txt"
			$logDir = Split-Path $PathLogFile -Parent
			if (-not (Test-Path $logDir)) { [void](New-Item -Path $logDir -ItemType Directory -Force) }
			if (-not (Test-Path $PathLogFile)) { [void](New-Item -Path $PathLogFile -ItemType File -Force) }
		} else {
			$PathLogFile = "C:\Users\Администратор\Documents\log-1C.txt"
			if (-Not (Test-Path $PathLogFile)) {
				[void](New-Item -Path "C:\Users\Администратор\Documents\" -Name "log-1C.txt" -ItemType File)
			}
		}
		
		[string]$InputServer1С = $Server1CName.ToUpper()
		
		if ($InputServer1С -like $env:COMPUTERNAME) {
			try {
				# Создаём COM-объект
				$Connector = New-Object -Comobject $ComponentName
				if ($Connector) {
					$result += "[OK] Создание COM-объекта|Green"
					
					# Проверка порта и подключение
					if (Get-NetTCPConnection | Where-Object {$_.Localport -eq $Port}) {
						$Server1C = $InputServer1С + ":" + $Port
						$AgentConnection = $Connector.ConnectAgent($Server1C)
						
						if ($AgentConnection) {
							$result += "[OK] Подключение к агенту сервера|Green"
							
							# Получаем кластер и базы
							$Cluster = $AgentConnection.GetClusters()[0]
							$AgentConnection.Authenticate($Cluster, "", "")
							$Bases = $AgentConnection.GetInfoBases($Cluster)
							
							if ($Bases.count -ne 0) {
								$GetDate = (Get-Date).ToString()
								$result += "DATE:$GetDate|White"
								Add-Content -Path $PathLogFile -Value ("[$InputServer1С][$GetDate]")
								
								$TimeDelay = 0
								$Sessions1C = ($AgentConnection.GetSessions($Cluster) | Where-Object {$_.AppId -ne "SrvrConsole" -and $_.AppId -ne "BackgroundJob"})
								
								$result += "Активные сеансы в кластере 1С|Cyan"
								$IntUsersCount = 0
								foreach ($Session1С in $Sessions1C) {
									$userName = $Session1С.userName.ToString()
									$baseName = $Session1С.infoBase.Name.ToString()
									$result += "SESSION:$userName;$baseName"
									$AllSession = "Active Session '" + $userName + " - " + $baseName
									Add-Content -Path $PathLogFile -Value ($AllSession) -Encoding UTF8
									$IntUsersCount++
								}
								
								$result += "COUNT:$IntUsersCount|White"
								$result += "BASES:" + (($Bases | ForEach-Object { $_.Name }) -join ";") + "|White"
								$result += "CLUSTER_READY|OK"
							} else {
								$result += "NO_SESSIONS|Yellow"
							}
						} else {
							$result += "ERROR: Не удалось подключиться к агенту|Red"
						}
					} else {
						$result += "ERROR: Порт $Port не верный|Red"
					}
				} else {
					$result += "ERROR: Компонента $ComponentName не зарегистрирована|Red"
				}
			}
			catch {
				$result += "ERROR: $($_.Exception.Message)|Red"
			}
		} else {
			$result += "ERROR: Имя сервера 1С $InputServer1С не соответствует имени сервера для отправки скрипт-блока|Red"
		}
		
		return $result
	}
	
	# Выполняем получение информации о кластере локально или удалённо (при локальном запуске передаём имя компьютера и папку лога)
	$serverNameForBlock = if ($isLocal) { $env:COMPUTERNAME } else { $Server }
	$logRootForBlock = if ($isLocal) { $sessionLogFolder } else { $null }
	if ($isLocal) {
		$output = & $scriptBlockGetClusterInfo -Server1CName $serverNameForBlock -ComponentName $componentName -Port $port -LogRoot $logRootForBlock
	} else {
		$output = Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $Server, $componentName, $port, $logRootForBlock -ScriptBlock $scriptBlockGetClusterInfo
	}
	
	# Обрабатываем результаты
	$clusterReady = $false
	$sessionCount = 0
	$availableBases = @()
	$currentDate = ""
	$sessionList = [System.Collections.ArrayList]@()
	
	foreach ($line in $output) {
		if ($line -match "^COUNT:(.+)$") {
			# Извлекаем только число (до |), чтобы избежать ошибки преобразования "31|White" в Int32
			$sessionCount = [int]($matches[1] -replace '\|.*$', '')
		}
		elseif ($line -match "^BASES:(.+)$") {
			# До первого | — список баз через ";", после | — цвет
			$basesPart = $matches[1] -replace '\|.*$', ''
			$availableBases = $basesPart -split ';'
		}
		elseif ($line -match "^DATE:(.+)$") {
			$currentDate = $matches[1] -replace '\|.*$', ''
		}
		elseif ($line -eq "CLUSTER_READY|OK") {
			$clusterReady = $true
		}
		elseif ($line -eq "NO_SESSIONS|Yellow") {
			Write-ToOutput "Активных сессий нет" ([System.Drawing.Color]::Yellow)
			return
		}
		elseif ($line -match "^SESSION:(.+)$") {
			# Формат: SESSION:Пользователь;База
			$sessionPart = $matches[1]
			$sessionParts = $sessionPart -split ';', 2
			$sessionNum = $sessionList.Count + 1
			$userName = if ($sessionParts.Length -ge 1) { $sessionParts[0] } else { "" }
			$baseName = if ($sessionParts.Length -ge 2) { $sessionParts[1] } else { "" }
			[void]$sessionList.Add([PSCustomObject]@{
				Сессия     = $sessionNum
				Пользователь = $userName
				База       = $baseName
			})
		}
		else {
			$parts = $line -split '\|', 2
			$text = $parts[0]
			$colorName = if ($parts.Length -gt 1) { $parts[1] } else { "White" }
			
			# Строки "[OK] ..." — маркер [OK] зелёным, остальное белым
			if ($text -match '^\[OK\]\s') {
				Write-ToOutputColored $text "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
			} else {
				$color = switch ($colorName) {
					"Green" { [System.Drawing.Color]::Green }
					"Red" { [System.Drawing.Color]::Red }
					"Yellow" { [System.Drawing.Color]::Yellow }
					"Cyan" { [System.Drawing.Color]::Cyan }
					"Gray" { [System.Drawing.Color]::Gray }
					"Magenta" { [System.Drawing.Color]::Magenta }
					default { [System.Drawing.Color]::White }
				}
				Write-ToOutput $text $color
			}
		}
	}
	
	# Вывод таблицы сессий (Сессия, Пользователь, База)
	if ($sessionList.Count -gt 0) {
		$sessionTable = $sessionList | Format-Table -Property Сессия, Пользователь, База -AutoSize | Out-String
		foreach ($tableLine in ($sessionTable -split "`r?`n")) {
			if (-not [string]::IsNullOrWhiteSpace($tableLine)) {
				Write-ToOutput $tableLine ([System.Drawing.Color]::White)
			}
		}
		Write-ToOutput "" ([System.Drawing.Color]::White)
	}
	
	if (-not $clusterReady) {
		return
	}
	
	# Диалог выбора действия (Modeless — можно переключиться на окно вывода и просмотреть список сессий)
	$actionItems = @("1. Из определённых баз", "2. Все сеансы")
	$actionPrompt = "Отключить все активные сеансы или из определённых баз 1С?`n`nНайдено активных сессий: $sessionCount"
	$selectedAction = Show-SelectionDialog -Title "Выбор действия" -Prompt $actionPrompt -Items $actionItems -CancelText "Отмена" -Modeless
	
	if ($null -eq $selectedAction) {
		Write-ToOutputColored "[ОШИБКА] Выбор действия для удаления сессий прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		& $copyOrReportSessionLog
		return
	}
	
	$basesToProcess = @()
	
	if ($selectedAction -eq 1) {
		# Из определённых баз — диалог выбора баз по CheckBox
		$basesToProcess = Show-BasesCheckBoxDialog -Title "Выбор баз данных" -Prompt "Отметьте базы, из которых нужно удалить сессии:" -AvailableBases $availableBases
		
		if ($null -eq $basesToProcess -or $basesToProcess.Count -eq 0) {
			Write-ToOutputColored "[ОШИБКА] Ввод баз данных прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			& $copyOrReportSessionLog
			return
		}
	} else {
		# Все сеансы - используем все доступные базы
		$basesToProcess = $availableBases
	}
	
	# Скрипт-блок завершения сессий
	$scriptBlockTerminateSessions = {
		param([string]$Server1CName, [string]$ComponentName, [int]$Port, [array]$BasesList, [bool]$AllSessions, [string]$LogRoot)
		
		$result = @()
		if ($LogRoot) {
			$PathLogFile = Join-Path $LogRoot "log-1C.txt"
		} else {
			$PathLogFile = "C:\Users\Администратор\Documents\log-1C.txt"
		}
		[string]$InputServer1С = $Server1CName.ToUpper()
		
		try {
			$Connector = New-Object -Comobject $ComponentName
			$Server1C = $InputServer1С + ":" + $Port
			$AgentConnection = $Connector.ConnectAgent($Server1C)
			$Cluster = $AgentConnection.GetClusters()[0]
			$AgentConnection.Authenticate($Cluster, "", "")
			
			$TimeDelay = 0
			$Bases = $AgentConnection.GetInfoBases($Cluster)
			
			if ($AllSessions) {
				foreach ($BaseAll in $Bases) {
					$Base = $BaseAll.Name
					$Sessions1CtoTerminate = ($AgentConnection.GetSessions($Cluster) | Where-Object {$_.Infobase.Name -eq $Base -and $_.AppId -ne "SrvrConsole" -and $_.AppId -ne "BackgroundJob" -and $_.StartedAt -lt ((Get-Date).AddHours($TimeDelay))})
					
					foreach ($Session in $Sessions1CtoTerminate) {
						$sessionMsg = "Terminated Session $($Session.infoBase.Name.ToString()) $($Session.userName.ToString()) $($Session.Host.ToString()) $($Session.AppID.ToString()) $($Session.StartedAt.ToString()) - $($Session.LastActiveAt.ToString()) has been terminated at $(Get-Date).ToString()|Red"
						$result += $sessionMsg
						
						$SessionToKillMsg = "Terminated Session '" + $Session.infoBase.Name.ToString() + " - " + $Session.userName.ToString() + " - " + $Session.Host.ToString() + " - " + $Session.AppID.ToString() + " - " + $Session.StartedAt.ToString() + " - " + $Session.LastActiveAt.ToString() + "' has been terminated at "  + "[" + (Get-Date).ToString("yyyy.MM.dd hh:mm:ss") + "]"
						Add-Content -Path $PathLogFile -Value ($SessionToKillMsg) -Encoding UTF8
						
						$AgentConnection.TerminateSession($Cluster, $Session)
					}
				}
			} else {
				foreach ($Base in $BasesList) {
					$Sessions1CtoTerminate = ($AgentConnection.GetSessions($Cluster) | Where-Object {$_.Infobase.Name -eq $Base -and $_.AppId -ne "SrvrConsole" -and $_.AppId -ne "BackgroundJob" -and $_.StartedAt -lt ((Get-Date).AddHours($TimeDelay))})
					
					foreach ($Session in $Sessions1CtoTerminate) {
						$sessionMsg = "Terminated Session $($Session.infoBase.Name.ToString()) $($Session.userName.ToString()) $($Session.Host.ToString()) $($Session.AppID.ToString()) $($Session.StartedAt.ToString()) - $($Session.LastActiveAt.ToString()) has been terminated at $(Get-Date).ToString()|Red"
						$result += $sessionMsg
						
						$SessionToKillMsg = "Terminated Session '" + $Session.infoBase.Name.ToString() + " - " + $Session.userName.ToString() + " - " + $Session.Host.ToString() + " - " + $Session.AppID.ToString() + " - " + $Session.StartedAt.ToString() + " - " + $Session.LastActiveAt.ToString() + "' has been terminated at " + "[" + (Get-Date).ToString("yyyy.MM.dd hh:mm:ss") + "]"
						Add-Content -Path $PathLogFile -Value ($SessionToKillMsg) -Encoding UTF8
						
						$AgentConnection.TerminateSession($Cluster, $Session)
					}
				}
			}
			
			$result += "LOG_FILE:$PathLogFile|White"
		}
		catch {
			$result += "ERROR: $($_.Exception.Message)|Red"
		}
		
		return $result
	}
	
	# Выполняем удаление сессий локально или удалённо (при локальном запуске используем имя компьютера и папку лога)
	if ($isLocal) {
		$terminationOutput = & $scriptBlockTerminateSessions -Server1CName $serverNameForBlock -ComponentName $componentName -Port $port -BasesList $basesToProcess -AllSessions ($selectedAction -eq 2) -LogRoot $sessionLogFolder
	} else {
		$terminationOutput = Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $Server, $componentName, $port, $basesToProcess, ($selectedAction -eq 2), $null -ScriptBlock $scriptBlockTerminateSessions
	}
	
	# Вывод результатов удаления
	$logFilePath = ""
	foreach ($line in $terminationOutput) {
		if ($line -match "^LOG_FILE:(.+)$") {
			$logFilePath = $matches[1] -replace '\|.*$', ''
		}
		else {
			$parts = $line -split '\|', 2
			$text = $parts[0]
			$colorName = if ($parts.Length -gt 1) { $parts[1] } else { "White" }
			
			# Формат: [OK] База: base | Пользователь: user | Узел: HOST | Статус: Terminated
			if ($text -match '^Terminated Session (\S+) (\S+) (\S+) ') {
				$baseName = $matches[1]
				$userName = $matches[2]
				$hostName = $matches[3].ToUpper()
				Write-ToOutputSegments -Segments @(
					[PSCustomObject]@{ Text = "[OK]"; Color = [System.Drawing.Color]::Green },
					[PSCustomObject]@{ Text = " База:"; Color = [System.Drawing.Color]::White },
					[PSCustomObject]@{ Text = " $baseName"; Color = [System.Drawing.Color]::Gray },
					[PSCustomObject]@{ Text = " |"; Color = [System.Drawing.Color]::Yellow },
					[PSCustomObject]@{ Text = " Пользователь:"; Color = [System.Drawing.Color]::White },
					[PSCustomObject]@{ Text = " $userName"; Color = [System.Drawing.Color]::Gray },
					[PSCustomObject]@{ Text = " |"; Color = [System.Drawing.Color]::Yellow },
					[PSCustomObject]@{ Text = " Узел:"; Color = [System.Drawing.Color]::White },
					[PSCustomObject]@{ Text = " $hostName"; Color = [System.Drawing.Color]::Gray },
					[PSCustomObject]@{ Text = " |"; Color = [System.Drawing.Color]::Yellow },
					[PSCustomObject]@{ Text = " Статус:"; Color = [System.Drawing.Color]::White },
					[PSCustomObject]@{ Text = " Terminated "; Color = [System.Drawing.Color]::Red }
				)
			} else {
				$color = switch ($colorName) {
					"Green" { [System.Drawing.Color]::Green }
					"Red" { [System.Drawing.Color]::Red }
					"Yellow" { [System.Drawing.Color]::Yellow }
					"Cyan" { [System.Drawing.Color]::Cyan }
					"Gray" { [System.Drawing.Color]::Gray }
					"Magenta" { [System.Drawing.Color]::Magenta }
					default { [System.Drawing.Color]::White }
				}
				Write-ToOutput $text $color
			}
		}
	}
	
	# Копирование лога в папку скрипта и вывод сообщения (по завершении функции)
	& $copyOrReportSessionLog

	Clear-Variable -Name "Server"
}

# Функция 7. Удаление временных файлов (модифицирована для работы с GUI диалогами)
function Remove-TempFiles1C() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $Server
	)

	# DEBUG: Проверяем, что функция вызывается
	# Write-ToOutput "[DEBUG] Remove-TempFiles1C: ФУНКЦИЯ НАЧАЛА ВЫПОЛНЕНИЕ! Server = $Server" ([System.Drawing.Color]::Cyan)
	# [System.Windows.Forms.Application]::DoEvents()
	
	# Проверяем, является ли сервер локальным
	$isLocal = Test-IsLocalServer -ServerName $Server
	# Write-ToOutput "[DEBUG] Remove-TempFiles1C: isLocal = $isLocal" ([System.Drawing.Color]::Cyan)
	# [System.Windows.Forms.Application]::DoEvents()
	# Подавляем вывод булева значения в консоль
	$null = $isLocal

	# Скрипт-блок для получения списка версий (полная версия 8.3.xx.xxxx из пути или реестра); возвращаем плоский массив строк, чтобы не было ArrayList при Invoke-Command
	$scriptBlockGetVersions = {
		$result = @()
		if (Get-Service -ErrorAction Stop | Where-Object {($_.Name).StartsWith("1C")}) {
			Get-Package | Where-Object {($_.Name -match "1С:Предприятие 8") -and ($_.Source -notmatch "(x86)")} | ForEach-Object {
				$versionString = $null
				# 1) Полная версия из пути установки (например, C:\Program Files\1cv8\8.3.27.1859)
				if ($_.Source -match '\\(8\.\d+\.\d+\.\d+)(?:\\|$)') {
					$versionString = $matches[1]
				}
				# 2) Запасной вариант: DisplayVersion из реестра по пути установки этого пакета
				if (-not $versionString) {
					$pkgSource = $_.Source
					$displayVer = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { ($_.DisplayName -like "*1С:Предприятие*" -or $_.DisplayName -like "*1С:Enterprise*") -and $_.InstallLocation -and ($pkgSource -like "*$($_.InstallLocation)*" -or $_.InstallLocation -like "*$pkgSource*") } | Select-Object -First 1).DisplayVersion
					if ($displayVer -and $displayVer -match '^8\.\d+\.\d+\.\d+') { $versionString = $displayVer }
				}
				# 3) Иначе из объекта Version (может быть укорочен при сериализации, например "1.8")
				if (-not $versionString) { $versionString = $_.Version.ToString() }
				if ($versionString -and $versionString -match '^8\.\d+\.\d+\.\d+') {
					$result += $versionString
				} elseif ($versionString) {
					$result += $versionString
				}
			}
			$result += "OK"
			return $result
		} else {
			return @("NO_SERVICES")
		}
	}

	# Получаем список версий локально или удалённо в зависимости от результата проверки
	if ($isLocal) {
		# Локальное выполнение - вызываем скрипт-блок напрямую
		$versionsResult = & $scriptBlockGetVersions
	} else {
		# Удалённое выполнение через Invoke-Command
		$versionsResult = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlockGetVersions
	}
	
	# Обрабатываем результат: разворачиваем массив/ArrayList в плоский список строк версий (полная версия 8.3.xx.xxxx)
	$ArrayPackage1C = @()
	$versionItems = @()
	$itemsToProcess = @()
	if ($null -ne $versionsResult) {
		if ($versionsResult -is [System.Collections.IEnumerable] -and $versionsResult -isnot [string]) {
			foreach ($item in $versionsResult) {
				if ($item -is [System.Collections.IEnumerable] -and $item -isnot [string]) {
					foreach ($sub in $item) { $itemsToProcess += $sub }
				} else {
					$itemsToProcess += $item
				}
			}
		} else {
			$itemsToProcess += $versionsResult
		}
	}
	foreach ($item in $itemsToProcess) {
		$str = if ($null -eq $item) { "" } else { $item.ToString() }
		if ($str -eq "NO_SERVICES") {
			Write-ToOutput "Не установлена служба 1С:Предприятие 8" ([System.Drawing.Color]::Yellow)
			return
		}
		if ($str -and $str -ne "OK") {
			$ArrayPackage1C += $str
			$versionItems += "$($ArrayPackage1C.Count). $str"
		}
	}
	
	if ($ArrayPackage1C.Count -eq 0) {
		Write-ToOutput "Не найдено установленных версий 1С:Предприятие 8" ([System.Drawing.Color]::Yellow)
		return
	}
	
	$selectedVersionIndex = Show-SelectionDialog -Title "Выбор версии" -Prompt "Выберите версию" -Items $versionItems -CancelText "Отмена"
	
	if ($null -eq $selectedVersionIndex) {
		Write-ToOutputColored "[ОШИБКА] Выбор версии для удаления прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	
	$selectedVersion = $ArrayPackage1C[$selectedVersionIndex - 1]
	
	# Скрипт-блок для получения информации о папке с временными файлами
	$scriptBlockGetTempFolderInfo = {
		param([string]$PackageVersion)
		
		$result = @{}
		
		try {
			$Package = $PackageVersion
			$PackageSource = (Get-Package | Where-Object {($_.Name -match "1С:Предприятие 8") -and ($_.Source -notmatch "(x86)") -and ($_.Source -match $Package)}).Source
			$ServiceName = (Get-WmiObject win32_service | Where-Object {$_.PathName -Like "*$PackageSource*"}).Name
			[string]$ServicePathName = (Get-WmiObject win32_service | Where-Object {$_.Name -Like "*$ServiceName*"}).PathName
			$PathName = $ServicePathName.Split('"')[3]
			[string]$RegPort = $ServicePathName.Split('"').Split(" ")[7]
			
			$tempFolderPath = $null
			if (Test-Path "$($PathName)\reg_$($RegPort)" -ErrorAction SilentlyContinue) {
				$GetFolderCash1C = (Get-ChildItem "$($PathName)\reg_$($RegPort)").Name
				if ($GetFolderCash1C -match "snccntx") {
					$tmpFolderCash1C = (Get-ChildItem "$($PathName)\reg_$($RegPort)").Name
					foreach ($tmpName in $tmpFolderCash1C) {
						if ($tmpName.StartsWith("snccntx")) {
							$tempFolderPath = "$($PathName)\reg_$($RegPort)\$($tmpName)"
							break
						}
					}
				}
			}
			
			if ($tempFolderPath -and (Test-Path $tempFolderPath -ErrorAction SilentlyContinue)) {
				$result["TempFolderPath"] = $tempFolderPath
				$result["ServiceName"] = $ServiceName
				$result["Status"] = "OK"
			} else {
				$result["Status"] = "NO_FOLDER"
			}
		}
		catch {
			$result["Status"] = "ERROR"
			$result["ErrorMessage"] = $_.Exception.Message
		}
		
		return $result
	}
	
	# Получаем информацию о папке с временными файлами
	if ($isLocal) {
		$tempFolderInfo = & $scriptBlockGetTempFolderInfo -PackageVersion $selectedVersion
	} else {
		$tempFolderInfo = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlockGetTempFolderInfo -ArgumentList $selectedVersion
	}
	
	if ($tempFolderInfo["Status"] -ne "OK") {
		if ($tempFolderInfo["Status"] -eq "NO_FOLDER") {
			Write-ToOutput "Папка с временными файлами платформы $selectedVersion отсутствует" ([System.Drawing.Color]::Yellow)
		} else {
			Write-ToOutputColored "[ОШИБКА] Ошибка при получении информации о папке: $($tempFolderInfo['ErrorMessage'])" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		}
		return
	}
	
	$tempFolderPath = $tempFolderInfo["TempFolderPath"]
	$serviceName = $tempFolderInfo["ServiceName"]
	
	# Исправляем двойной слеш в пути (если есть)
	$tempFolderPath = $tempFolderPath -replace '\\\\', '\'
	
	# Сохраняем родительскую папку для проверки, если конкретная подпапка не найдена
	$parentFolderPath = Split-Path $tempFolderPath -Parent
	
	# Скрипт-блок для удаления временных файлов (только содержимое папки)
	$localRemoveTempFilesScriptBlock = {
		param([string]$TempFolderPath, [string]$ServiceName)
		
		$result = @()
		
		try {
			$CheckService1C = Get-Service -Name $ServiceName -ErrorAction Stop
			
			$serviceWasRunning = $false
			if ($CheckService1C.Status -like "Running") {
				$msg = "Остановка службы $ServiceName...|Yellow"
				Write-Output $msg
				Stop-Service -Name $ServiceName -Force -ErrorAction Stop -WarningAction SilentlyContinue
				Start-Sleep -Seconds 5
				$GetStatus1C = Get-Service -Name $ServiceName -ErrorAction Stop
				if ($GetStatus1C.Status -like "Stopped") {
					$serviceWasRunning = $true
					$msg = "Служба $ServiceName Остановлена|Red"
					Write-Output $msg
				} else {
					$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось остановить службу $ServiceName. Статус: $($GetStatus1C.Status)|Yellow"
					Write-Output $msg
				}
			} else {
				$msg = "Служба $ServiceName уже остановлена|White"
				Write-Output $msg
			}
			
			# Дополнительная проверка: убеждаемся, что служба остановлена перед удалением
			$finalServiceCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
			if ($null -ne $finalServiceCheck -and $finalServiceCheck.Status -like "Running") {
				# Пробуем остановить еще раз
				try {
					Stop-Service -Name $ServiceName -Force -ErrorAction Stop -WarningAction SilentlyContinue
					Start-Sleep -Seconds 3
					$finalServiceCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
					if ($finalServiceCheck.Status -like "Stopped") {
						$msg = "Служба $ServiceName Остановлена после повторной попытки|Red"
						Write-Output $msg
						$serviceWasRunning = $true
					}
				} catch {
					$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось остановить службу $ServiceName перед удалением файлов|Yellow"
					Write-Output $msg
				}
			}
			
			# Дополнительная задержка после остановки службы для разблокировки файлов
			if ($serviceWasRunning) {
				Start-Sleep -Seconds 10
				# Проверяем процессы, использующие файлы из папки
				try {
					$processesUsingFiles = Get-Process | Where-Object {
						$_.Path -like "$TempFolderPath*"
					} -ErrorAction SilentlyContinue
					
					if ($null -ne $processesUsingFiles -and $processesUsingFiles.Count -gt 0) {
						Start-Sleep -Seconds 5
					}
				} catch {
					# Игнорируем ошибки проверки процессов
				}
			}
			
			if (Test-Path $TempFolderPath -ErrorAction Stop) {
				# Подсчитываем файлы и подпапки перед удалением (с повторными попытками)
				$allFiles = $null
				$allDirs = $null
				$retryCount = 0
				$maxRetries = 3
				
				while ($retryCount -lt $maxRetries) {
					try {
						$allFiles = Get-ChildItem -Path $TempFolderPath -Recurse -File -Force -ErrorAction SilentlyContinue
						$allDirs = Get-ChildItem -Path $TempFolderPath -Recurse -Directory -Force -ErrorAction SilentlyContinue
						break
					} catch {
						$retryCount++
						if ($retryCount -lt $maxRetries) {
							Start-Sleep -Milliseconds 500
						}
					}
				}
				
				$totalFiles = if ($null -eq $allFiles) { 0 } else { $allFiles.Count }
				$totalDirs = if ($null -eq $allDirs) { 0 } else { $allDirs.Count }
				
				if ($totalFiles -gt 0 -or $totalDirs -gt 0) {
					$msg = "[OK] Найдено файлов: $totalFiles, подпапок: $totalDirs|White"
					Write-Output $msg
					
					# Удаляем только содержимое папки, а не саму папку
					# Сначала удаляем все файлы рекурсивно
					$allFilesToDelete = Get-ChildItem -Path $TempFolderPath -Recurse -File -Force -ErrorAction SilentlyContinue
					$deletedFilesCount = 0
					$failedFilesCount = 0
					
					if ($null -ne $allFilesToDelete -and $allFilesToDelete.Count -gt 0) {
						foreach ($file in $allFilesToDelete) {
							try {
								Remove-Item -Path $file.FullName -Force -Confirm:$false -ErrorAction Stop
								$deletedFilesCount++
							} catch {
								$failedFilesCount++
								# Пробуем удалить через cmd для заблокированных файлов
								try {
									$null = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "del /f /q `"$($file.FullName)`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
									$deletedFilesCount++
									$failedFilesCount--
								} catch {
									# Игнорируем ошибки
								}
							}
						}
					}
					
					# Затем удаляем все подпапки внутри папки (но не саму папку)
					# Сортируем по глубине (самые глубокие сначала) для правильного удаления
					$deletedDirsCount = 0
					$failedDirsCount = 0
					
					# Удаляем подпапки рекурсивно, начиная с самых глубоких
					$allSubDirs = Get-ChildItem -Path $TempFolderPath -Recurse -Directory -Force -ErrorAction SilentlyContinue
					if ($null -ne $allSubDirs) {
						# Сортируем по длине пути (более длинный путь = более глубокая папка)
						$sortedDirs = $allSubDirs | Sort-Object { $_.FullName.Length } -Descending
						foreach ($dir in $sortedDirs) {
							try {
								Remove-Item -Path $dir.FullName -Recurse -Force -Confirm:$false -ErrorAction Stop
								$deletedDirsCount++
							} catch {
								$failedDirsCount++
								# Пробуем удалить через cmd для заблокированных папок
								try {
									$null = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "rd /s /q `"$($dir.FullName)`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
									$deletedDirsCount++
									$failedDirsCount--
								} catch {
									# Игнорируем ошибки
								}
							}
						}
					}
					
					# Удаляем подпапки первого уровня (если они еще существуют)
					$firstLevelDirs = Get-ChildItem -Path $TempFolderPath -Directory -Force -ErrorAction SilentlyContinue
					if ($null -ne $firstLevelDirs) {
						foreach ($dir in $firstLevelDirs) {
							try {
								Remove-Item -Path $dir.FullName -Recurse -Force -Confirm:$false -ErrorAction Stop
								$deletedDirsCount++
							} catch {
								$failedDirsCount++
								# Пробуем удалить через cmd
								try {
									$null = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "rd /s /q `"$($dir.FullName)`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
									$deletedDirsCount++
									$failedDirsCount--
								} catch {
									# Игнорируем ошибки
								}
							}
						}
					}
					
					if ($failedFilesCount -gt 0 -or $failedDirsCount -gt 0) {
						$msg = "[ПРЕДУПРЕЖДЕНИЕ] Удалено файлов: $deletedFilesCount из $totalFiles, подпапок: $deletedDirsCount из $totalDirs|Yellow"
						Write-Output $msg
						if ($failedFilesCount -gt 0) {
							$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось удалить $failedFilesCount файлов (возможно, заблокированы процессами)|Yellow"
							Write-Output $msg
						}
						if ($failedDirsCount -gt 0) {
							$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось удалить $failedDirsCount подпапок (возможно, заблокированы процессами)|Yellow"
							Write-Output $msg
						}
					} else {
						$folderName = Split-Path -Path $TempFolderPath -Leaf
						$msg = "[OK] Содержимое папки $folderName ($deletedFilesCount файлов, $deletedDirsCount подпапок) Удалено|White"
						Write-Output $msg
					}
				} else {
					$msg = "Папка пуста|Yellow"
					Write-Output $msg
				}
				
				if ($serviceWasRunning) {
					$msg = "Запуск службы $ServiceName...|Yellow"
					Write-Output $msg
					Start-Service -Name $ServiceName -ErrorAction Stop
					Start-Sleep -Seconds 3
					$finalServiceStatus = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
					if ($null -ne $finalServiceStatus -and $finalServiceStatus.Status -like "Running") {
						$msg = "Служба $ServiceName Запущена|Green"
						Write-Output $msg
					} else {
						$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось запустить службу $ServiceName. Статус: $($finalServiceStatus.Status)|Yellow"
						Write-Output $msg
					}
				}
			} else {
				$msg = "Папка не найдена: $TempFolderPath|Yellow"
				Write-Output $msg
			}
		}
		catch {
			$msg = "[ОШИБКА] $($_.Exception.Message)|Red"
			Write-Output $msg
		}
		
		return $result
	}
	
	$remoteRemoveTempFilesScriptBlock = {
		param([string]$TempFolderPath, [string]$ServiceName)
		
		$result = @()
		
		try {
			$CheckService1C = Get-Service -Name $ServiceName -ErrorAction Stop
			
			$serviceWasRunning = $false
			if ($CheckService1C.Status -like "Running") {
				$msg = "Остановка службы $ServiceName...|Yellow"
				Write-Output $msg
				Stop-Service -Name $ServiceName -Force -ErrorAction Stop -WarningAction SilentlyContinue
				Start-Sleep -Seconds 5
				$GetStatus1C = Get-Service -Name $ServiceName -ErrorAction Stop
				if ($GetStatus1C.Status -like "Stopped") {
					$serviceWasRunning = $true
					$msg = "Служба $ServiceName Остановлена|Red"
					Write-Output $msg
				} else {
					$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось остановить службу $ServiceName. Статус: $($GetStatus1C.Status)|Yellow"
					Write-Output $msg
				}
			} else {
				$msg = "Служба $ServiceName уже остановлена|White"
				Write-Output $msg
			}
			
			# Дополнительная проверка: убеждаемся, что служба остановлена перед удалением
			$finalServiceCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
			if ($null -ne $finalServiceCheck -and $finalServiceCheck.Status -like "Running") {
				# Пробуем остановить еще раз
				try {
					Stop-Service -Name $ServiceName -Force -ErrorAction Stop -WarningAction SilentlyContinue
					Start-Sleep -Seconds 3
					$finalServiceCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
					if ($finalServiceCheck.Status -like "Stopped") {
						$msg = "Служба $ServiceName Остановлена после повторной попытки|Red"
						Write-Output $msg
						$serviceWasRunning = $true
					}
				} catch {
					$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось остановить службу $ServiceName перед удалением файлов|Yellow"
					Write-Output $msg
				}
			}
			
			# Дополнительная задержка после остановки службы для разблокировки файлов
			if ($serviceWasRunning) {
				Start-Sleep -Seconds 10
				# Проверяем процессы, использующие файлы из папки
				try {
					$processesUsingFiles = Get-Process | Where-Object {
						$_.Path -like "$TempFolderPath*"
					} -ErrorAction SilentlyContinue
					
					if ($null -ne $processesUsingFiles -and $processesUsingFiles.Count -gt 0) {
						Start-Sleep -Seconds 5
					}
				} catch {
					# Игнорируем ошибки проверки процессов
				}
			}
			
			if (Test-Path $TempFolderPath -ErrorAction Stop) {
				# Подсчитываем файлы и подпапки перед удалением (с повторными попытками)
				$allFiles = $null
				$allDirs = $null
				$retryCount = 0
				$maxRetries = 3
				
				while ($retryCount -lt $maxRetries) {
					try {
						$allFiles = Get-ChildItem -Path $TempFolderPath -Recurse -File -Force -ErrorAction SilentlyContinue
						$allDirs = Get-ChildItem -Path $TempFolderPath -Recurse -Directory -Force -ErrorAction SilentlyContinue
						break
					} catch {
						$retryCount++
						if ($retryCount -lt $maxRetries) {
							Start-Sleep -Milliseconds 500
						}
					}
				}
				
				$totalFiles = if ($null -eq $allFiles) { 0 } else { $allFiles.Count }
				$totalDirs = if ($null -eq $allDirs) { 0 } else { $allDirs.Count }
				
				if ($totalFiles -gt 0 -or $totalDirs -gt 0) {
					$msg = "[OK] Найдено файлов: $totalFiles, подпапок: $totalDirs|White"
					Write-Output $msg
					
					# Удаляем только содержимое папки, а не саму папку
					# Сначала удаляем все файлы рекурсивно
					$allFilesToDelete = Get-ChildItem -Path $TempFolderPath -Recurse -File -Force -ErrorAction SilentlyContinue
					$deletedFilesCount = 0
					$failedFilesCount = 0
					
					if ($null -ne $allFilesToDelete -and $allFilesToDelete.Count -gt 0) {
						foreach ($file in $allFilesToDelete) {
							try {
								Remove-Item -Path $file.FullName -Force -Confirm:$false -ErrorAction Stop
								$deletedFilesCount++
							} catch {
								$failedFilesCount++
								# Пробуем удалить через cmd для заблокированных файлов
								try {
									$null = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "del /f /q `"$($file.FullName)`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
									$deletedFilesCount++
									$failedFilesCount--
								} catch {
									# Игнорируем ошибки
								}
							}
						}
					}
					
					# Затем удаляем все подпапки внутри папки (но не саму папку)
					# Сортируем по глубине (самые глубокие сначала) для правильного удаления
					$deletedDirsCount = 0
					$failedDirsCount = 0
					
					# Удаляем подпапки рекурсивно, начиная с самых глубоких
					$allSubDirs = Get-ChildItem -Path $TempFolderPath -Recurse -Directory -Force -ErrorAction SilentlyContinue
					if ($null -ne $allSubDirs) {
						# Сортируем по длине пути (более длинный путь = более глубокая папка)
						$sortedDirs = $allSubDirs | Sort-Object { $_.FullName.Length } -Descending
						foreach ($dir in $sortedDirs) {
							try {
								Remove-Item -Path $dir.FullName -Recurse -Force -Confirm:$false -ErrorAction Stop
								$deletedDirsCount++
							} catch {
								$failedDirsCount++
								# Пробуем удалить через cmd для заблокированных папок
								try {
									$null = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "rd /s /q `"$($dir.FullName)`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
									$deletedDirsCount++
									$failedDirsCount--
								} catch {
									# Игнорируем ошибки
								}
							}
						}
					}
					
					# Удаляем подпапки первого уровня (если они еще существуют)
					$firstLevelDirs = Get-ChildItem -Path $TempFolderPath -Directory -Force -ErrorAction SilentlyContinue
					if ($null -ne $firstLevelDirs) {
						foreach ($dir in $firstLevelDirs) {
							try {
								Remove-Item -Path $dir.FullName -Recurse -Force -Confirm:$false -ErrorAction Stop
								$deletedDirsCount++
							} catch {
								$failedDirsCount++
								# Пробуем удалить через cmd
								try {
									$null = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "rd /s /q `"$($dir.FullName)`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
									$deletedDirsCount++
									$failedDirsCount--
								} catch {
									# Игнорируем ошибки
								}
							}
						}
					}
					
					if ($failedFilesCount -gt 0 -or $failedDirsCount -gt 0) {
						$msg = "[ПРЕДУПРЕЖДЕНИЕ] Удалено файлов: $deletedFilesCount из $totalFiles, подпапок: $deletedDirsCount из $totalDirs|Yellow"
						Write-Output $msg
						if ($failedFilesCount -gt 0) {
							$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось удалить $failedFilesCount файлов (возможно, заблокированы процессами)|Yellow"
							Write-Output $msg
						}
						if ($failedDirsCount -gt 0) {
							$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось удалить $failedDirsCount подпапок (возможно, заблокированы процессами)|Yellow"
							Write-Output $msg
						}
					} else {
						$folderName = Split-Path -Path $TempFolderPath -Leaf
						$msg = "[OK] Содержимое папки $folderName ($deletedFilesCount файлов, $deletedDirsCount подпапок) Удалено|White"
						Write-Output $msg
					}
				} else {
					$msg = "Папка пуста|Yellow"
					Write-Output $msg
				}
				
				if ($serviceWasRunning) {
					$msg = "Запуск службы $ServiceName...|Yellow"
					Write-Output $msg
					Start-Service -Name $ServiceName -ErrorAction Stop
					Start-Sleep -Seconds 3
					$finalServiceStatus = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
					if ($null -ne $finalServiceStatus -and $finalServiceStatus.Status -like "Running") {
						$msg = "Служба $ServiceName Запущена|Green"
						Write-Output $msg
					} else {
						$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось запустить службу $ServiceName. Статус: $($finalServiceStatus.Status)|Yellow"
						Write-Output $msg
					}
				}
			} else {
				$msg = "Папка не найдена: $TempFolderPath|Yellow"
				Write-Output $msg
			}
		}
		catch {
			$msg = "[ОШИБКА] $($_.Exception.Message)|Red"
			Write-Output $msg
		}
		
		return $result
	}
	
	# Прогресс-бар уже показан в Execute-Function, не показываем его повторно
	# (как в Remove-Server1C - прогресс-бар показывается только в Execute-Function)
	
	# Подсчитываем начальное количество файлов и размер для прогресс-бара
	$totalFilesForProgress = 0
	$totalSizeMBForProgress = 0
	$showFolderProgressBar = $false
	
		try {
			if ($isLocal) {
				$initialFiles = Get-ChildItem -Path $tempFolderPath -Recurse -File -Force -ErrorAction SilentlyContinue
				$initialDirs = Get-ChildItem -Path $tempFolderPath -Recurse -Directory -Force -ErrorAction SilentlyContinue
				$totalFilesForProgress = if ($null -eq $initialFiles) { 0 } else { $initialFiles.Count }
				$totalDirsForProgress = if ($null -eq $initialDirs) { 0 } else { $initialDirs.Count }
				if ($totalFilesForProgress -gt 0) {
					$totalSizeBytesForProgress = ($initialFiles | Measure-Object -Property Length -Sum).Sum
					$totalSizeMBForProgress = [math]::Round($totalSizeBytesForProgress / 1MB, 0)
				} elseif ($totalDirsForProgress -gt 0) {
					# Если есть только папки, используем их количество для прогресс-бара
					$totalFilesForProgress = $totalDirsForProgress
					$totalSizeMBForProgress = 0
				}
		} else {
			$initialInfo = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
				param([string]$Path)
				try {
					$files = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue
					$dirs = Get-ChildItem -Path $Path -Recurse -Directory -Force -ErrorAction SilentlyContinue
					$count = if ($null -eq $files) { 0 } else { $files.Count }
					$dirCount = if ($null -eq $dirs) { 0 } else { $dirs.Count }
					$size = if ($null -eq $files -or $count -eq 0) { 0 } else { ($files | Measure-Object -Property Length -Sum).Sum }
					return @{ Count = $count; Size = $size; DirCount = $dirCount }
				} catch {
					return @{ Count = 0; Size = 0; DirCount = 0 }
				}
			} -ArgumentList $tempFolderPath
			
			if ($null -ne $initialInfo) {
				$totalFilesForProgress = $initialInfo.Count
				$totalSizeMBForProgress = [math]::Round($initialInfo.Size / 1MB, 0)
				# Если есть папки, но нет файлов, все равно показываем прогресс-бар
				if ($totalFilesForProgress -eq 0 -and $initialInfo.DirCount -gt 0) {
					$totalFilesForProgress = $initialInfo.DirCount  # Используем количество папок для прогресс-бара
				}
			}
		}
	
	# Не показываем прогресс-бар здесь - он будет показан после вывода сообщения "Служба ... Остановлена" в GUI
	# (прогресс-бар показывается только в цикле мониторинга после того, как сообщение выведено)
	} catch {
		# Игнорируем ошибки при подсчете
	}
	
	# Запускаем удаление в фоновом Job для возможности обновления UI
	if ($isLocal) {
		# Локальное выполнение - используем Start-Job
		$removeTempJob = Start-Job -ScriptBlock $localRemoveTempFilesScriptBlock -ArgumentList $tempFolderPath, $serviceName
	} else {
		# Удалённое выполнение через Invoke-Command -AsJob
		$removeTempJob = Invoke-Command -ComputerName $Server -ScriptBlock $remoteRemoveTempFilesScriptBlock -ArgumentList $tempFolderPath, $serviceName -AsJob
	}
	
	# Даем Job время начать выполнение
	Start-Sleep -Milliseconds 500
	[System.Windows.Forms.Application]::DoEvents()
	
	# Не показываем прогресс-бар здесь - он будет показан после вывода сообщения "Служба ... Остановлена" в GUI
	# (прогресс-бар показывается только в цикле мониторинга после того, как сообщение выведено)
	
	# Переменные для отслеживания прогресса
	$folderStillExists = $true
	$lastKnownDeletedFiles = 0
	$lastKnownDeletedMB = 0
	$lastKnownUpdateTime = Get-Date
	$deletionStartTime = Get-Date
	$progressBarUpdateCount = 0
	$folderProgressBarShown = $showFolderProgressBar
	$processedOutputLines = @()
	$lastOutputCheckTime = Get-Date
	$serviceStoppedMessageDisplayed = $false  # Флаг: сообщение "Служба ... Остановлена" выведено в GUI
	
	# Цикл отслеживания прогресса удаления
	$lastFolderCheck = Get-Date
	while (($removeTempJob.State -eq "Running" -or $removeTempJob.State -eq "Blocked") -or $folderStillExists) {
		$currentTime = Get-Date
		$timeSinceLastUpdate = ($currentTime - $lastKnownUpdateTime).TotalSeconds
		$timeSinceLastOutputCheck = ($currentTime - $lastOutputCheckTime).TotalSeconds
		$timeSinceLastFolderCheck = ($currentTime - $lastFolderCheck).TotalSeconds
		
		# Проверяем, появилось ли сообщение "Служба ... Остановлена" в выводе
		$serviceStoppedMessageFound = $false
		foreach ($line in $processedOutputLines) {
			$lineStr = $line.ToString()
			if ($lineStr -match "Служба.*Остановлена" -or $lineStr -match "Служба.*остановлена") {
				$serviceStoppedMessageFound = $true
				break
			}
		}
		
		# Если прогресс-бар еще не показан И сообщение "Служба ... Остановлена" уже выведено в GUI, проверяем папку чаще (каждые 0.1 секунды)
		if (-not $folderProgressBarShown -and $serviceStoppedMessageDisplayed -and $timeSinceLastFolderCheck -ge 0.1) {
			# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Сообщение 'Служба ... Остановлена' найдено, проверяем папку для показа прогресс-бара" ([System.Drawing.Color]::Cyan)
			# [System.Windows.Forms.Application]::DoEvents()
			$lastFolderCheck = $currentTime
			try {
				# Проверяем существование папки (локально или удаленно)
				$pathExists = $false
				$checkPath = $null
				
				if ($isLocal) {
					# Локальная проверка
					$pathExists = Test-Path $tempFolderPath -ErrorAction SilentlyContinue
					# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Проверка папки (локально): tempFolderPath = $tempFolderPath, pathExists = $pathExists" ([System.Drawing.Color]::Cyan)
					# [System.Windows.Forms.Application]::DoEvents()
					
					# Если конкретная подпапка не найдена, проверяем родительскую папку
					if (-not $pathExists) {
						$pathExists = Test-Path $parentFolderPath -ErrorAction SilentlyContinue
						# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Конкретная подпапка не найдена, проверяем родительскую (локально): parentFolderPath = $parentFolderPath, pathExists = $pathExists" ([System.Drawing.Color]::Cyan)
						# [System.Windows.Forms.Application]::DoEvents()
						
						if ($pathExists) {
							$checkPath = $parentFolderPath
						}
					} else {
						$checkPath = $tempFolderPath
					}
				} else {
					# Удаленная проверка через Invoke-Command
					$pathCheckResult = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
						param([string]$TempPath, [string]$ParentPath)
						$result = @{}
						$result["TempPathExists"] = Test-Path $TempPath -ErrorAction SilentlyContinue
						if (-not $result["TempPathExists"]) {
							$result["ParentPathExists"] = Test-Path $ParentPath -ErrorAction SilentlyContinue
						} else {
							$result["ParentPathExists"] = $false
						}
						return $result
					} -ArgumentList $tempFolderPath, $parentFolderPath
					
					if ($null -ne $pathCheckResult) {
						if ($pathCheckResult["TempPathExists"]) {
							$pathExists = $true
							$checkPath = $tempFolderPath
							# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Проверка папки (удаленно): tempFolderPath = $tempFolderPath, pathExists = True" ([System.Drawing.Color]::Cyan)
							# [System.Windows.Forms.Application]::DoEvents()
						} elseif ($pathCheckResult["ParentPathExists"]) {
							$pathExists = $true
							$checkPath = $parentFolderPath
							# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Конкретная подпапка не найдена, проверяем родительскую (удаленно): parentFolderPath = $parentFolderPath, pathExists = True" ([System.Drawing.Color]::Cyan)
							# [System.Windows.Forms.Application]::DoEvents()
						} else {
							# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Проверка папки (удаленно): tempFolderPath = $tempFolderPath, pathExists = False; parentFolderPath = $parentFolderPath, pathExists = False" ([System.Drawing.Color]::Cyan)
							# [System.Windows.Forms.Application]::DoEvents()
						}
					} else {
						# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Ошибка при проверке папки (удаленно): pathCheckResult = null" ([System.Drawing.Color]::Yellow)
						# [System.Windows.Forms.Application]::DoEvents()
					}
				}
				
				if ($pathExists -and $null -ne $checkPath) {
					$checkFiles = $null
					$checkDirs = $null
					$checkFilesCount = 0
					$checkDirsCount = 0
					
					if ($isLocal) {
						$checkFiles = Get-ChildItem -Path $checkPath -Recurse -File -Force -ErrorAction SilentlyContinue
						$checkDirs = Get-ChildItem -Path $checkPath -Recurse -Directory -Force -ErrorAction SilentlyContinue
						$checkFilesCount = if ($null -eq $checkFiles) { 0 } else { $checkFiles.Count }
						$checkDirsCount = if ($null -eq $checkDirs) { 0 } else { $checkDirs.Count }
						# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Локально: checkPath = $checkPath, checkFilesCount = $checkFilesCount, checkDirsCount = $checkDirsCount" ([System.Drawing.Color]::Cyan)
						# [System.Windows.Forms.Application]::DoEvents()
					} else {
						$checkInfo = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
							param([string]$Path)
							try {
								$files = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue
								$dirs = Get-ChildItem -Path $Path -Recurse -Directory -Force -ErrorAction SilentlyContinue
								$fileCount = if ($null -eq $files) { 0 } else { $files.Count }
								$dirCount = if ($null -eq $dirs) { 0 } else { $dirs.Count }
								$size = if ($null -eq $files -or $fileCount -eq 0) { 0 } else { ($files | Measure-Object -Property Length -Sum).Sum }
								return @{ Count = $fileCount; Size = $size; DirCount = $dirCount }
							} catch {
								return @{ Count = 0; Size = 0; DirCount = 0 }
							}
						} -ArgumentList $checkPath
						
						if ($null -ne $checkInfo) {
							$checkFilesCount = $checkInfo.Count
							$checkDirsCount = $checkInfo.DirCount
							# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Удаленно: checkFilesCount = $checkFilesCount, checkDirsCount = $checkDirsCount" ([System.Drawing.Color]::Cyan)
							# [System.Windows.Forms.Application]::DoEvents()
						} else {
							# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Удаленно: checkInfo = null" ([System.Drawing.Color]::Yellow)
							# [System.Windows.Forms.Application]::DoEvents()
						}
					}
					
					# Если папка существует и в ней есть файлы или папки - показываем прогресс-бар
					if ($checkFilesCount -gt 0 -or $checkDirsCount -gt 0) {
						# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Найдены файлы/папки, готовимся показать прогресс-бар" ([System.Drawing.Color]::Green)
						# [System.Windows.Forms.Application]::DoEvents()
						
						# Пересчитываем общее количество файлов и размер для прогресс-бара
						$totalFilesForProgress = $checkFilesCount
						if ($totalFilesForProgress -eq 0 -and $checkDirsCount -gt 0) {
							$totalFilesForProgress = $checkDirsCount
						}
						
						# Вычисляем размер
						if ($isLocal) {
							$totalSizeBytesForProgress = if ($null -eq $checkFiles -or $checkFilesCount -eq 0) { 0 } else { ($checkFiles | Measure-Object -Property Length -Sum).Sum }
						} else {
							$totalSizeBytesForProgress = if ($null -eq $checkInfo) { 0 } else { $checkInfo.Size }
						}
						$totalSizeMBForProgress = [math]::Round($totalSizeBytesForProgress / 1MB, 0)
						
						# Write-ToOutput "[DEBUG] Remove-TempFiles1C: totalFilesForProgress = $totalFilesForProgress, totalSizeMBForProgress = $totalSizeMBForProgress" ([System.Drawing.Color]::Cyan)
						# [System.Windows.Forms.Application]::DoEvents()
						
						if ($totalFilesForProgress -gt 0) {
							# Инициализируем переменные для интерполяции
							if (-not $folderProgressBarShown) {
								$lastKnownDeletedFiles = 0
								$lastKnownDeletedMB = 0
								$lastKnownUpdateTime = Get-Date
								$deletionStartTime = Get-Date
								$progressBarUpdateCount = 0
							}
							
							# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Показываем прогресс-бар удаления папки" ([System.Drawing.Color]::Green)
							# [System.Windows.Forms.Application]::DoEvents()
							
							$showFolderProgressBar = $true
							$folderProgressBarShown = $true
							Show-FolderDeletionProgressBar
							Update-FolderDeletionProgressBar -DeletedFiles 0 -TotalFiles $totalFilesForProgress -DeletedMB 0 -TotalMB $totalSizeMBForProgress
							[System.Windows.Forms.Application]::DoEvents()
							
							# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Прогресс-бар удаления папки показан" ([System.Drawing.Color]::Green)
							# [System.Windows.Forms.Application]::DoEvents()
						} else {
							# Write-ToOutput "[DEBUG] Remove-TempFiles1C: totalFilesForProgress = 0, прогресс-бар не показываем" ([System.Drawing.Color]::Yellow)
							# [System.Windows.Forms.Application]::DoEvents()
						}
					} else {
						# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Файлы/папки не найдены (checkFilesCount = $checkFilesCount, checkDirsCount = $checkDirsCount)" ([System.Drawing.Color]::Yellow)
						# [System.Windows.Forms.Application]::DoEvents()
					}
				} else {
					# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Папка не существует: $tempFolderPath" ([System.Drawing.Color]::Yellow)
					# [System.Windows.Forms.Application]::DoEvents()
				}
			} catch {
				# Write-ToOutput "[DEBUG] Remove-TempFiles1C: ОШИБКА при проверке папки: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
				# [System.Windows.Forms.Application]::DoEvents()
			}
		}
		
		# Получаем промежуточные результаты из Job для вывода по мере выполнения (каждые 0.5 секунды)
		if ($timeSinceLastOutputCheck -ge 0.5) {
			try {
				if ($removeTempJob.HasMoreData) {
					$newOutput = Receive-Job -Job $removeTempJob -ErrorAction SilentlyContinue
					if ($null -ne $newOutput) {
						$outputArray = @()
						if ($newOutput -is [System.Array]) {
							foreach ($item in $newOutput) {
								if ($item -is [System.Array]) {
									$outputArray += $item
								} else {
									$outputArray += $item
								}
							}
						} else {
							$outputArray = @($newOutput)
						}
						
						# Выводим только новые строки
						foreach ($line in $outputArray) {
							if ($line -notin $processedOutputLines) {
								$processedOutputLines += $line
								Write-OutputResults -OutputLines @($line)
								[System.Windows.Forms.Application]::DoEvents()
								
								# Проверяем, является ли это сообщением "Служба ... Остановлена" и устанавливаем флаг
								$lineStr = $line.ToString()
								if (-not $serviceStoppedMessageDisplayed -and ($lineStr -match "Служба.*Остановлена" -or $lineStr -match "Служба.*остановлена")) {
									$serviceStoppedMessageDisplayed = $true
									# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Сообщение 'Служба ... Остановлена' выведено в GUI, можно показывать прогресс-бар" ([System.Drawing.Color]::Cyan)
									# [System.Windows.Forms.Application]::DoEvents()
								}
							}
						}
					}
				}
				$lastOutputCheckTime = $currentTime
			} catch {
				# Игнорируем ошибки при получении промежуточных результатов
			}
		}
		
		# Обновляем прогресс каждые 0.1 секунды
		if ($timeSinceLastUpdate -ge 0.1) {
			try {
				# Проверяем, что папка пуста (нет файлов и подпапок) - локально или удаленно
				$folderIsEmpty = $false
				$remainingFilesCount = 0
				$remainingSizeBytes = 0
				
				if ($isLocal) {
					if (Test-Path $tempFolderPath -ErrorAction SilentlyContinue) {
						# Проверяем наличие файлов и подпапок
						$remainingFiles = Get-ChildItem -Path $tempFolderPath -Recurse -File -Force -ErrorAction SilentlyContinue
						$remainingDirs = Get-ChildItem -Path $tempFolderPath -Recurse -Directory -Force -ErrorAction SilentlyContinue
						$remainingFilesCount = if ($null -eq $remainingFiles) { 0 } else { $remainingFiles.Count }
						$remainingDirsCount = if ($null -eq $remainingDirs) { 0 } else { $remainingDirs.Count }
						$remainingSizeBytes = if ($null -eq $remainingFiles -or $remainingFiles.Count -eq 0) { 0 } else { ($remainingFiles | Measure-Object -Property Length -Sum).Sum }
						
						# Папка пуста, если нет файлов и подпапок
						$folderIsEmpty = ($remainingFilesCount -eq 0 -and $remainingDirsCount -eq 0)
					} else {
						# Папка не существует - считаем пустой
						$folderIsEmpty = $true
					}
				} else {
					$remainingInfo = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
						param([string]$Path)
						try {
							if (Test-Path $Path -ErrorAction SilentlyContinue) {
								$files = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue
								$dirs = Get-ChildItem -Path $Path -Recurse -Directory -Force -ErrorAction SilentlyContinue
								$fileCount = if ($null -eq $files) { 0 } else { $files.Count }
								$dirCount = if ($null -eq $dirs) { 0 } else { $dirs.Count }
								$size = if ($null -eq $files -or $fileCount -eq 0) { 0 } else { ($files | Measure-Object -Property Length -Sum).Sum }
								return @{ Count = $fileCount; Size = $size; DirCount = $dirCount; IsEmpty = ($fileCount -eq 0 -and $dirCount -eq 0) }
							} else {
								return @{ Count = 0; Size = 0; DirCount = 0; IsEmpty = $true }
							}
						} catch {
							return @{ Count = 0; Size = 0; DirCount = 0; IsEmpty = $true }
						}
					} -ArgumentList $tempFolderPath
					
					if ($null -ne $remainingInfo) {
						$remainingFilesCount = $remainingInfo.Count
						$remainingSizeBytes = $remainingInfo.Size
						$folderIsEmpty = $remainingInfo.IsEmpty
					} else {
						$folderIsEmpty = $true
					}
				}
				
				if (-not $folderIsEmpty) {
					# Папка еще содержит файлы или подпапки
					$folderStillExists = $true
					$remainingSizeMB = [math]::Round($remainingSizeBytes / 1MB, 0)
					
					# Вычисляем количество удаленных файлов и размер
					$deletedFilesCount = if ($totalFilesForProgress -gt 0) { [math]::Max(0, $totalFilesForProgress - $remainingFilesCount) } else { 0 }
					$deletedSizeMB = if ($totalSizeMBForProgress -gt 0) { [math]::Max(0, $totalSizeMBForProgress - $remainingSizeMB) } else { 0 }
					
					# Гарантируем монотонное возрастание
					if ($deletedFilesCount -lt $lastKnownDeletedFiles) {
						$deletedFilesCount = $lastKnownDeletedFiles
					}
					if ($deletedSizeMB -lt $lastKnownDeletedMB) {
						$deletedSizeMB = $lastKnownDeletedMB
					}
					
					# Обновляем прогресс-бар только если значения увеличились
					if ($showFolderProgressBar -and $folderProgressBarShown -and $totalFilesForProgress -gt 0) {
						if ($deletedFilesCount -gt $lastKnownDeletedFiles -or $deletedSizeMB -gt $lastKnownDeletedMB) {
							Update-FolderDeletionProgressBar -DeletedFiles $deletedFilesCount -TotalFiles $totalFilesForProgress -DeletedMB $deletedSizeMB -TotalMB $totalSizeMBForProgress
							$lastKnownDeletedFiles = $deletedFilesCount
							$lastKnownDeletedMB = $deletedSizeMB
							$lastKnownUpdateTime = $currentTime
							$progressBarUpdateCount++
							[System.Windows.Forms.Application]::DoEvents()
						}
					}
				} else {
					# Папка пуста (все содержимое удалено) - показываем 100%
					$folderStillExists = $false
					if ($showFolderProgressBar -and $folderProgressBarShown -and $totalFilesForProgress -gt 0) {
						if ($lastKnownDeletedFiles -lt $totalFilesForProgress) {
							Update-FolderDeletionProgressBar -DeletedFiles $totalFilesForProgress -TotalFiles $totalFilesForProgress -DeletedMB $totalSizeMBForProgress -TotalMB $totalSizeMBForProgress
							$lastKnownDeletedFiles = $totalFilesForProgress
							$lastKnownDeletedMB = $totalSizeMBForProgress
							$progressBarUpdateCount++
							[System.Windows.Forms.Application]::DoEvents()
						}
					}
				}
			} catch {
				# Игнорируем ошибки при проверке прогресса
			}
		}
		
		# Интерполяция для плавного прогресса
		if ($showFolderProgressBar -and $folderProgressBarShown -and $totalFilesForProgress -gt 0 -and $totalSizeMBForProgress -gt 0) {
			$timeSinceLastKnownUpdate = ($currentTime - $lastKnownUpdateTime).TotalSeconds
			$timeSinceDeletionStart = ($currentTime - $deletionStartTime).TotalSeconds
			$minUpdateInterval = 0.1
			
			if ($timeSinceLastKnownUpdate -ge $minUpdateInterval -and $lastKnownDeletedFiles -lt $totalFilesForProgress) {
				$estimatedDurationSeconds = [math]::Max(5, ($timeSinceDeletionStart + 1))
				$timeBasedProgressPercent = [math]::Min(($timeSinceDeletionStart / $estimatedDurationSeconds) * 100, 100)
				
				$estimatedProgress = [math]::Min(
					[math]::Max($lastKnownDeletedFiles, [math]::Round(($timeBasedProgressPercent / 100) * $totalFilesForProgress)),
					$totalFilesForProgress
				)
				
				$estimatedMB = [math]::Min(
					[math]::Max($lastKnownDeletedMB, [math]::Round(($timeBasedProgressPercent / 100) * $totalSizeMBForProgress, 0)),
					$totalSizeMBForProgress
				)
				
				$estimatedProgressRounded = [math]::Round($estimatedProgress)
				$estimatedMBRounded = [math]::Round($estimatedMB, 0)
				
				if ($estimatedProgressRounded -lt $lastKnownDeletedFiles) {
					$estimatedProgressRounded = $lastKnownDeletedFiles
				}
				if ($estimatedMBRounded -lt $lastKnownDeletedMB) {
					$estimatedMBRounded = $lastKnownDeletedMB
				}
				
				$maxInterpolationStep = [math]::Max(1, [math]::Round($totalFilesForProgress / 100))
				if ($estimatedProgressRounded -gt ($lastKnownDeletedFiles + $maxInterpolationStep)) {
					$estimatedProgressRounded = $lastKnownDeletedFiles + $maxInterpolationStep
				}
				$maxInterpolationStepMB = [math]::Max(1, [math]::Round($totalSizeMBForProgress / 100))
				if ($estimatedMBRounded -gt ($lastKnownDeletedMB + $maxInterpolationStepMB)) {
					$estimatedMBRounded = $lastKnownDeletedMB + $maxInterpolationStepMB
				}
				
				if ($estimatedProgressRounded -gt $lastKnownDeletedFiles -or $estimatedMBRounded -gt $lastKnownDeletedMB) {
					Update-FolderDeletionProgressBar -DeletedFiles $estimatedProgressRounded -TotalFiles $totalFilesForProgress -DeletedMB $estimatedMBRounded -TotalMB $totalSizeMBForProgress
					$progressBarUpdateCount++
					$lastKnownUpdateTime = $currentTime
					$lastKnownDeletedFiles = $estimatedProgressRounded
					$lastKnownDeletedMB = $estimatedMBRounded
					[System.Windows.Forms.Application]::DoEvents()
				}
			}
		}
		
		# Если содержимое удалено и Job завершен, выходим из цикла
		if (-not $folderStillExists -and ($removeTempJob.State -eq "Completed" -or $removeTempJob.State -eq "Failed")) {
			break
		}
		
		# Если Job завершен, но папка еще не пуста, продолжаем проверку еще немного
		if (($removeTempJob.State -eq "Completed" -or $removeTempJob.State -eq "Failed") -and $folderStillExists) {
			# Даем еще немного времени на завершение удаления
			$timeSinceJobCompleted = ($currentTime - $deletionStartTime).TotalSeconds
			if ($timeSinceJobCompleted -gt 5) {
				# Если прошло больше 5 секунд после завершения Job, но папка еще не пуста, выходим
				break
			}
		}
		
		# Защита от бесконечного цикла
		$timeSinceDeletionStart = ($currentTime - $deletionStartTime).TotalSeconds
		if ($timeSinceDeletionStart -gt 120) {
			break
		}
		
		Start-Sleep -Milliseconds 10
	}
	
	# Финальная проверка: убеждаемся, что папка действительно пуста
	$finalCheckEmpty = $false
	try {
		if ($isLocal) {
			if (Test-Path $tempFolderPath -ErrorAction SilentlyContinue) {
				$finalFiles = Get-ChildItem -Path $tempFolderPath -Recurse -File -Force -ErrorAction SilentlyContinue
				$finalDirs = Get-ChildItem -Path $tempFolderPath -Recurse -Directory -Force -ErrorAction SilentlyContinue
				$finalFilesCount = if ($null -eq $finalFiles) { 0 } else { $finalFiles.Count }
				$finalDirsCount = if ($null -eq $finalDirs) { 0 } else { $finalDirs.Count }
				$finalCheckEmpty = ($finalFilesCount -eq 0 -and $finalDirsCount -eq 0)
			} else {
				$finalCheckEmpty = $true
			}
		} else {
			$finalCheckInfo = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
				param([string]$Path)
				try {
					if (Test-Path $Path -ErrorAction SilentlyContinue) {
						$files = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue
						$dirs = Get-ChildItem -Path $Path -Recurse -Directory -Force -ErrorAction SilentlyContinue
						$fileCount = if ($null -eq $files) { 0 } else { $files.Count }
						$dirCount = if ($null -eq $dirs) { 0 } else { $dirs.Count }
						return @{ IsEmpty = ($fileCount -eq 0 -and $dirCount -eq 0); FileCount = $fileCount; DirCount = $dirCount }
					} else {
						return @{ IsEmpty = $true; FileCount = 0; DirCount = 0 }
					}
				} catch {
					return @{ IsEmpty = $false; FileCount = 0; DirCount = 0 }
				}
			} -ArgumentList $tempFolderPath
			
			if ($null -ne $finalCheckInfo) {
				$finalCheckEmpty = $finalCheckInfo.IsEmpty
			}
		}
	} catch {
		# Игнорируем ошибки при финальной проверке
	}
	
	# Останавливаем таймер анимации
	Stop-ProgressBarAnimation
	
	# Получаем результат после завершения Job
	$output = @()
	try {
		# Ждем завершения Job, если он еще выполняется
		$jobWaitTimeout = 30  # Максимум 30 секунд ожидания
		$jobWaitStart = Get-Date
		while ($removeTempJob.State -eq "Running" -or $removeTempJob.State -eq "Blocked") {
			$elapsed = ((Get-Date) - $jobWaitStart).TotalSeconds
			if ($elapsed -gt $jobWaitTimeout) {
				# Таймаут - останавливаем Job
				Stop-Job -Job $removeTempJob -ErrorAction SilentlyContinue
				break
			}
			Start-Sleep -Milliseconds 100
			[System.Windows.Forms.Application]::DoEvents()
		}
		
		if ($removeTempJob.State -eq "Running") {
			Stop-Job -Job $removeTempJob -ErrorAction SilentlyContinue
			Start-Sleep -Seconds 1
		}
		
		# Получаем все результаты из Job (включая уже обработанные)
		$jobResult = Receive-Job -Job $removeTempJob -ErrorAction SilentlyContinue
		
		# Добавляем в финальный вывод только те строки, которые еще не были выведены в цикле
		if ($jobResult -is [System.Array]) {
			foreach ($item in $jobResult) {
				if ($item -is [System.Array]) {
					foreach ($subItem in $item) {
						if ($subItem -notin $processedOutputLines) {
							$output += $subItem
						}
					}
				} else {
					if ($item -notin $processedOutputLines) {
						$output += $item
					}
				}
			}
		} else {
			if ($null -ne $jobResult) {
				# Если это не массив, проверяем каждую строку отдельно
				$jobResultArray = @($jobResult)
				foreach ($line in $jobResultArray) {
					if ($line -notin $processedOutputLines) {
						$output += $line
					}
				}
			}
		}
		
		# Получаем ошибки из Job
		$jobErrors = $null
		try {
			if ($removeTempJob.HasMoreData) {
				$jobErrors = Receive-Job -Job $removeTempJob -ErrorStream -ErrorAction SilentlyContinue
			}
		} catch {
			# Игнорируем ошибки при получении ошибок из Job
		}
		
		if ($removeTempJob.State -eq "Failed") {
			$errorMessage = "Job не завершился корректно. Состояние: $($removeTempJob.State)"
			if ($jobErrors) {
				$errorMessage += ". Ошибки: $($jobErrors -join ', ')"
			}
			$output += "[ОШИБКА] $errorMessage|Red"
		}
		
		Remove-Job -Job $removeTempJob -Force -ErrorAction SilentlyContinue
	} catch {
		$output += "[ОШИБКА] Ошибка при получении результатов: $($_.Exception.Message)|Red"
	}
	
	# Проверяем, что папка действительно пуста после завершения Job
	if (-not $finalCheckEmpty) {
		# Папка не пуста - добавляем предупреждение
		$output += "[ПРЕДУПРЕЖДЕНИЕ] Папка с временными файлов не была полностью очищена: $tempFolderPath|Yellow"
		$output += "[ПРЕДУПРЕЖДЕНИЕ] Рекомендуется проверить содержимое папки и удалить оставшиеся файлы вручную|Yellow"
	}
	
	# Вывод результатов в GUI с обработкой маркеров [OK] и [ОШИБКА]
	# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Начинаем вывод результатов, количество строк: $($output.Count)" ([System.Drawing.Color]::Cyan)
	# [System.Windows.Forms.Application]::DoEvents()
	Write-OutputResults -OutputLines $output
	# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Результаты выведены" ([System.Drawing.Color]::Cyan)
	# [System.Windows.Forms.Application]::DoEvents()
	
	# Даем время на вывод всех сообщений, включая сообщение о запуске службы
	Start-Sleep -Milliseconds 500
	[System.Windows.Forms.Application]::DoEvents()
	Start-Sleep -Milliseconds 300
	[System.Windows.Forms.Application]::DoEvents()
	
	# Проверяем состояние прогресс-бара перед закрытием
	# Скрываем прогресс-бар удаления папки
	if ($showFolderProgressBar -and $folderProgressBarShown) {
		# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Закрываем прогресс-бар удаления папки" ([System.Drawing.Color]::Cyan)
		# [System.Windows.Forms.Application]::DoEvents()
		Hide-FolderDeletionProgressBar
		[System.Windows.Forms.Application]::DoEvents()
		Start-Sleep -Milliseconds 150
		[System.Windows.Forms.Application]::DoEvents()
		# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Прогресс-бар удаления папки закрыт" ([System.Drawing.Color]::Cyan)
		# [System.Windows.Forms.Application]::DoEvents()
	} else {
		# Write-ToOutput "[DEBUG] Remove-TempFiles1C: Прогресс-бар удаления папки не показывался (showFolderProgressBar = $showFolderProgressBar, folderProgressBarShown = $folderProgressBarShown)" ([System.Drawing.Color]::Cyan)
		# [System.Windows.Forms.Application]::DoEvents()
	}
	
	# Основной прогресс-бар закрывается в finally блоке Execute-Function
	# (как в Remove-Server1C - прогресс-бар закрывается только в Execute-Function)
	
	Clear-Variable -Name "Server"
}

# Функция 8. Удаление сервера и службы (модифицирована для работы с GUI диалогами)
function Remove-Server1C() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $Server
	)

	# Write-DebugWithTime "=== НАЧАЛО ФУНКЦИИ Remove-Server1C ===" "Yellow"
	# Write-DebugWithTime "Параметр Server = $Server" "Cyan"

	# Проверяем, является ли сервер локальным
	$isLocal = Test-IsLocalServer -ServerName $Server
	Write-DebugWithTime "Результат проверки isLocal = $isLocal" "Cyan"
	# Подавляем вывод булева значения в консоль
	$null = $isLocal

	# Получаем список продуктов локально или удалённо
	$scriptBlockGetProducts = {
		$result = @()
		if ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {($_.DisplayName -like "*1С:Предприятие*") -or ($_.DisplayName -like "*1С:Enterprise*")}) -or
			(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {($_.DisplayName -like "*1С:Предприятие*") -or ($_.DisplayName -like "*1С:Enterprise*")})) {
			
			# Получаем продукты напрямую в массив строк, без использования ArrayList
			$GetProduct = (Get-WmiObject Win32_Product).Name
			foreach ($Product in $GetProduct) {
				if (($Product -notlike $null) -and (($Product -match "1С:Предприятие") -or ($Product -match "1С:Enterprise"))) {
					# Добавляем каждый продукт напрямую в результат как строку
					$result += $Product.ToString()
				}
			}
			# Добавляем маркер успешного выполнения
			if ($result.Count -gt 0) {
				$result += "OK"
			} else {
				$result = @("NO_PRODUCTS")
			}
		} else {
			$result += "NO_PRODUCTS"
		}
		return $result
	}
	
	# Выполняем локально или удалённо в зависимости от результата проверки
	Write-DebugWithTime "Начало получения списка продуктов. isLocal = $isLocal" "Cyan"
	if ($isLocal) {
		# Локальное выполнение - вызываем скрипт-блок напрямую
		Write-DebugWithTime "Локальное выполнение: получение списка продуктов" "Cyan"
		$productsResult = & $scriptBlockGetProducts
	} else {
		# Удалённое выполнение через Invoke-Command
		Write-DebugWithTime "Удаленное выполнение: получение списка продуктов через Invoke-Command на сервере $Server" "Cyan"
		$productsResult = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock $scriptBlockGetProducts
	}
	Write-DebugWithTime "Получено результатов продуктов: $($productsResult.Count)" "Cyan"
	
	# Обрабатываем результат - используем foreach для правильного извлечения элементов
	# Аналогично функции установки сервера
	Write-DebugWithTime "Начало обработки результатов продуктов" "Cyan"
	$ArrayProduct1C = @()
	$hasNoProducts = $false
	foreach ($item in $productsResult) {
		if ($item -eq "NO_PRODUCTS") {
			$hasNoProducts = $true
			Write-DebugWithTime "Обнаружен маркер NO_PRODUCTS" "Yellow"
			break
		}
		if ($item -ne "OK" -and $item -ne "NO_PRODUCTS") {
			# Явно преобразуем каждый элемент в строку
			$productStr = $item.ToString()
			$ArrayProduct1C += $productStr
			Write-DebugWithTime "Добавлен продукт: $productStr" "Cyan"
		}
	}
	Write-DebugWithTime "Обработка завершена. Найдено продуктов: $($ArrayProduct1C.Count), hasNoProducts = $hasNoProducts" "Cyan"
	
	if ($hasNoProducts -or $ArrayProduct1C.Count -eq 0) {
		Write-DebugWithTime "Продукты не найдены. Выход из функции" "Yellow"
		Write-ToOutput "Не установлен продукт 1С:Предприятие 8" ([System.Drawing.Color]::Yellow)
		return
	}
	
	# Диалог выбора продукта
	# Формируем список для диалога - каждый продукт с номером
	Write-DebugWithTime "Формирование списка продуктов для диалога выбора" "Cyan"
	$productItems = @()
	for ($i = 0; $i -lt $ArrayProduct1C.Count; $i++) {
		# Явно преобразуем каждый продукт в строку для правильного отображения
		$productStr = $ArrayProduct1C[$i].ToString()
		$productItems += "$($i+1). $productStr"
	}
	Write-DebugWithTime "Список продуктов сформирован. Количество элементов: $($productItems.Count)" "Cyan"
	
	Write-DebugWithTime "Открытие диалога выбора продукта" "Cyan"
	$selectedProductIndex = Show-SelectionDialog -Title "Выбор продукта" -Prompt "Выберите продукт для удаления" -Items $productItems -CancelText "Отмена"
	Write-DebugWithTime "Диалог закрыт. selectedProductIndex = $selectedProductIndex" "Cyan"
	
	if ($null -eq $selectedProductIndex) {
		Write-DebugWithTime "Пользователь отменил выбор продукта. Выход из функции" "Yellow"
		Write-ToOutputColored "[ОШИБКА] Выбор продукта для удаления прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	
	# Получаем выбранный продукт из $ArrayProduct1C через foreach с индексом
	# Аналогично функции установки сервера
	Write-DebugWithTime "Получение выбранного продукта по индексу $selectedProductIndex" "Cyan"
	$selectedProduct = $null
	$currentIndex = 0
	foreach ($product in $ArrayProduct1C) {
		if ($currentIndex -eq ($selectedProductIndex - 1)) {
			$selectedProduct = $product.ToString()
			Write-DebugWithTime "Выбранный продукт: $selectedProduct" "Green"
			break
		}
		$currentIndex++
	}
	
	if ($null -eq $selectedProduct) {
		Write-DebugWithTime "ОШИБКА: Не удалось получить выбранный продукт. Выход из функции" "Red"
		Write-ToOutputColored "[ОШИБКА] Не удалось получить выбранный продукт" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	
	# Обновляем прогресс-бар для анимации во время удаления
	Write-DebugWithTime "Обновление главного прогресс-бара и запуск анимации" "Cyan"
	Update-ProgressBar -Status "Выполнение удаления сервера 1С..."
	# Убеждаемся, что прогресс-бар в режиме анимации Marquee и таймер запущен
	if ($Global:ProgressBar -ne $null) {
		$Global:ProgressBar.Style = "Marquee"
		$Global:ProgressBar.MarqueeAnimationSpeed = 50
		# Принудительно обновляем прогресс-бар и форму для немедленного отображения
		$Global:ProgressBar.Update()
		$Global:ProgressForm.Update()
		# Множественные вызовы DoEvents() для обработки всех событий
		for ($i = 0; $i -lt 10; $i++) {
			[System.Windows.Forms.Application]::DoEvents()
		}
	}
	# Запускаем таймер для плавной анимации
	Start-ProgressBarAnimation
	Write-DebugWithTime "Таймер анимации запущен" "Cyan"
	# Дополнительное обновление UI после запуска таймера для немедленного старта анимации
	for ($i = 0; $i -lt 10; $i++) {
		[System.Windows.Forms.Application]::DoEvents()
	}
	
	# Получаем путь к папке рабочих процессов перед запуском Job для отслеживания прогресса
	Write-DebugWithTime "Начало получения пути к папке рабочих процессов. isLocal = $isLocal" "Cyan"
	$jobProcessPathForProgress = $null
	
	if ($isLocal) {
		# Для локального выполнения получаем путь из службы
		Write-DebugWithTime "Локальное получение пути к папке рабочих процессов" "Cyan"
		try {
			$SplitNameProduct1C = $selectedProduct.Split(" ")
			$ReplaceSplitNameProduct1C = $null
			if ($SplitNameProduct1C.Count -ge 4) {
				$ReplaceSplitNameProduct1C = $SplitNameProduct1C[3].Replace("(", "").Replace(")", "")
			}
			Write-DebugWithTime "Версия продукта для поиска службы: $ReplaceSplitNameProduct1C" "Cyan"
			
			if ($null -ne $ReplaceSplitNameProduct1C -and $ReplaceSplitNameProduct1C -ne "") {
				$serviceMatch = Get-WmiObject win32_service | Where-Object {$_.PathName -match $ReplaceSplitNameProduct1C}
				Write-DebugWithTime "Найдено служб: $($serviceMatch.Count)" "Cyan"
				
				if ($null -ne $serviceMatch) {
					$serviceInfo = Get-WmiObject win32_service | Where-Object {$_.Name -eq $serviceMatch.Name}
					Write-DebugWithTime "PathName службы: $($serviceInfo.PathName)" "Cyan"
					
					if ($null -ne $serviceInfo -and $null -ne $serviceInfo.PathName) {
						if ($serviceInfo.PathName -match '-d\s+"([^"]+)"') {
							$jobProcessPathForProgress = $matches[1].TrimEnd('\')
							Write-DebugWithTime "Извлечен путь к папке: $jobProcessPathForProgress" "Green"
						} else {
							Write-DebugWithTime "Не удалось извлечь путь из PathName (нет совпадения с регулярным выражением)" "Yellow"
						}
					} else {
						Write-DebugWithTime "serviceInfo или PathName = null" "Yellow"
					}
				} else {
					Write-DebugWithTime "Служба не найдена" "Yellow"
				}
			} else {
				Write-DebugWithTime "ReplaceSplitNameProduct1C пуст или null" "Yellow"
			}
		} catch {
			Write-DebugWithTime "ОШИБКА при получении пути (локально): $($_.Exception.Message)" "Red"
		}
	} else {
		# Для удаленного выполнения получаем путь через Invoke-Command
		Write-DebugWithTime "Удаленное получение пути к папке рабочих процессов на сервере $Server" "Cyan"
		try {
			$SplitNameProduct1C = $selectedProduct.Split(" ")
			$ReplaceSplitNameProduct1C = $null
			if ($SplitNameProduct1C.Count -ge 4) {
				$ReplaceSplitNameProduct1C = $SplitNameProduct1C[3].Replace("(", "").Replace(")", "")
			}
			Write-DebugWithTime "Версия продукта для поиска службы (удаленно): $ReplaceSplitNameProduct1C" "Cyan"
			
			if ($null -ne $ReplaceSplitNameProduct1C -and $ReplaceSplitNameProduct1C -ne "") {
				$serviceMatch = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
					param([string]$Version)
					Get-WmiObject win32_service | Where-Object {$_.PathName -match $Version}
				} -ArgumentList $ReplaceSplitNameProduct1C
				Write-DebugWithTime "Найдено служб (удаленно): $($serviceMatch.Count)" "Cyan"
				
				if ($null -ne $serviceMatch) {
					$serviceInfo = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
						param([string]$ServiceName)
						Get-WmiObject win32_service | Where-Object {$_.Name -eq $ServiceName}
					} -ArgumentList $serviceMatch.Name
					Write-DebugWithTime "PathName службы (удаленно): $($serviceInfo.PathName)" "Cyan"
					
					if ($null -ne $serviceInfo -and $null -ne $serviceInfo.PathName) {
						if ($serviceInfo.PathName -match '-d\s+"([^"]+)"') {
							$jobProcessPathForProgress = $matches[1].TrimEnd('\')
							Write-DebugWithTime "Извлечен путь к папке (удаленно): $jobProcessPathForProgress" "Green"
						} else {
							Write-DebugWithTime "Не удалось извлечь путь из PathName (нет совпадения с регулярным выражением)" "Yellow"
						}
					} else {
						Write-DebugWithTime "serviceInfo или PathName = null (удаленно)" "Yellow"
					}
				} else {
					Write-DebugWithTime "Служба не найдена (удаленно)" "Yellow"
				}
			} else {
				Write-DebugWithTime "ReplaceSplitNameProduct1C пуст или null (удаленно)" "Yellow"
			}
		} catch {
			Write-DebugWithTime "ОШИБКА при получении пути (удаленно): $($_.Exception.Message)" "Red"
		}
	}
	
	Write-DebugWithTime "Итоговый jobProcessPathForProgress = $jobProcessPathForProgress" "Cyan"
	
	# Write-Host "[DEBUG] Итоговый jobProcessPathForProgress = $jobProcessPathForProgress" -ForegroundColor Cyan
	
	# Подсчитываем файлы перед запуском Job для отслеживания прогресса
	Write-DebugWithTime "Начало подсчета файлов перед запуском Job" "Cyan"
	$totalFilesForProgress = 0
	$totalSizeMBForProgress = 0
	$showFolderProgressBar = $false
	$folderProgressBarShown = $false
	
	Write-DebugWithTime "Проверка существования папки: jobProcessPathForProgress = $jobProcessPathForProgress" "Cyan"
	
	if ($null -ne $jobProcessPathForProgress) {
		# Проверяем существование папки (локально или удаленно)
		$pathExists = $false
		if ($isLocal) {
			$pathExists = Test-Path $jobProcessPathForProgress -ErrorAction SilentlyContinue
		} else {
			$pathExists = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
				param([string]$Path)
				Test-Path $Path -ErrorAction SilentlyContinue
			} -ArgumentList $jobProcessPathForProgress
		}
		Write-DebugWithTime "Test-Path результат: $pathExists" "Cyan"
		
		if ($pathExists) {
			Write-DebugWithTime "Получен путь к папке: $jobProcessPathForProgress. Начало подсчета файлов" "Green"
			
			try {
				if ($isLocal) {
					Write-DebugWithTime "Локальный подсчет файлов" "Cyan"
					$allFilesForProgress = Get-ChildItem -Path $jobProcessPathForProgress -Recurse -File -Force -ErrorAction SilentlyContinue
				} else {
					Write-DebugWithTime "Удаленный подсчет файлов через Invoke-Command" "Cyan"
					$allFilesForProgress = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
						param([string]$Path)
						Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue
					} -ArgumentList $jobProcessPathForProgress
				}
				$totalFilesForProgress = if ($null -eq $allFilesForProgress) { 0 } else { $allFilesForProgress.Count }
				Write-DebugWithTime "Подсчитано файлов: $totalFilesForProgress" "Cyan"
				# Правильно вычисляем размер файлов
				if ($null -eq $allFilesForProgress -or $allFilesForProgress.Count -eq 0) {
					$totalSizeBytesForProgress = 0
				} else {
					if ($isLocal) {
						$totalSizeBytesForProgress = ($allFilesForProgress | Measure-Object -Property Length -Sum).Sum
				} else {
					# Для удаленного сервера всегда получаем размер через Invoke-Command для точности
					# (объекты FileInfo могут быть сериализованы неправильно при передаче через Invoke-Command)
					Write-DebugWithTime "Получение размера файлов через Invoke-Command (удаленно)" "Cyan"
					$totalSizeBytesForProgress = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
						param([string]$Path)
						try {
							# Получаем все файлы и суммируем их размеры (как в Job удаления)
							$files = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue
							if ($null -eq $files) {
								return 0
							}
							$totalSize = ($files | Measure-Object -Property Length -Sum).Sum
							return $totalSize
						} catch {
							return 0
						}
					} -ArgumentList $jobProcessPathForProgress
					
					if ($null -eq $totalSizeBytesForProgress) {
						$totalSizeBytesForProgress = 0
					}
				}
				}
				$totalSizeMBForProgress = [math]::Round($totalSizeBytesForProgress / 1MB, 0)
				Write-DebugWithTime "Подсчет завершен: totalFilesForProgress = $totalFilesForProgress, totalSizeMBForProgress = $totalSizeMBForProgress" "Green"
				
				# Инициализируем переменные для интерполяции
				$lastKnownDeletedFiles = 0
				$lastKnownDeletedMB = 0
				$lastKnownUpdateTime = Get-Date
				$deletionStartTime = Get-Date  # Запоминаем время начала удаления
				$progressBarUpdateCount = 0  # Сбрасываем счетчик обновлений
				Write-DebugWithTime "Инициализация переменных для интерполяции завершена" "Cyan"
				
				# Прогресс-бар будет показан в цикле после сообщения "Удаление содержимого папки..."
			} catch {
				Write-DebugWithTime "ОШИБКА при подсчете файлов: $($_.Exception.Message)" "Red"
			}
		} else {
			Write-DebugWithTime "Папка не существует по пути $jobProcessPathForProgress" "Yellow"
			$parentPath = Split-Path -Path $jobProcessPathForProgress -Parent -ErrorAction SilentlyContinue
			if ($null -ne $parentPath) {
				$parentExists = Test-Path $parentPath -ErrorAction SilentlyContinue
				Write-DebugWithTime "Родительская папка существует: $parentExists" "Cyan"
			}
			Write-DebugWithTime "Второй прогресс-бар будет показан в цикле (если папка появится)" "Yellow"
		}
	} else {
		Write-DebugWithTime "jobProcessPathForProgress = null, пропускаем подсчет файлов" "Yellow"
	}
	
	# Запускаем Job (локально или на удаленном сервере)
	Write-DebugWithTime "=== НАЧАЛО ПОДГОТОВКИ К ЗАПУСКУ JOB ===" "Yellow"
	Write-DebugWithTime "isLocal = $isLocal, selectedProduct = $selectedProduct" "Cyan"
	if ($isLocal) {
		# Для локального сервера создаем отдельный скрипт-блок, который выполняется напрямую без Invoke-Command
		Write-DebugWithTime "Создание локального скрипт-блока для удаления" "Cyan"
		$localRemoveScriptBlock = {
			param([string]$NameProduct1C)
			
			# Отключаем подтверждения для всех команд удаления
			$ConfirmPreference = 'None'
			
			try {
				# Определяем версию продукта из названия для поиска службы
				$SplitNameProduct1C = $NameProduct1C.Split(" ")
				$ReplaceSplitNameProduct1C = $null
				
				# Безопасное извлечение версии (4-й элемент после разбиения)
				if ($SplitNameProduct1C.Count -ge 4) {
					$ReplaceSplitNameProduct1C = $SplitNameProduct1C[3].Replace("(", "").Replace(")", "")
				}
				
				# Поиск службы по версии в PathName
				$NameService1C = $null
				if ($null -ne $ReplaceSplitNameProduct1C -and $ReplaceSplitNameProduct1C -ne "") {
					$serviceMatch = Get-WmiObject win32_service | Where-Object {$_.PathName -match $ReplaceSplitNameProduct1C}
					if ($null -ne $serviceMatch) {
						$NameService1C = $serviceMatch.Name
					}
				}
				
				# Если служба найдена - сначала останавливаем и удаляем её
				$jobProcessPath = $null
				if ($null -ne $NameService1C -and $NameService1C -ne "") {
					$serviceInfo = Get-WmiObject win32_service | Where-Object {$_.Name -eq $NameService1C}
					if ($null -ne $serviceInfo -and $null -ne $serviceInfo.PathName) {
						if ($serviceInfo.PathName -match '-d\s+"([^"]+)"') {
							$jobProcessPath = $matches[1].TrimEnd('\')
						}
					}
					
					# Этап 1: Остановка службы
					$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
					$msg = "[DEBUG $timestamp] Этап 1: Остановка службы $NameService1C|Cyan"
					Write-Output $msg
					$msg = "Остановка службы $NameService1C...|Yellow"
					Write-Output $msg
					
					$stopTimeout = 60
					$stopStartTime = Get-Date
					
					try {
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Вызов Stop-Service для службы $NameService1C|Cyan"
						Write-Output $msg
						Stop-Service $NameService1C -Force -ErrorAction Stop -WarningAction SilentlyContinue
						
						$NameService1CStatus = (Get-Service $NameService1C -ErrorAction SilentlyContinue).Status
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Статус службы после Stop-Service: $NameService1CStatus|Cyan"
						Write-Output $msg
						while ($NameService1CStatus -ne "Stopped") {
							$elapsedTime = (Get-Date) - $stopStartTime
							if ($elapsedTime.TotalSeconds -gt $stopTimeout) {
								throw "Таймаут ожидания остановки службы $NameService1C (превышено $stopTimeout секунд)"
							}
							
							Start-Sleep -Milliseconds 500
							$NameService1CStatus = (Get-Service $NameService1C -ErrorAction SilentlyContinue).Status
						}
						
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Служба $NameService1C успешно остановлена|Green"
						Write-Output $msg
						$msg = "[OK] Служба $NameService1C Остановлена|Red"
						Write-Output $msg
						Start-Sleep -Milliseconds 300
					}
					catch {
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] ОШИБКА при остановке службы: $($_.Exception.Message)|Red"
						Write-Output $msg
						$msg = "[ОШИБКА] Не удалось остановить службу $NameService1C : $($_.Exception.Message)|Red"
						Write-Output $msg
						throw
					}
					
					# Этап 2: Удаление службы
					$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
					$msg = "[DEBUG $timestamp] Этап 2: Удаление службы $NameService1C|Cyan"
					Write-Output $msg
					$deleteTimeout = 30
					$deleteStartTime = Get-Date
					
					$serviceExists = Get-WmiObject win32_service | Where-Object {$_.PathName -match $ReplaceSplitNameProduct1C}
					$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
					$msg = "[DEBUG $timestamp] Проверка существования службы. serviceExists = $($null -ne $serviceExists)|Cyan"
					Write-Output $msg
					if ($null -ne $serviceExists) {
						$msg = "Удаление службы $NameService1C...|Yellow"
						Write-Output $msg
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Вызов delete() для службы $NameService1C|Cyan"
						Write-Output $msg
						
						try {
							[void](($serviceExists).delete())
							
							while ($true) {
								$elapsedTime = (Get-Date) - $deleteStartTime
								if ($elapsedTime.TotalSeconds -gt $deleteTimeout) {
									throw "Таймаут ожидания удаления службы $NameService1C (превышено $deleteTimeout секунд)"
								}
								
								$serviceCheck = Get-WmiObject win32_service | Where-Object {$_.PathName -match $ReplaceSplitNameProduct1C}
								if ($null -eq $serviceCheck) {
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Служба $NameService1C успешно удалена|Green"
									Write-Output $msg
									$msg = "[OK] Служба $NameService1C Удалена|Green"
									Write-Output $msg
									Start-Sleep -Milliseconds 300
									break
								}
								
								Start-Sleep -Milliseconds 500
							}
						}
						catch {
							$msg = "[ОШИБКА] Не удалось удалить службу $NameService1C : $($_.Exception.Message)|Red"
							Write-Output $msg
							throw
						}
					}
				}
				
				# Этап 3: Удаление продукта с таймаутом
				$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
				$msg = "[DEBUG $timestamp] Этап 3: Удаление продукта $NameProduct1C (удаленный Job)|Cyan"
				Write-Output $msg
				$uninstallTimeout = 300
				$uninstallStartTime = Get-Date
				
				$msg = "Удаление продукта $NameProduct1C...|Yellow"
				Write-Output $msg
				
				try {
					$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
					$msg = "[DEBUG $timestamp] Поиск продукта через Get-WmiObject Win32_Product|Cyan"
					Write-Output $msg
					$productExists = Get-WmiObject Win32_Product -Filter "Name ='$NameProduct1C'" -ErrorAction SilentlyContinue
					if ($null -eq $productExists) {
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Продукт $NameProduct1C не найден (уже удален)|Yellow"
						Write-Output $msg
						$msg = "[OK] Продукт $NameProduct1C уже удален|Green"
						Write-Output $msg
						Start-Sleep -Milliseconds 300
					}
					else {
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Продукт найден. Вызов Uninstall()|Cyan"
						Write-Output $msg
						[void]($productExists.Uninstall())
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Uninstall() вызван, ожидание завершения удаления|Cyan"
						Write-Output $msg
						
						while ($true) {
							$elapsedTime = (Get-Date) - $uninstallStartTime
							if ($elapsedTime.TotalSeconds -gt $uninstallTimeout) {
								throw "Таймаут ожидания удаления продукта $NameProduct1C (превышено $uninstallTimeout секунд)"
							}
							
							$productCheck = Get-WmiObject Win32_Product -Filter "Name ='$NameProduct1C'" -ErrorAction SilentlyContinue
							if ($null -eq $productCheck) {
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$msg = "[DEBUG $timestamp] Продукт $NameProduct1C успешно удален (проверка завершена)|Green"
								Write-Output $msg
								$msg = "[OK] Продукт $NameProduct1C Удален|Green"
								Write-Output $msg
								Start-Sleep -Milliseconds 300
								break
							}
							
							Start-Sleep -Seconds 2
						}
					}
				}
				catch {
					$msg = "[ОШИБКА] Не удалось удалить продукт $NameProduct1C : $($_.Exception.Message)|Red"
					Write-Output $msg
					throw
				}
				
				# Этап 4: Удаление папки рабочих процессов
				$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
				$msg = "[DEBUG $timestamp] Этап 4: Удаление папки рабочих процессов. jobProcessPath = $jobProcessPath (удаленный Job)|Cyan"
				Write-Output $msg
				if ($null -ne $jobProcessPath -and $jobProcessPath -ne "") {
					if (Test-Path $jobProcessPath -ErrorAction SilentlyContinue) {
						$msg = "Удаление папки рабочих процессов: $jobProcessPath|Yellow"
						Write-Output $msg
						
						try {
							$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
							$msg = "[DEBUG $timestamp] Ожидание завершения процессов (20 секунд)|Cyan"
							Write-Output $msg
							$msg = "Ожидание завершения процессов (20 секунд)...|Yellow"
							Write-Output $msg
							Start-Sleep -Seconds 20
							
							$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
							$msg = "[DEBUG $timestamp] Проверка блокирующих процессов|Cyan"
							Write-Output $msg
							$msg = "Проверка блокирующих процессов...|Yellow"
							Write-Output $msg
							try {
								$processesUsingFiles = Get-Process | Where-Object {
									$_.Path -like "$jobProcessPath*"
								} -ErrorAction SilentlyContinue
								
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$processCount = if ($null -eq $processesUsingFiles) { 0 } else { $processesUsingFiles.Count }
								$msg = "[DEBUG $timestamp] Найдено процессов, использующих файлы: $processCount|Cyan"
								Write-Output $msg
								
								if ($null -ne $processesUsingFiles -and $processesUsingFiles.Count -gt 0) {
									$msg = "Обнаружено процессов, использующих файлы: $($processesUsingFiles.Count). Ожидание дополнительно 10 секунд...|Yellow"
									Write-Output $msg
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Дополнительное ожидание 10 секунд из-за блокирующих процессов|Cyan"
									Write-Output $msg
									Start-Sleep -Seconds 10
								}
							} catch {
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$msg = "[DEBUG $timestamp] Ошибка при проверке процессов: $($_.Exception.Message)|Yellow"
								Write-Output $msg
								# Игнорируем ошибки проверки процессов
							}
							
							$deleted = $false
							$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
							$msg = "[DEBUG $timestamp] Начало подсчета файлов для удаления (удаленный Job)|Cyan"
							Write-Output $msg
							$msg = "Подсчет файлов для удаления...|Yellow"
							Write-Output $msg
							$allFiles = @()
							try {
								$allFiles = Get-ChildItem -Path $jobProcessPath -Recurse -File -Force -ErrorAction SilentlyContinue
							} catch {
								# Игнорируем ошибки
							}
							
							$totalFiles = $allFiles.Count
							$totalSizeBytes = ($allFiles | Measure-Object -Property Length -Sum).Sum
							$totalSizeMB = [math]::Round($totalSizeBytes / 1MB, 2)
							$deletedFiles = 0
							$deletedSizeBytes = 0
							
							if ($totalFiles -gt 0) {
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$msg = "[DEBUG $timestamp] Подсчет завершен (удаленный Job): totalFiles = $totalFiles, totalSizeMB = $totalSizeMB|Green"
								Write-Output $msg
								$msg = "[OK] Найдено файлов: $totalFiles, общий размер: $totalSizeMB MB|White"
								Write-Output $msg
								Start-Sleep -Milliseconds 300
							}
							
							# Этап 5: Удаление содержимого папки
							# $msg = "Удаление содержимого папки...|Yellow"
							# Write-Output $msg  # Удалено из вывода по запросу пользователя
							$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
							$msg = "[DEBUG $timestamp] Этап 5: НАЧАЛО УДАЛЕНИЯ ФАЙЛОВ В JOB (удаленный Job). jobProcessPath = $jobProcessPath|Red"
							Write-Output $msg
							try {
								$allFilesToDelete = Get-ChildItem -Path $jobProcessPath -Recurse -File -Force -ErrorAction SilentlyContinue
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$msg = "[DEBUG $timestamp] Найдено файлов для удаления: $($allFilesToDelete.Count)|Red"
								Write-Output $msg
								
								if ($null -ne $allFilesToDelete -and $allFilesToDelete.Count -gt 0) {
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Начало цикла удаления файлов. Всего файлов: $($allFilesToDelete.Count)|Red"
									Write-Output $msg
									$fileIndex = 0
									foreach ($file in $allFilesToDelete) {
										$fileIndex++
										if ($fileIndex % 100 -eq 0) {
											$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
											$msg = "[DEBUG $timestamp] Удалено файлов в цикле: $fileIndex из $($allFilesToDelete.Count)|Red"
											Write-Output $msg
										}
										try {
											Remove-Item -Path $file.FullName -Force -Confirm:$false -ErrorAction SilentlyContinue
											$deletedFiles++
											$deletedSizeBytes += $file.Length
										} catch {
											# Игнорируем ошибки для отдельных файлов
										}
									}
									
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Завершено удаление файлов. Удалено файлов: $deletedFiles, размер: $([math]::Round($deletedSizeBytes / 1MB, 2)) MB|Green"
									Write-Output $msg
									
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Начало удаления подпапок|Cyan"
									Write-Output $msg
									$allDirsToDelete = Get-ChildItem -Path $jobProcessPath -Recurse -Directory -Force -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
									$dirCount = if ($null -eq $allDirsToDelete) { 0 } else { $allDirsToDelete.Count }
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Найдено подпапок для удаления: $dirCount|Cyan"
									Write-Output $msg
									if ($null -ne $allDirsToDelete) {
										$dirIndex = 0
										foreach ($dir in $allDirsToDelete) {
											$dirIndex++
											try {
												Remove-Item -Path $dir.FullName -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
											} catch {
												$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
												$msg = "[DEBUG $timestamp] Ошибка при удалении подпапки $($dir.FullName): $($_.Exception.Message)|Yellow"
												Write-Output $msg
												# Игнорируем ошибки для отдельных папок
											}
										}
										$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
										$msg = "[DEBUG $timestamp] Завершено удаление подпапок. Удалено: $dirIndex из $dirCount|Green"
										Write-Output $msg
									}
									
									$folderName = Split-Path -Path $jobProcessPath -Leaf
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Содержимое папки $folderName удалено. Файлов: $deletedFiles, размер: $([math]::Round($deletedSizeBytes / 1MB, 2)) MB|Green"
									Write-Output $msg
									# $msg = "[OK] Содержимое $folderName ($deletedFiles файлов, $([math]::Round($deletedSizeBytes / 1MB, 2)) MB) Удалена|White"
									# Write-Output $msg  # Удалено из вывода по запросу пользователя
									Start-Sleep -Milliseconds 300
								} else {
									$msg = "Папка пуста|Yellow"
									Write-Output $msg
								}
								
								Start-Sleep -Milliseconds 500
								
								# Этап 6: Удаление родительской папки
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$msg = "[DEBUG $timestamp] Этап 6: Удаление родительской папки $jobProcessPath (удаленный Job)|Cyan"
								Write-Output $msg
								# $msg = "Удаление родительской папки...|Yellow"
								# Write-Output $msg  # Удалено из вывода по запросу пользователя
								$parentDeleted = $false
								for ($attempt = 1; $attempt -le 3; $attempt++) {
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Попытка $attempt из 3: удаление родительской папки $jobProcessPath|Cyan"
									Write-Output $msg
									try {
										Remove-Item -Path $jobProcessPath -Recurse -Force -Confirm:$false -ErrorAction Stop
										$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
										$msg = "[DEBUG $timestamp] Remove-Item выполнен, проверка существования папки|Cyan"
										Write-Output $msg
										Start-Sleep -Milliseconds 500
										if (-not (Test-Path $jobProcessPath -ErrorAction SilentlyContinue)) {
											$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
											$msg = "[DEBUG $timestamp] Родительская папка успешно удалена|Green"
											Write-Output $msg
											$parentDeleted = $true
											break
										} else {
											$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
											$msg = "[DEBUG $timestamp] Папка все еще существует после Remove-Item|Yellow"
											Write-Output $msg
										}
									} catch {
										$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
										$msg = "[DEBUG $timestamp] Ошибка при попытке $attempt удаления родительской папки: $($_.Exception.Message)|Yellow"
										Write-Output $msg
										if ($attempt -lt 3) {
											Start-Sleep -Seconds 1
										}
									}
								}
								
								if ($parentDeleted) {
									$deleted = $true
									$msg = "[OK] Папка рабочих процессов Удалена|Green"
									Write-Output $msg
								} else {
									$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось полностью удалить папку рабочих процессов $jobProcessPath. Рекомендуется удалить папку вручную (Shift+Del) после завершения всех процессов.|Yellow"
									Write-Output $msg
								}
							}
							catch {
								$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось удалить папку рабочих процессов $jobProcessPath : $($_.Exception.Message). Рекомендуется удалить папку вручную.|Yellow"
								Write-Output $msg
							}
							
							if (-not $deleted) {
								$msg = "[ПРЕДУПРЕЖДЕНИЕ] Папка рабочих процессов не была полностью удалена: $jobProcessPath. Рекомендуется удалить папку вручную (Shift+Del) после завершения всех процессов.|Yellow"
								Write-Output $msg
							}
						}
						catch {
							$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось удалить папку рабочих процессов $jobProcessPath : $($_.Exception.Message). Рекомендуется удалить папку вручную.|Yellow"
							Write-Output $msg
						}
					} else {
						$msg = "Папка рабочих процессов не найдена: $jobProcessPath|Yellow"
						Write-Output $msg
					}
				}
			}
			catch {
				$msg = "[ОШИБКА] $($_.Exception.Message)|Red"
				Write-Output $msg
			}
		}
		
		# Запускаем Job локально через Start-Job
		Write-DebugWithTime "Запуск локального Job через Start-Job" "Green"
		$removeJob = Start-Job -ScriptBlock $localRemoveScriptBlock -ArgumentList $selectedProduct
		Write-DebugWithTime "Job запущен. Job ID = $($removeJob.Id), State = $($removeJob.State)" "Green"
	} else {
		# Для удаленного сервера создаем отдельный скрипт-блок, который выполняется напрямую на удаленном сервере
		# без повторного вызова Invoke-Command внутри
		$remoteRemoveScriptBlock = {
			param([string]$NameProduct1C)
			
			# Отключаем подтверждения для всех команд удаления
			$ConfirmPreference = 'None'
			
			try {
				# Определяем версию продукта из названия для поиска службы
				$SplitNameProduct1C = $NameProduct1C.Split(" ")
				$ReplaceSplitNameProduct1C = $null
				
				# Безопасное извлечение версии (4-й элемент после разбиения)
				if ($SplitNameProduct1C.Count -ge 4) {
					$ReplaceSplitNameProduct1C = $SplitNameProduct1C[3].Replace("(", "").Replace(")", "")
				}
				
				# Поиск службы по версии в PathName
				$NameService1C = $null
				if ($null -ne $ReplaceSplitNameProduct1C -and $ReplaceSplitNameProduct1C -ne "") {
					$serviceMatch = Get-WmiObject win32_service | Where-Object {$_.PathName -match $ReplaceSplitNameProduct1C}
					if ($null -ne $serviceMatch) {
						$NameService1C = $serviceMatch.Name
					}
				}
				
				# Если служба найдена - сначала останавливаем и удаляем её
				$jobProcessPath = $null  # Путь к папке для рабочих процессов
				if ($null -ne $NameService1C -and $NameService1C -ne "") {
					# Получаем PathName службы для извлечения пути к папке рабочих процессов
					$serviceInfo = Get-WmiObject win32_service | Where-Object {$_.Name -eq $NameService1C}
					if ($null -ne $serviceInfo -and $null -ne $serviceInfo.PathName) {
						# Извлекаем путь после параметра -d из PathName
						if ($serviceInfo.PathName -match '-d\s+"([^"]+)"') {
							$jobProcessPath = $matches[1].TrimEnd('\')
						}
					}
					
					# Этап 1: Остановка службы
					$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
					$msg = "[DEBUG $timestamp] Этап 1: Остановка службы $NameService1C (удаленный Job)|Cyan"
					Write-Output $msg
					$msg = "Остановка службы $NameService1C...|Yellow"
					Write-Output $msg
					
					# Остановка службы с таймаутом
					$stopTimeout = 60
					$stopStartTime = Get-Date
					
					try {
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Вызов Stop-Service для службы $NameService1C (удаленный Job)|Cyan"
						Write-Output $msg
						Stop-Service $NameService1C -Force -ErrorAction Stop -WarningAction SilentlyContinue
						
						$NameService1CStatus = (Get-Service $NameService1C -ErrorAction SilentlyContinue).Status
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Статус службы после Stop-Service (удаленный Job): $NameService1CStatus|Cyan"
						Write-Output $msg
						while ($NameService1CStatus -ne "Stopped") {
							$elapsedTime = (Get-Date) - $stopStartTime
							if ($elapsedTime.TotalSeconds -gt $stopTimeout) {
								throw "Таймаут ожидания остановки службы $NameService1C (превышено $stopTimeout секунд)"
							}
							
							Start-Sleep -Milliseconds 500
							$NameService1CStatus = (Get-Service $NameService1C -ErrorAction SilentlyContinue).Status
						}
						
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Служба $NameService1C успешно остановлена (удаленный Job)|Green"
						Write-Output $msg
						$msg = "[OK] Служба $NameService1C Остановлена|Red"
						Write-Output $msg
						Start-Sleep -Milliseconds 300
					}
					catch {
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] ОШИБКА при остановке службы (удаленный Job): $($_.Exception.Message)|Red"
						Write-Output $msg
						$msg = "[ОШИБКА] Не удалось остановить службу $NameService1C : $($_.Exception.Message)|Red"
						Write-Output $msg
						throw
					}
					
					# Этап 2: Удаление службы с таймаутом
					$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
					$msg = "[DEBUG $timestamp] Этап 2: Удаление службы $NameService1C (удаленный Job)|Cyan"
					Write-Output $msg
					$deleteTimeout = 30
					$deleteStartTime = Get-Date
					
					$serviceExists = Get-WmiObject win32_service | Where-Object {$_.PathName -match $ReplaceSplitNameProduct1C}
					$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
					$msg = "[DEBUG $timestamp] Проверка существования службы. serviceExists = $($null -ne $serviceExists)|Cyan"
					Write-Output $msg
					if ($null -ne $serviceExists) {
						$msg = "Удаление службы $NameService1C...|Yellow"
						Write-Output $msg
						
						try {
							$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
							$msg = "[DEBUG $timestamp] Вызов delete() для службы $NameService1C|Cyan"
							Write-Output $msg
							[void](($serviceExists).delete())
							
							while ($true) {
								$elapsedTime = (Get-Date) - $deleteStartTime
								if ($elapsedTime.TotalSeconds -gt $deleteTimeout) {
									throw "Таймаут ожидания удаления службы $NameService1C (превышено $deleteTimeout секунд)"
								}
								
								$serviceCheck = Get-WmiObject win32_service | Where-Object {$_.PathName -match $ReplaceSplitNameProduct1C}
								if ($null -eq $serviceCheck) {
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Служба $NameService1C успешно удалена|Green"
									Write-Output $msg
									$msg = "[OK] Служба $NameService1C Удалена|Green"
									Write-Output $msg
									Start-Sleep -Milliseconds 300
									break
								}
								
								Start-Sleep -Milliseconds 500
							}
						}
						catch {
							$msg = "[ОШИБКА] Не удалось удалить службу $NameService1C : $($_.Exception.Message)|Red"
							Write-Output $msg
							throw
						}
					}
				}
				
				# Этап 3: Удаление продукта с таймаутом
				$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
				$msg = "[DEBUG $timestamp] Этап 3: Удаление продукта $NameProduct1C (удаленный Job)|Cyan"
				Write-Output $msg
				$uninstallTimeout = 300
				$uninstallStartTime = Get-Date
				
				$msg = "Удаление продукта $NameProduct1C...|Yellow"
				Write-Output $msg
				
				try {
					$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
					$msg = "[DEBUG $timestamp] Поиск продукта через Get-WmiObject Win32_Product|Cyan"
					Write-Output $msg
					$productExists = Get-WmiObject Win32_Product -Filter "Name ='$NameProduct1C'" -ErrorAction SilentlyContinue
					if ($null -eq $productExists) {
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Продукт $NameProduct1C не найден (уже удален)|Yellow"
						Write-Output $msg
						$msg = "[OK] Продукт $NameProduct1C уже удален|Green"
						Write-Output $msg
						Start-Sleep -Milliseconds 300
					}
					else {
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Продукт найден. Вызов Uninstall()|Cyan"
						Write-Output $msg
						[void]($productExists.Uninstall())
						$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
						$msg = "[DEBUG $timestamp] Uninstall() вызван, ожидание завершения удаления|Cyan"
						Write-Output $msg
						
						while ($true) {
							$elapsedTime = (Get-Date) - $uninstallStartTime
							if ($elapsedTime.TotalSeconds -gt $uninstallTimeout) {
								throw "Таймаут ожидания удаления продукта $NameProduct1C (превышено $uninstallTimeout секунд)"
							}
							
							$productCheck = Get-WmiObject Win32_Product -Filter "Name ='$NameProduct1C'" -ErrorAction SilentlyContinue
							if ($null -eq $productCheck) {
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$msg = "[DEBUG $timestamp] Продукт $NameProduct1C успешно удален (проверка завершена)|Green"
								Write-Output $msg
								$msg = "[OK] Продукт $NameProduct1C Удален|Green"
								Write-Output $msg
								Start-Sleep -Milliseconds 300
								break
							}
							
							Start-Sleep -Seconds 2
						}
					}
				}
				catch {
					$msg = "[ОШИБКА] Не удалось удалить продукт $NameProduct1C : $($_.Exception.Message)|Red"
					Write-Output $msg
					throw
				}
				
				# Этап 4: Удаление папки рабочих процессов
				$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
				$msg = "[DEBUG $timestamp] Этап 4: Удаление папки рабочих процессов. jobProcessPath = $jobProcessPath (удаленный Job)|Cyan"
				Write-Output $msg
				if ($null -ne $jobProcessPath -and $jobProcessPath -ne "") {
					if (Test-Path $jobProcessPath -ErrorAction SilentlyContinue) {
						$msg = "Удаление папки рабочих процессов: $jobProcessPath|Yellow"
						Write-Output $msg
						
						try {
							$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
							$msg = "[DEBUG $timestamp] Ожидание завершения процессов (20 секунд)|Cyan"
							Write-Output $msg
							$msg = "Ожидание завершения процессов (20 секунд)...|Yellow"
							Write-Output $msg
							Start-Sleep -Seconds 20
							
							$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
							$msg = "[DEBUG $timestamp] Проверка блокирующих процессов|Cyan"
							Write-Output $msg
							$msg = "Проверка блокирующих процессов...|Yellow"
							Write-Output $msg
							try {
								$processesUsingFiles = Get-Process | Where-Object {
									$_.Path -like "$jobProcessPath*"
								} -ErrorAction SilentlyContinue
								
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$processCount = if ($null -eq $processesUsingFiles) { 0 } else { $processesUsingFiles.Count }
								$msg = "[DEBUG $timestamp] Найдено процессов, использующих файлы: $processCount|Cyan"
								Write-Output $msg
								
								if ($null -ne $processesUsingFiles -and $processesUsingFiles.Count -gt 0) {
									$msg = "Обнаружено процессов, использующих файлы: $($processesUsingFiles.Count). Ожидание дополнительно 10 секунд...|Yellow"
									Write-Output $msg
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Дополнительное ожидание 10 секунд из-за блокирующих процессов|Cyan"
									Write-Output $msg
									Start-Sleep -Seconds 10
								}
							} catch {
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$msg = "[DEBUG $timestamp] Ошибка при проверке процессов: $($_.Exception.Message)|Yellow"
								Write-Output $msg
								# Игнорируем ошибки проверки процессов
							}
							
							$deleted = $false
							$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
							$msg = "[DEBUG $timestamp] Начало подсчета файлов для удаления (удаленный Job)|Cyan"
							Write-Output $msg
							$msg = "Подсчет файлов для удаления...|Yellow"
							Write-Output $msg
							$allFiles = @()
							try {
								$allFiles = Get-ChildItem -Path $jobProcessPath -Recurse -File -Force -ErrorAction SilentlyContinue
							} catch {
								# Игнорируем ошибки
							}
							
							$totalFiles = $allFiles.Count
							$totalSizeBytes = ($allFiles | Measure-Object -Property Length -Sum).Sum
							$totalSizeMB = [math]::Round($totalSizeBytes / 1MB, 2)
							$deletedFiles = 0
							$deletedSizeBytes = 0
							
							if ($totalFiles -gt 0) {
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$msg = "[DEBUG $timestamp] Подсчет завершен (удаленный Job): totalFiles = $totalFiles, totalSizeMB = $totalSizeMB|Green"
								Write-Output $msg
								$msg = "[OK] Найдено файлов: $totalFiles, общий размер: $totalSizeMB MB|White"
								Write-Output $msg
								Start-Sleep -Milliseconds 300
							}
							
							# Этап 5: Удаление содержимого папки
							# $msg = "Удаление содержимого папки...|Yellow"
							# Write-Output $msg  # Удалено из вывода по запросу пользователя
							$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
							$msg = "[DEBUG $timestamp] Этап 5: НАЧАЛО УДАЛЕНИЯ ФАЙЛОВ В JOB (удаленный Job). jobProcessPath = $jobProcessPath|Red"
							Write-Output $msg
							try {
								$allFilesToDelete = Get-ChildItem -Path $jobProcessPath -Recurse -File -Force -ErrorAction SilentlyContinue
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$msg = "[DEBUG $timestamp] Найдено файлов для удаления: $($allFilesToDelete.Count)|Red"
								Write-Output $msg
								
								if ($null -ne $allFilesToDelete -and $allFilesToDelete.Count -gt 0) {
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Начало цикла удаления файлов. Всего файлов: $($allFilesToDelete.Count)|Red"
									Write-Output $msg
									$fileIndex = 0
									foreach ($file in $allFilesToDelete) {
										$fileIndex++
										if ($fileIndex % 100 -eq 0) {
											$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
											$msg = "[DEBUG $timestamp] Удалено файлов в цикле: $fileIndex из $($allFilesToDelete.Count)|Red"
											Write-Output $msg
										}
										try {
											Remove-Item -Path $file.FullName -Force -Confirm:$false -ErrorAction SilentlyContinue
											$deletedFiles++
											$deletedSizeBytes += $file.Length
										} catch {
											# Игнорируем ошибки для отдельных файлов
										}
									}
									
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Завершено удаление файлов. Удалено файлов: $deletedFiles, размер: $([math]::Round($deletedSizeBytes / 1MB, 2)) MB|Green"
									Write-Output $msg
									
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Начало удаления подпапок|Cyan"
									Write-Output $msg
									$allDirsToDelete = Get-ChildItem -Path $jobProcessPath -Recurse -Directory -Force -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
									$dirCount = if ($null -eq $allDirsToDelete) { 0 } else { $allDirsToDelete.Count }
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Найдено подпапок для удаления: $dirCount|Cyan"
									Write-Output $msg
									if ($null -ne $allDirsToDelete) {
										$dirIndex = 0
										foreach ($dir in $allDirsToDelete) {
											$dirIndex++
											try {
												Remove-Item -Path $dir.FullName -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
											} catch {
												$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
												$msg = "[DEBUG $timestamp] Ошибка при удалении подпапки $($dir.FullName): $($_.Exception.Message)|Yellow"
												Write-Output $msg
												# Игнорируем ошибки для отдельных папок
											}
										}
										$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
										$msg = "[DEBUG $timestamp] Завершено удаление подпапок. Удалено: $dirIndex из $dirCount|Green"
										Write-Output $msg
									}
									
									$folderName = Split-Path -Path $jobProcessPath -Leaf
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Содержимое папки $folderName удалено. Файлов: $deletedFiles, размер: $([math]::Round($deletedSizeBytes / 1MB, 2)) MB|Green"
									Write-Output $msg
									# $msg = "[OK] Содержимое $folderName ($deletedFiles файлов, $([math]::Round($deletedSizeBytes / 1MB, 2)) MB) Удалена|White"
									# Write-Output $msg  # Удалено из вывода по запросу пользователя
									Start-Sleep -Milliseconds 300
								} else {
									$msg = "Папка пуста|Yellow"
									Write-Output $msg
								}
								
								Start-Sleep -Milliseconds 500
								
								# Этап 6: Удаление родительской папки
								$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
								$msg = "[DEBUG $timestamp] Этап 6: Удаление родительской папки $jobProcessPath (удаленный Job)|Cyan"
								Write-Output $msg
								# $msg = "Удаление родительской папки...|Yellow"
								# Write-Output $msg  # Удалено из вывода по запросу пользователя
								$parentDeleted = $false
								for ($attempt = 1; $attempt -le 3; $attempt++) {
									$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
									$msg = "[DEBUG $timestamp] Попытка $attempt из 3: удаление родительской папки $jobProcessPath|Cyan"
									Write-Output $msg
									try {
										Remove-Item -Path $jobProcessPath -Recurse -Force -Confirm:$false -ErrorAction Stop
										$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
										$msg = "[DEBUG $timestamp] Remove-Item выполнен, проверка существования папки|Cyan"
										Write-Output $msg
										Start-Sleep -Milliseconds 500
										if (-not (Test-Path $jobProcessPath -ErrorAction SilentlyContinue)) {
											$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
											$msg = "[DEBUG $timestamp] Родительская папка успешно удалена|Green"
											Write-Output $msg
											$parentDeleted = $true
											break
										} else {
											$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
											$msg = "[DEBUG $timestamp] Папка все еще существует после Remove-Item|Yellow"
											Write-Output $msg
										}
									} catch {
										$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
										$msg = "[DEBUG $timestamp] Ошибка при попытке $attempt удаления родительской папки: $($_.Exception.Message)|Yellow"
										Write-Output $msg
										if ($attempt -lt 3) {
											Start-Sleep -Seconds 1
										}
									}
								}
								
								if ($parentDeleted) {
									$deleted = $true
									$msg = "[OK] Папка рабочих процессов Удалена|Green"
									Write-Output $msg
								} else {
									$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось полностью удалить папку рабочих процессов $jobProcessPath. Рекомендуется удалить папку вручную (Shift+Del) после завершения всех процессов.|Yellow"
									Write-Output $msg
								}
							}
							catch {
								$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось удалить папку рабочих процессов $jobProcessPath : $($_.Exception.Message). Рекомендуется удалить папку вручную.|Yellow"
								Write-Output $msg
							}
							
							if (-not $deleted) {
								$msg = "[ПРЕДУПРЕЖДЕНИЕ] Папка рабочих процессов не была полностью удалена: $jobProcessPath. Рекомендуется удалить папку вручную (Shift+Del) после завершения всех процессов.|Yellow"
								Write-Output $msg
							}
						}
						catch {
							$msg = "[ПРЕДУПРЕЖДЕНИЕ] Не удалось удалить папку рабочих процессов $jobProcessPath : $($_.Exception.Message). Рекомендуется удалить папку вручную.|Yellow"
							Write-Output $msg
						}
					} else {
						$msg = "Папка рабочих процессов не найдена: $jobProcessPath|Yellow"
						Write-Output $msg
					}
				}
			}
			catch {
				$msg = "[ОШИБКА] $($_.Exception.Message)|Red"
				Write-Output $msg
			}
		}
		
		# Запускаем Job на удаленном сервере через Invoke-Command -AsJob
		Write-DebugWithTime "Запуск удаленного Job через Invoke-Command -AsJob на сервере $Server" "Green"
		$removeJob = Invoke-Command -ComputerName $Server -ScriptBlock $remoteRemoveScriptBlock -ArgumentList $selectedProduct -AsJob
		Write-DebugWithTime "Job запущен. Job ID = $($removeJob.Id), State = $($removeJob.State)" "Green"
	}
	
	# Даем Job время начать выполнение перед проверкой папки
	Start-Sleep -Milliseconds 500
	[System.Windows.Forms.Application]::DoEvents()
	
	# Прогресс-бар будет показан сразу после получения сообщения "[OK] Продукт ... Удален"
	
	# Ждем завершения Job с активным обновлением UI и отслеживанием прогресса удаления папки
	$lastProgressUpdate = Get-Date
	$lastFolderCheck = Get-Date
	$lastKnownDeletedFiles = 0
	$lastKnownDeletedMB = 0
	$lastInterpolatedFiles = 0  # Отдельная переменная для интерполированного значения (независимо от реального подсчета)
	$lastInterpolatedMB = 0  # Отдельная переменная для интерполированного значения (независимо от реального подсчета)
	$lastKnownUpdateTime = Get-Date
	$progressBarUpdateCount = 0  # Счетчик обновлений прогресс-бара для гарантии минимум 10 обновлений
	$deletionStartTime = $null  # Будет установлено в момент показа прогресс-бара
	$progressBarShownTime = $null  # Время показа прогресс-бара для отслеживания длительности интерполяции
	$folderStillExists = $true  # Отслеживаем существование папки
	$loopIteration = 0  # Счетчик итераций цикла для DEBUG вывода
	$processedOutputLines = @()  # Массив для отслеживания уже выведенных строк
	$lastOutputCheckTime = Get-Date  # Время последней проверки вывода Job
	$fileCountingMessageReceived = $false  # Флаг получения сообщения "Подсчет файлов для удаления..."
	$productDeletedMessageReceived = $false  # Флаг получения сообщения "[OK] Продукт ... Удален"
	Write-DebugWithTime "=== НАЧАЛО ЦИКЛА ОБРАБОТКИ ВЫВОДА JOB ===" "Yellow"
	Write-DebugWithTime "Начальные значения: loopIteration = 0, folderStillExists = $folderStillExists, Job State = $($removeJob.State)" "Cyan"
	while (($removeJob.State -eq "Running" -or $removeJob.State -eq "Blocked") -or $folderStillExists) {
		$loopIteration++
		if ($loopIteration % 50 -eq 0) {
			Write-DebugWithTime "Итерация цикла: $loopIteration, Job State = $($removeJob.State), folderStillExists = $folderStillExists" "Cyan"
		}
		# Проверяем наличие папки и файлов каждые 0.1 секунды для быстрого показа прогресс-бара
		$currentTime = Get-Date
		# ИСПРАВЛЕНО: Проверяем на $null перед вычитанием дат, чтобы избежать ошибки "op_Subtraction"
		$timeSinceLastFolderCheck = if ($null -ne $lastFolderCheck) { ($currentTime - $lastFolderCheck).TotalSeconds } else { 0 }
		$timeSinceLastOutputCheck = if ($null -ne $lastOutputCheckTime) { ($currentTime - $lastOutputCheckTime).TotalSeconds } else { 0 }
		
		# Получаем промежуточные результаты из Job для вывода по мере выполнения (каждые 0.5 секунды)
		if ($timeSinceLastOutputCheck -ge 0.5) {
			try {
				if ($removeJob.HasMoreData) {
					$newOutput = Receive-Job -Job $removeJob -ErrorAction SilentlyContinue
					if ($null -ne $newOutput) {
						$outputArray = @()
						if ($newOutput -is [System.Array]) {
							foreach ($item in $newOutput) {
								if ($item -is [System.Array]) {
									$outputArray += $item
								} else {
									$outputArray += $item
								}
							}
						} else {
							$outputArray = @($newOutput)
						}
						
						# Выводим только новые строки
						foreach ($line in $outputArray) {
							if ($line -notin $processedOutputLines) {
								$processedOutputLines += $line
								Write-OutputResults -OutputLines @($line)
								[System.Windows.Forms.Application]::DoEvents()
								
								# Проверяем сообщения для управления прогресс-баром
								$lineStr = $line.ToString()
								
								# КРИТИЧНО: Показываем прогресс-бар сразу после получения сообщения "[OK] Продукт ... Удален"
								# Это происходит ДО начала удаления файлов (Этап 5), что гарантирует правильный момент показа
								if ($lineStr -match "\[OK\]\s+Продукт.*Удален") {
									$productDeletedMessageReceived = $true
									Write-DebugWithTime "Получено сообщение '[OK] Продукт ... Удален'. productDeletedMessageReceived = $productDeletedMessageReceived" "Yellow"
									
									# Показываем прогресс-бар сразу после удаления продукта, используя данные из предварительного подсчета
									if (-not $folderProgressBarShown -and $totalFilesForProgress -gt 0 -and $totalSizeMBForProgress -gt 0) {
										if ($null -ne $jobProcessPathForProgress -and $totalFilesForProgress -gt 0 -and $totalSizeMBForProgress -gt 0) {
											Write-DebugWithTime "ПОКАЗ ПРОГРЕСС-БАРА (после удаления продукта): jobProcessPathForProgress = $jobProcessPathForProgress" "Yellow"
											Write-DebugWithTime "Используем данные из предварительного подсчета: TotalFiles = $totalFilesForProgress, TotalMB = $totalSizeMBForProgress" "Yellow"
											
											# Инициализируем переменные для интерполяции в момент показа прогресс-бара
											$deletionStartTime = Get-Date
											$progressBarShownTime = Get-Date
											$lastKnownDeletedFiles = 0
											$lastKnownDeletedMB = 0
											$lastInterpolatedFiles = 0
											$lastInterpolatedMB = 0
											$lastKnownUpdateTime = Get-Date
											$progressBarUpdateCount = 0
											
											Write-DebugWithTime "Инициализация переменных для интерполяции: deletionStartTime = $deletionStartTime, progressBarShownTime = $progressBarShownTime" "Cyan"
											
											try {
												Show-FolderDeletionProgressBar
												$showFolderProgressBar = $true
												$folderProgressBarShown = $true
												Start-Sleep -Milliseconds 100
												Update-FolderDeletionProgressBar -DeletedFiles 0 -TotalFiles $totalFilesForProgress -DeletedMB 0 -TotalMB $totalSizeMBForProgress
												Write-DebugWithTime "Прогресс-бар показан и обновлен с начальными значениями (после удаления продукта)" "Green"
												[System.Windows.Forms.Application]::DoEvents()
											} catch {
												$showFolderProgressBar = $false
												Write-DebugWithTime "ОШИБКА при показе прогресс-бара: $($_.Exception.Message)" "Red"
											}
										}
									}
								}
								
								# Проверяем, получено ли сообщение "Подсчет файлов для удаления..."
								if ($lineStr -match "Подсчет файлов для удаления") {
									$fileCountingMessageReceived = $true
									Write-DebugWithTime "Получено сообщение 'Подсчет файлов для удаления...'. fileCountingMessageReceived = $fileCountingMessageReceived" "Cyan"
								}
								
								# Извлекаем данные о файлах из сообщения "[OK] Найдено файлов: X, общий размер: Y MB"
								# Это сообщение приходит из Job, но прогресс-бар уже показан после удаления продукта
								if ($lineStr -match "\[OK\]\s+Найдено файлов:\s+(\d+),\s+общий размер:\s+([\d,\.]+)\s+MB") {
									$totalFilesForProgress = [int]$matches[1]
									$totalSizeMBForProgress = [math]::Round([double]($matches[2] -replace ',', '.'), 0)
									
									Write-DebugWithTime "Получены данные о файлах ИЗ JOB: totalFilesForProgress = $totalFilesForProgress, totalSizeMBForProgress = $totalSizeMBForProgress" "Cyan"
									# Прогресс-бар уже показан после удаления продукта, здесь только обновляем данные если нужно
								}
								
								# Не закрываем прогресс-бар после сообщения "[OK] Содержимое ... Удалена"
								# Он будет закрыт в блоке finally после завершения Job
							}
						}
					}
				}
				$lastOutputCheckTime = $currentTime
			} catch {
				# Игнорируем ошибки при получении промежуточных результатов
			}
		}
		
		# Проверяем существование папки для отслеживания состояния каждые 0.05 секунды
		# При пустой папке прогресс-бар папки не показывается — проверяем папку в любом случае, чтобы выйти из цикла и закрыть главный прогресс-бар
		if ($timeSinceLastFolderCheck -ge 0.05 -and $null -ne $jobProcessPathForProgress) {
			$lastFolderCheck = $currentTime
			try {
				# Проверяем существование папки (локально или удаленно)
				$pathExists = $false
				if ($isLocal) {
					$pathExists = Test-Path $jobProcessPathForProgress -ErrorAction SilentlyContinue
				} else {
					$pathExists = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
						param([string]$Path)
						Test-Path $Path -ErrorAction SilentlyContinue
					} -ArgumentList $jobProcessPathForProgress
				}
				
				if ($pathExists) {
					$folderStillExists = $true
				} else {
					$folderStillExists = $false
					# Папка удалена - показываем 100% только если еще не показывали
					if ($showFolderProgressBar -and $folderProgressBarShown -and $totalFilesForProgress -gt 0) {
						if ($lastKnownDeletedFiles -lt $totalFilesForProgress) {
							Update-FolderDeletionProgressBar -DeletedFiles $totalFilesForProgress -TotalFiles $totalFilesForProgress -DeletedMB $totalSizeMBForProgress -TotalMB $totalSizeMBForProgress
							$lastKnownDeletedFiles = $totalFilesForProgress
							$lastKnownDeletedMB = $totalSizeMBForProgress
							$progressBarUpdateCount++
							[System.Windows.Forms.Application]::DoEvents()
						}
					}
				}
			} catch {
				# Игнорируем ошибки при проверке папки
			}
		}
		
		# Обновляем прогресс удаления папки каждые 0.1 секунды (если папка существует) для более частого и плавного обновления
		# При пустой папке прогресс-бар папки не показывается — проверяем папку в любом случае, чтобы выйти из цикла и закрыть главный прогресс-бар
		$timeSinceLastUpdate = if ($null -ne $lastProgressUpdate) { ($currentTime - $lastProgressUpdate).TotalSeconds } else { 0 }
		
		if ($timeSinceLastUpdate -ge 0.1 -and $null -ne $jobProcessPathForProgress) {
			$lastProgressUpdate = $currentTime
			try {
				# Проверяем существование папки (локально или удаленно)
				$pathExists = $false
				if ($isLocal) {
					$pathExists = Test-Path $jobProcessPathForProgress -ErrorAction SilentlyContinue
				} else {
					$pathExists = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
						param([string]$Path)
						Test-Path $Path -ErrorAction SilentlyContinue
					} -ArgumentList $jobProcessPathForProgress
				}
				
				if ($pathExists) {
					$folderStillExists = $true
					# Подсчитываем оставшиеся файлы (оптимизированный метод для быстрого подсчета)
					Write-DebugWithTime "Начало реального подсчета файлов. jobProcessPathForProgress = $jobProcessPathForProgress" "Cyan"
					$remainingFilesCount = 0
					$remainingSizeBytes = 0
					
					if ($isLocal) {
						# Локальный подсчет - используем более быстрый метод
						$remainingFiles = Get-ChildItem -Path $jobProcessPathForProgress -Recurse -File -Force -ErrorAction SilentlyContinue
						$remainingFilesCount = if ($null -eq $remainingFiles) { 0 } else { $remainingFiles.Count }
						$remainingSizeBytes = if ($null -eq $remainingFiles -or $remainingFiles.Count -eq 0) { 0 } else { ($remainingFiles | Measure-Object -Property Length -Sum).Sum }
					} else {
						# Удаленный подсчет - используем Get-ChildItem для точного подсчета файлов в подпапках
						$remainingInfo = Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ScriptBlock {
							param([string]$Path, [int]$TotalFiles, [double]$TotalSizeMB)
							try {
								# Используем Get-ChildItem для точного подсчета всех файлов рекурсивно (включая подпапки)
								$files = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue
								
								$count = 0
								$size = 0
								
								if ($null -ne $files) {
									# Если это массив или коллекция
									if ($files -is [System.Array] -or $files -is [System.Collections.ICollection]) {
										$count = $files.Count
									} else {
										# Если это один объект
										$count = 1
									}
									
									# Подсчитываем размер
									if ($count -gt 0) {
										$size = ($files | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
										if ($null -eq $size) {
											$size = 0
										}
									}
								}
								
								return @{ Count = $count; Size = $size }
							} catch {
								# При ошибке возвращаем 0
								return @{ Count = 0; Size = 0 }
							}
						} -ArgumentList $jobProcessPathForProgress, $totalFilesForProgress, $totalSizeMBForProgress
						
						if ($null -ne $remainingInfo) {
							$remainingFilesCount = $remainingInfo.Count
							$remainingSizeBytes = $remainingInfo.Size
						} else {
							$remainingFilesCount = 0
							$remainingSizeBytes = 0
						}
					}
					
					$remainingSizeMB = [math]::Round($remainingSizeBytes / 1MB, 0)
					
					# Если начальный размер был 0, пересчитываем его на основе текущего размера
					if ($totalSizeMBForProgress -eq 0 -and $remainingFilesCount -gt 0 -and $remainingSizeMB -gt 0) {
						# Пересчитываем начальный размер на основе текущего размера и количества файлов
						if ($totalFilesForProgress -gt 0) {
							$avgSizePerFile = $remainingSizeBytes / $remainingFilesCount
							$totalSizeBytesForProgress = [math]::Round($avgSizePerFile * $totalFilesForProgress)
							$totalSizeMBForProgress = [math]::Round($totalSizeBytesForProgress / 1MB, 0)
						}
					}
					
					# Вычисляем количество удаленных файлов и размер
					$deletedFilesCount = if ($totalFilesForProgress -gt 0) { [math]::Max(0, $totalFilesForProgress - $remainingFilesCount) } else { 0 }
					$deletedSizeMB = if ($totalSizeMBForProgress -gt 0) { [math]::Max(0, $totalSizeMBForProgress - $remainingSizeMB) } else { 0 }
					
					Write-DebugWithTime "Реальный подсчет: remainingFilesCount = $remainingFilesCount, remainingSizeMB = $remainingSizeMB" "Cyan"
					Write-DebugWithTime "Вычислено: deletedFilesCount = $deletedFilesCount, deletedSizeMB = $deletedSizeMB" "Cyan"
					Write-DebugWithTime "Текущие значения: lastKnownDeletedFiles = $lastKnownDeletedFiles, lastKnownDeletedMB = $lastKnownDeletedMB" "Cyan"
					
					# КРИТИЧНО: Гарантируем монотонное возрастание - никогда не уменьшаем прогресс!
					# Если вычисленное значение меньше последнего известного (из-за ошибок подсчета), используем последнее известное
					if ($deletedFilesCount -lt $lastKnownDeletedFiles) {
						Write-DebugWithTime "КОРРЕКТИРОВКА: deletedFilesCount ($deletedFilesCount) < lastKnownDeletedFiles ($lastKnownDeletedFiles), используем lastKnownDeletedFiles" "Yellow"
						$deletedFilesCount = $lastKnownDeletedFiles
					}
					if ($deletedSizeMB -lt $lastKnownDeletedMB) {
						Write-DebugWithTime "КОРРЕКТИРОВКА: deletedSizeMB ($deletedSizeMB) < lastKnownDeletedMB ($lastKnownDeletedMB), используем lastKnownDeletedMB" "Yellow"
						$deletedSizeMB = $lastKnownDeletedMB
					}
					
					# ИСПРАВЛЕНО: Реальный подсчет обновляет $lastKnownDeletedFiles для ограничения интерполяции
					# И обновляет прогресс-бар до 100%, когда все файлы удалены, даже если интерполяция уже остановилась
					if ($showFolderProgressBar -and $folderProgressBarShown -and $totalFilesForProgress -gt 0) {
						if ($deletedFilesCount -gt $lastKnownDeletedFiles -or $deletedSizeMB -gt $lastKnownDeletedMB) {
							Write-DebugWithTime "РЕАЛЬНЫЙ ПОДСЧЕТ (для ограничения интерполяции): deletedFilesCount = $deletedFilesCount, deletedSizeMB = $deletedSizeMB" "Cyan"
							
							# Сохраняем последние известные значения для ограничения интерполяции сверху
							$lastKnownDeletedFiles = $deletedFilesCount
							$lastKnownDeletedMB = $deletedSizeMB
							
							# УЛУЧШЕНИЕ: Если реальный подсчет достиг 100%, обновляем прогресс-бар до 100% немедленно
							# Это гарантирует, что прогресс-бар достигнет 100%, даже если интерполяция уже остановилась
							if ($deletedFilesCount -ge $totalFilesForProgress -and $lastInterpolatedFiles -lt $totalFilesForProgress) {
								Write-DebugWithTime "ОБНОВЛЕНИЕ ДО 100% (реальный подсчет): deletedFilesCount = $deletedFilesCount из $totalFilesForProgress, интерполяция = $lastInterpolatedFiles" "Green"
								Update-FolderDeletionProgressBar -DeletedFiles $totalFilesForProgress -TotalFiles $totalFilesForProgress -DeletedMB $totalSizeMBForProgress -TotalMB $totalSizeMBForProgress
								$lastInterpolatedFiles = $totalFilesForProgress
								$lastInterpolatedMB = $totalSizeMBForProgress
								$progressBarUpdateCount++
							}
							
							# Дополнительное обновление UI
							[System.Windows.Forms.Application]::DoEvents()
						}
					}
				} else {
					# Папка удалена - показываем 100% даже если подсчет еще не завершился
					$folderStillExists = $false
					if ($showFolderProgressBar -and $folderProgressBarShown -and $totalFilesForProgress -gt 0) {
						# Папка удалена - показываем 100% только если еще не показывали
						if ($lastKnownDeletedFiles -lt $totalFilesForProgress) {
							Update-FolderDeletionProgressBar -DeletedFiles $totalFilesForProgress -TotalFiles $totalFilesForProgress -DeletedMB $totalSizeMBForProgress -TotalMB $totalSizeMBForProgress
							$lastKnownDeletedFiles = $totalFilesForProgress
							$lastKnownDeletedMB = $totalSizeMBForProgress
							$progressBarUpdateCount++
							[System.Windows.Forms.Application]::DoEvents()
						}
					}
					
					# Главный прогресс-бар остается в режиме Marquee с текстом "Выполнение удаления сервера 1С..."
					# Не обновляем его с информацией о файлах - это делает второй прогресс-бар
				}
			} catch {
				# Игнорируем ошибки при проверке прогресса
			}
		}
		
		# Убеждаемся, что главный прогресс-бар остается в режиме Marquee с правильным текстом
		if ($Global:ProgressBar -ne $null -and $Global:ProgressForm -ne $null -and $Global:ProgressForm.Visible) {
			# Убеждаемся, что прогресс-бар в режиме Marquee
			if ($Global:ProgressBar.Style -ne "Marquee") {
				$Global:ProgressBar.Style = "Marquee"
				$Global:ProgressBar.MarqueeAnimationSpeed = 50
			}
			# Убеждаемся, что текст правильный (без информации о файлах)
			if ($Global:ProgressLabel.Text -ne "Выполнение удаления сервера 1С...") {
				$Global:ProgressLabel.Text = "Выполнение удаления сервера 1С..."
			}
			# Принудительно обновляем прогресс-бар и форму
			$Global:ProgressBar.Refresh()
			$Global:ProgressForm.Refresh()
		}
		
		# Обновляем второй прогресс-бар с независимой интерполяцией для плавного прогресса
		# ИСПРАВЛЕНО: Интерполяция работает независимо от реального подсчета и всегда заполняет прогресс-бар плавно минимум 10 секунд
		if ($showFolderProgressBar -and $folderProgressBarShown -and $totalFilesForProgress -gt 0 -and $totalSizeMBForProgress -gt 0 -and $null -ne $deletionStartTime -and $null -ne $progressBarShownTime) {
			# Промежуточные обновления каждые 0.1 секунды для плавности
			# ИСПРАВЛЕНО: Проверяем на $null перед вычитанием дат, чтобы избежать ошибки "op_Subtraction"
			$timeSinceLastKnownUpdate = if ($null -ne $lastKnownUpdateTime) { ($currentTime - $lastKnownUpdateTime).TotalSeconds } else { 0 }
			$timeSinceDeletionStart = if ($null -ne $deletionStartTime) { ($currentTime - $deletionStartTime).TotalSeconds } else { 0 }
			$timeSinceProgressBarShown = if ($null -ne $progressBarShownTime) { ($currentTime - $progressBarShownTime).TotalSeconds } else { 0 }
			
			# ИСПРАВЛЕНО: Используем фиксированный интервал 0.1 секунды для частых и плавных обновлений
			# Это обеспечит примерно 100 обновлений за 10 секунд, что гарантирует плавное заполнение
			$estimatedDurationSeconds = 10  # Фиксированная длительность 10 секунд
			$minUpdateInterval = 0.1  # Фиксированный интервал 0.1 сек для частых обновлений
			
			# ИСПРАВЛЕНО: Интерполяция работает ВСЕГДА, пока не прошло 10 секунд с момента показа прогресс-бара
			# Это гарантирует плавное заполнение до конца без ограничения на количество прыжков
			# Условие: прошло >= 0.1 сек с последнего обновления И прошло < 10 сек с момента показа прогресс-бара
			$interpolationCondition = $timeSinceLastKnownUpdate -ge $minUpdateInterval -and $null -ne $progressBarShownTime -and $timeSinceProgressBarShown -lt $estimatedDurationSeconds
			if ($interpolationCondition) {
				Write-DebugWithTime "ИНТЕРПОЛЯЦИЯ: timeSinceLastKnownUpdate = $([math]::Round($timeSinceLastKnownUpdate, 3)) сек, timeSinceProgressBarShown = $([math]::Round($timeSinceProgressBarShown, 3)) сек, lastInterpolatedFiles = $lastInterpolatedFiles"
				# Используем простую линейную интерполяцию на основе времени с момента показа прогресс-бара
				# Рассчитываем процент выполнения на основе времени (линейная интерполяция)
				# Гарантируем, что прогресс всегда увеличивается от 0% до 100% в течение 10 секунд
				$timeBasedProgressPercent = [math]::Min(($timeSinceProgressBarShown / $estimatedDurationSeconds) * 100, 100)
				
				# Рассчитываем количество файлов на основе процента
				# Интерполяция работает независимо от реального подсчета для плавного заполнения
				# ВАЖНО: Интерполяция всегда монотонно возрастает от $lastInterpolatedFiles
				$targetProgress = [math]::Round(($timeBasedProgressPercent / 100) * $totalFilesForProgress)
				$estimatedProgress = [math]::Max($lastInterpolatedFiles, $targetProgress)
				
				# Рассчитываем размер на основе процента
				$targetMB = [math]::Round(($timeBasedProgressPercent / 100) * $totalSizeMBForProgress, 0)
				$estimatedMB = [math]::Max($lastInterpolatedMB, $targetMB)
				
				$estimatedProgressRounded = [math]::Round($estimatedProgress)
				$estimatedMBRounded = [math]::Round($estimatedMB, 0)
				
				# ГАРАНТИРУЕМ монотонное возрастание - никогда не уменьшаем прогресс
				if ($estimatedProgressRounded -lt $lastInterpolatedFiles) {
					$estimatedProgressRounded = $lastInterpolatedFiles
				}
				if ($estimatedMBRounded -lt $lastInterpolatedMB) {
					$estimatedMBRounded = $lastInterpolatedMB
				}
				
				# ИСПРАВЛЕНО: Убрано ограничение шага - интерполяция всегда достигает 100% в течение 10 секунд
				# Интерполяция основана на времени, поэтому она автоматически достигнет 100% за 10 секунд
				# Ограничение шага не нужно, так как интерполяция уже монотонно возрастает и ограничена временем
				
				# ИСПРАВЛЕНО: Интерполяция всегда монотонно возрастает до 100% в течение 10 секунд, НЕЗАВИСИМО от реального подсчета
				# КРИТИЧНО: Интерполяция НИКОГДА не уменьшается и НЕ останавливается, даже если реальный подсчет показывает меньшее значение
				# Это гарантирует последовательное заполнение до конца без остановки на промежуточных значениях
				# ЛОГИКА: Интерполяция всегда растет до 100% в течение 10 секунд
				# Реальный подсчет используется ТОЛЬКО для ограничения сверху (не превышать реальное значение)
				# НО: интерполяция продолжает расти в следующих итерациях, даже если сейчас ограничена реальным подсчетом
				# КЛЮЧЕВОЕ ИЗМЕНЕНИЕ: Используем интерполяцию БЕЗ ограничения реальным подсчетом (если он меньше 100%)
				# Интерполяция всегда растет до 100% в течение 10 секунд, независимо от реального подсчета
				# Реальный подсчет используется ТОЛЬКО когда он достиг 100%
				$displayFiles = [math]::Max($estimatedProgressRounded, $lastInterpolatedFiles)
				$displayMB = [math]::Max($estimatedMBRounded, $lastInterpolatedMB)
				
				# Ограничиваем реальным подсчетом только если он доступен и достиг 100%
				# НО: если реальный подсчет меньше 100%, интерполяция продолжает расти (не ограничиваем)
				if ($lastKnownDeletedFiles -ge $totalFilesForProgress) {
					$displayFiles = $totalFilesForProgress
				}
				# НЕ ограничиваем интерполяцию реальным подсчетом, если он меньше 100% - интерполяция продолжает расти
				if ($lastKnownDeletedMB -ge $totalSizeMBForProgress) {
					$displayMB = $totalSizeMBForProgress
				}
				# НЕ ограничиваем интерполяцию реальным подсчетом, если он меньше 100% - интерполяция продолжает расти
				
				# Обновляем только если значение увеличилось
				if ($displayFiles -gt $lastInterpolatedFiles -or $displayMB -gt $lastInterpolatedMB) {
					Write-DebugWithTime "ИНТЕРПОЛЯЦИЯ ОБНОВЛЕНИЕ: displayFiles = $displayFiles из $totalFilesForProgress ($([math]::Round(($displayFiles / $totalFilesForProgress) * 100, 1))%), lastInterpolatedFiles = $lastInterpolatedFiles, estimatedProgressRounded = $estimatedProgressRounded, timeBasedProgressPercent = $([math]::Round($timeBasedProgressPercent, 1))%"
					Update-FolderDeletionProgressBar -DeletedFiles $displayFiles -TotalFiles $totalFilesForProgress -DeletedMB $displayMB -TotalMB $totalSizeMBForProgress
					$progressBarUpdateCount++
					# Обновляем время последнего известного обновления для интерполяции
					$lastKnownUpdateTime = $currentTime
					# Обновляем последние известные значения для интерполяции
					$lastInterpolatedFiles = $displayFiles
					$lastInterpolatedMB = $displayMB
					[System.Windows.Forms.Application]::DoEvents()
				} else {
					Write-DebugWithTime "ИНТЕРПОЛЯЦИЯ ПРОПУСК: displayFiles = $displayFiles, lastInterpolatedFiles = $lastInterpolatedFiles, estimatedProgressRounded = $estimatedProgressRounded, timeBasedProgressPercent = $([math]::Round($timeBasedProgressPercent, 1))%"
				}
			} else {
				Write-DebugWithTime "ИНТЕРПОЛЯЦИЯ УСЛОВИЕ НЕ ВЫПОЛНЕНО: timeSinceLastKnownUpdate = $([math]::Round($timeSinceLastKnownUpdate, 3)) сек (нужно >= $minUpdateInterval), timeSinceProgressBarShown = $([math]::Round($timeSinceProgressBarShown, 3)) сек (нужно < $estimatedDurationSeconds), lastInterpolatedFiles = $lastInterpolatedFiles"
			}
			
			# Проверка папки уже выполняется выше каждые 0.05 секунды
		}
		
		# ИСПРАВЛЕНО: Дополнительная проверка - обновляем прогресс-бар до 100%, когда реальный подсчет показывает, что все файлы удалены
		# Это гарантирует, что прогресс-бар достигнет 100%, даже если интерполяция уже остановилась (прошло больше 10 секунд)
		# Эта проверка выполняется в каждом цикле, чтобы гарантировать обновление до 100%
		if ($showFolderProgressBar -and $folderProgressBarShown -and $totalFilesForProgress -gt 0 -and $lastKnownDeletedFiles -ge $totalFilesForProgress -and $lastInterpolatedFiles -lt $totalFilesForProgress) {
			Write-DebugWithTime "ОБНОВЛЕНИЕ ДО 100% (дополнительная проверка): реальный подсчет = $lastKnownDeletedFiles из $totalFilesForProgress, интерполяция = $lastInterpolatedFiles" "Green"
			Update-FolderDeletionProgressBar -DeletedFiles $totalFilesForProgress -TotalFiles $totalFilesForProgress -DeletedMB $totalSizeMBForProgress -TotalMB $totalSizeMBForProgress
			$lastInterpolatedFiles = $totalFilesForProgress
			$lastInterpolatedMB = $totalSizeMBForProgress
			$progressBarUpdateCount++
			[System.Windows.Forms.Application]::DoEvents()
		}
		
		# Множественные вызовы DoEvents() для обработки всех событий UI
		for ($i = 0; $i -lt 10; $i++) {
			[System.Windows.Forms.Application]::DoEvents()
		}
		
		# Если второй прогресс-бар показан, дополнительно обновляем его форму
		if ($showFolderProgressBar -and $folderProgressBarShown -and $Global:FolderDeletionProgressForm -ne $null -and $Global:FolderDeletionProgressForm.Visible) {
			$Global:FolderDeletionProgressForm.Refresh()
			$Global:FolderDeletionProgressForm.Update()
			[System.Windows.Forms.Application]::DoEvents()
		}
		
		# УДАЛЕНО: Дублирующий блок интерполяции - основная интерполяция уже работает выше
		# Интерполяция обрабатывается в блоке выше (строки 6438-6527) с правильной логикой монотонного возрастания
		
		# Если папка удалена и Job завершен, выходим из цикла
		if (-not $folderStillExists -and ($removeJob.State -eq "Completed" -or $removeJob.State -eq "Failed")) {
			Write-DebugWithTime "Выход из цикла: папка удалена и Job завершен. Job State = $($removeJob.State)" "Green"
			break
		}
		
		# Защита от бесконечного цикла - если прошло больше 60 секунд, выходим
		# ИСПРАВЛЕНО: Проверяем на $null перед вычитанием дат
		$timeSinceDeletionStart = if ($null -ne $deletionStartTime) { ($currentTime - $deletionStartTime).TotalSeconds } else { 0 }
		if ($timeSinceDeletionStart -gt 60) {
			Write-DebugWithTime "Выход из цикла: превышено время ожидания (60 секунд)" "Yellow"
			break
		}
		
		# Минимальная задержка для обеспечения частых обновлений UI
		Start-Sleep -Milliseconds 10
	}
	
	# Останавливаем таймер анимации после завершения удаления
	Write-DebugWithTime "Остановка таймера анимации" "Cyan"
	Stop-ProgressBarAnimation
	
	# Получаем результат после завершения Job
	Write-DebugWithTime "=== НАЧАЛО ПОЛУЧЕНИЯ РЕЗУЛЬТАТОВ JOB ===" "Yellow"
	Write-DebugWithTime "Job State перед получением результатов: $($removeJob.State)" "Cyan"
	$jobResult = $null
	$output = @()
	
	try {
		# Проверяем состояние Job перед получением результатов
		if ($removeJob.State -eq "Running") {
			Write-DebugWithTime "Job все еще выполняется, останавливаем его" "Yellow"
			# Если Job все еще выполняется, останавливаем его
			Stop-Job -Job $removeJob -ErrorAction SilentlyContinue
			Start-Sleep -Seconds 1
		}
		
		# Получаем результаты Job (Wait-Job убран, так как он блокируется при интерактивных диалогах)
		# Job уже завершился после выхода из цикла while выше
		Write-DebugWithTime "Получение результатов Job через Receive-Job" "Cyan"
		$jobResult = Receive-Job -Job $removeJob -ErrorAction SilentlyContinue
		Write-DebugWithTime "Результаты получены. Тип результата: $($jobResult.GetType().Name), Количество элементов: $($jobResult.Count)" "Cyan"
		
		# Обрабатываем результат - Receive-Job может вернуть массив массивов
		Write-DebugWithTime "Обработка результатов Job" "Cyan"
		if ($null -ne $jobResult) {
			# Проверяем, является ли результат массивом
			if ($jobResult -is [System.Array]) {
				Write-DebugWithTime "Результат является массивом. Количество элементов: $($jobResult.Count)" "Cyan"
				# Если это массив массивов, разворачиваем его
				foreach ($item in $jobResult) {
					if ($null -ne $item) {
						if ($item -is [System.Array]) {
							foreach ($subItem in $item) {
								if ($null -ne $subItem) {
									$output += $subItem
								}
							}
						} else {
							$output += $item
						}
					}
				}
			} else {
				# Это не массив, добавляем как есть
				Write-DebugWithTime "Результат не является массивом, добавляем как есть" "Cyan"
				if ($jobResult -ne $null) {
					$output = @($jobResult)
				}
			}
		} else {
			Write-DebugWithTime "jobResult = null" "Yellow"
		}
		Write-DebugWithTime "Обработка завершена. Количество элементов в output: $($output.Count)" "Cyan"
		
		# Если результатов нет, но Job завершился, проверяем состояние
		if ($output.Count -eq 0) {
			Write-DebugWithTime "Результатов нет, проверяем вывод Job через Get-Job" "Yellow"
			# Проверяем вывод Job независимо от состояния
			$jobOutput = Get-Job -Id $removeJob.Id | Select-Object -ExpandProperty Output -ErrorAction SilentlyContinue
			if ($null -ne $jobOutput -and $jobOutput.Count -gt 0) {
				Write-DebugWithTime "Получен вывод через Get-Job. Количество элементов: $($jobOutput.Count)" "Cyan"
				$output = $jobOutput
			}
			
			# Если все еще нет результатов, проверяем ошибки Job
			if ($output.Count -eq 0) {
				Write-DebugWithTime "Результатов все еще нет, проверяем ошибки Job" "Yellow"
				# Получаем ошибки из Job через свойство Error
				$jobErrors = $null
				try {
					if ($removeJob.HasMoreData) {
						$jobErrors = Receive-Job -Job $removeJob -ErrorAction SilentlyContinue 2>&1 | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
					}
					# Также проверяем свойство Error у Job
					if ($removeJob.Error -and $removeJob.Error.Count -gt 0) {
						$jobErrors = $removeJob.Error
					}
				} catch {
					# Игнорируем ошибки при получении ошибок Job
				}
				
				if ($null -ne $jobErrors -and $jobErrors.Count -gt 0) {
					Write-DebugWithTime "Найдено ошибок Job: $($jobErrors.Count)" "Red"
					foreach ($err in $jobErrors) {
						if ($err -is [System.Management.Automation.ErrorRecord]) {
							$output += "[ОШИБКА] $($err.Exception.Message)|Red"
						} else {
							$output += "[ОШИБКА] $err|Red"
						}
					}
				} else {
					Write-DebugWithTime "Ошибок Job не найдено" "Yellow"
				}
			}
		}
	}
	catch {
		Write-DebugWithTime "ОШИБКА при получении результатов удаления: $($_.Exception.Message)" "Red"
		Write-ToOutputColored "[ОШИБКА] Ошибка при получении результатов удаления: $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
	}
	finally {
		Write-DebugWithTime "=== НАЧАЛО БЛОКА FINALLY ===" "Yellow"
		# Закрываем второй прогресс-бар для удаления папки (если был показан)
		Write-DebugWithTime "Finally блок: showFolderProgressBar = $showFolderProgressBar" "Cyan"
		if ($showFolderProgressBar) {
			Write-DebugWithTime "Finally блок: Закрываем второй прогресс-бар" "Green"
			Hide-FolderDeletionProgressBar
		} else {
			Write-DebugWithTime "Finally блок: Второй прогресс-бар не был показан, закрывать нечего" "Yellow"
		}
		
		# Удаляем Job с принудительным удалением, если он не завершен
		Write-DebugWithTime "Очистка Job. Job State = $($removeJob.State)" "Cyan"
		try {
			if ($removeJob.State -eq "Running" -or $removeJob.State -eq "Blocked") {
				Write-DebugWithTime "Остановка Job перед удалением" "Yellow"
				Stop-Job -Job $removeJob -ErrorAction SilentlyContinue
				Start-Sleep -Milliseconds 500
			}
			Write-DebugWithTime "Удаление Job" "Cyan"
			Remove-Job -Job $removeJob -Force -ErrorAction SilentlyContinue
			Write-DebugWithTime "Job удален" "Green"
			
			# Закрываем сессию, если Job имеет свойство Runspace (для PSSessionJob)
			try {
				if ($removeJob.PSObject.Properties['Runspace'] -and $removeJob.Runspace) {
					$session = $removeJob.Runspace
					if ($session -and $session.GetType().Name -eq 'RemoteRunspace') {
						Write-DebugWithTime "Закрытие удаленной сессии" "Cyan"
						Remove-PSSession -Session $session -ErrorAction SilentlyContinue
					}
				}
			} catch {
				Write-DebugWithTime "Ошибка при закрытии сессии: $($_.Exception.Message)" "Yellow"
				# Игнорируем ошибки закрытия сессии
			}
		}
		catch {
			Write-DebugWithTime "Ошибка при удалении Job: $($_.Exception.Message)" "Red"
			# Игнорируем ошибки при удалении Job
		}
		Write-DebugWithTime "=== КОНЕЦ БЛОКА FINALLY ===" "Yellow"
	}
	
	# Вывод оставшихся результатов в GUI (только те, которые еще не были выведены через инкрементальный вывод)
	Write-DebugWithTime "Вывод оставшихся результатов в GUI. Количество элементов в output: $($output.Count)" "Cyan"
	if ($output.Count -gt 0) {
		# Фильтруем только те строки, которые еще не были выведены
		$remainingOutput = @()
		foreach ($line in $output) {
			if ($line -notin $processedOutputLines) {
				$remainingOutput += $line
			}
		}
		
		Write-DebugWithTime "Отфильтровано оставшихся результатов: $($remainingOutput.Count)" "Cyan"
		if ($remainingOutput.Count -gt 0) {
			Write-DebugWithTime "Вывод оставшихся результатов в GUI" "Green"
			Write-OutputResults -OutputLines $remainingOutput
		}
	} else {
		Write-DebugWithTime "Результатов нет. Job State = $($removeJob.State)" "Yellow"
		# Если результатов нет, но Job завершился успешно, выводим сообщение
		if ($removeJob.State -eq "Completed") {
			Write-ToOutputColored "[ПРЕДУПРЕЖДЕНИЕ] Результаты удаления не получены или пусты. Проверьте состояние Job: $($removeJob.State)" "[ПРЕДУПРЕЖДЕНИЕ]" ([System.Drawing.Color]::Yellow) ([System.Drawing.Color]::White)
		} else {
			Write-ToOutputColored "[ПРЕДУПРЕЖДЕНИЕ] Job не завершился корректно. Состояние: $($removeJob.State)" "[ПРЕДУПРЕЖДЕНИЕ]" ([System.Drawing.Color]::Yellow) ([System.Drawing.Color]::White)
		}
	}
	
	# Завершаем анимацию прогресс-бара после удаления
	Write-DebugWithTime "Завершение анимации главного прогресс-бара" "Cyan"
	if ($Global:ProgressBar -ne $null) {
		$Global:ProgressBar.Style = "Continuous"
		Update-ProgressBar -Status "Удаление завершено!" -PercentComplete 100
	}
	
	Write-DebugWithTime "Очистка переменной Server" "Cyan"
	Clear-Variable -Name "Server"
	Write-DebugWithTime "=== КОНЕЦ ФУНКЦИИ Remove-Server1C ===" "Yellow"
}

# Функция 9. Установка сервера и службы (модифицирована для работы с GUI диалогами)
function Install-Server1C() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $Server
	)

	# Проверяем, является ли сервер локальным
	$isLocal = Test-IsLocalServer -ServerName $Server
	# Подавляем вывод булева значения в консоль
	$null = $isLocal

	# Диалог ввода пути к дистрибутиву с инструкцией
	# Функция копирования упразднена, поэтому сразу запрашиваем локальный путь
	$instructionText = @"
Укажите локальный путь к дистрибутиву 1С.
Пример: C:\Distrib\1C\8.3.22.2239
"@
	# Ввод пути к дистрибутиву с проверкой на пустое значение и валидацией
	$distribPath = $null
	$pathValid = $false
	do {
		$distribPath = Show-InputDialog -Title "Указать локальный путь к дистрибутиву 1С" -Prompt $instructionText -DefaultValue "" -CancelText "Отмена"
		
		# Если нажата кнопка "Отмена", выходим из функции
		if ($null -eq $distribPath) {
			Write-ToOutputColored "[ОШИБКА] Ввод пути к дистрибутиву прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			return
		}
		
		# Если введено пустое значение, показываем ошибку и продолжаем цикл
		if ($distribPath -eq "") {
			Write-ToOutputColored "[ОШИБКА] Не введен путь к дистрибутиву. Пожалуйста, введите путь." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			$pathValid = $false
			continue
		}
		
		# Проверка формата пути
		if (-not ((($distribPath).StartsWith("\\")) -or ($distribPath -match ":"+"\\"))) {
			Write-ToOutputColored "[ОШИБКА] Неверно указан путь. Путь должен начинаться с \\ или содержать :\\" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			$pathValid = $false
			continue
		}
		
		# Проверка существования пути (локально или удалённо)
		try {
			if ($isLocal) {
				$pathExists = Test-Path $distribPath -ErrorAction SilentlyContinue
			} else {
				$pathExists = Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $distribPath -ScriptBlock {
					param([string]$Path)
					return Test-Path $Path -ErrorAction SilentlyContinue
				}
			}
			
			if (-not $pathExists) {
				$serverType = if ($isLocal) { "локальном" } else { "удалённом" }
				Write-ToOutputColored "[ОШИБКА] Путь не существует на $serverType сервере. Проверьте путь и попробуйте снова." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$pathValid = $false
				continue
			}
			
			# Путь валиден
			$pathValid = $true
			Write-ToOutputColored "[OK] Проверка пути к дистрибутиву" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
		}
		catch {
			Write-ToOutputColored "[ОШИБКА] Ошибка при проверке пути: $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			$pathValid = $false
		}
	} while (-not $pathValid)
	
	# Выбор файла MSI: читаем папку дистрибутива (локально или удалённо), находим все .msi, показываем диалог выбора как в Show-SelectionDialog
	$msiFile = $null
	$msiNames = @()
	try {
		if ($isLocal) {
			$msiNames = (Get-ChildItem -LiteralPath $distribPath -Filter "*.msi" -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
		} else {
			$msiNames = Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $distribPath -ScriptBlock {
				param([string]$Path)
				Get-ChildItem -LiteralPath $Path -Filter "*.msi" -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
			}
		}
	} catch {
		Write-ToOutputColored "[ОШИБКА] Ошибка при чтении папки дистрибутива: $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	$msiNames = @($msiNames)
	if ($msiNames.Count -eq 0) {
		Write-ToOutputColored "[ОШИБКА] В папке дистрибутива не найдено файлов .msi" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	# Формируем список для диалога: "1. имя.msi", "2. имя2.msi" ...
	$msiItems = @()
	for ($i = 0; $i -lt $msiNames.Count; $i++) {
		$msiItems += "$($i + 1). $($msiNames[$i])"
	}
	$selectedMsiIndex = Show-SelectionDialog -Title "Файл установщика" -Prompt "Выберите файл установщика" -Items $msiItems -CancelText "Отмена"
	if ($null -eq $selectedMsiIndex) {
		Write-ToOutputColored "[ОШИБКА] Выбор файла установщика прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	$msiFile = $msiNames[$selectedMsiIndex - 1]
	Write-ToOutputColored "[OK] Выбран файл установщика: $msiFile" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
	
	# Диалог выбора варианта установки
	$installItems = @("1. Сервер 1С", "2. Сервер 1С, Средства администрирования", "3. Сервер 1С, Средства администрирования, Толстый клиент, Тонкий клиент")
	$selectedInstall = Show-SelectionDialog -Title "Вариант установки" -Prompt "Выберите вариант установки" -Items $installItems -CancelText "Отмена"
	
	if ($null -eq $selectedInstall) {
		Write-ToOutputColored "[ОШИБКА] Выбор варианта установки прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
		return
	}
	
	# Обновляем прогресс-бар для анимации во время установки
	Update-ProgressBar -Status "Выполнение установки сервера 1С..."
	# Убеждаемся, что прогресс-бар в режиме анимации Marquee и таймер запущен
	if ($Global:ProgressBar -ne $null) {
		$Global:ProgressBar.Style = "Marquee"
		$Global:ProgressBar.MarqueeAnimationSpeed = 50
		# Принудительно обновляем прогресс-бар и форму для немедленного отображения
		$Global:ProgressBar.Update()
		$Global:ProgressForm.Update()
		# Множественные вызовы DoEvents() для обработки всех событий
		for ($i = 0; $i -lt 10; $i++) {
			[System.Windows.Forms.Application]::DoEvents()
		}
	}
	# Запускаем таймер для плавной анимации
	Start-ProgressBarAnimation
	# Дополнительное обновление UI после запуска таймера для немедленного старта анимации
	for ($i = 0; $i -lt 10; $i++) {
		[System.Windows.Forms.Application]::DoEvents()
	}
	
	# Запускаем установку в фоновом Job для возможности обновления UI
	# Запускаем Job (локально или на удаленном сервере)
	if ($isLocal) {
		# Для локального сервера создаем отдельный скрипт-блок, который выполняется напрямую без Invoke-Command
		$localInstallScriptBlock = {
			param([string]$PathSource, [string]$FileMsi1C, [int]$Install1C)
			
			$result = @()
			
			try {
				$GetFileMsi = Get-ChildItem "$PathSource" -File | Where-Object {($_.Name) -like $FileMsi1C}
				
				if ($Install1C -eq 1) {
					Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$($GetFileMsi.FullName)`" /quiet /norestart TRANSFORMS=`"1049.mst`" INSTALLSRVRASSRVC=0 HASPInstall=no SERVER=1 SERVERCLIENT=0 DESIGNERALLCLIENTS=0 THICKCLIENT=0 THINCLIENT=0 LANGUAGES=RU THINCLIENTFILE=0 WEBSERVEREXT=0 CONFREPOSSERVER=0 CONVERTER77=0" -Wait
					Start-Sleep -Seconds 5
					$result += "[OK] Сервер 1С Установлен|Green"
					$result += "INSTALL_SERVICE_REQUIRED|OK"
				}
				elseif ($Install1C -eq 2) {
					Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$($GetFileMsi.FullName)`" /quiet /norestart TRANSFORMS=`"1049.mst`" INSTALLSRVRASSRVC=0 HASPInstall=no SERVER=1 SERVERCLIENT=1 DESIGNERALLCLIENTS=1 THICKCLIENT=0 THINCLIENT=0 LANGUAGES=RU THINCLIENTFILE=0 WEBSERVEREXT=0 CONFREPOSSERVER=0 CONVERTER77=0" -Wait
					Start-Sleep -Seconds 5
					$result += "[OK] Сервер 1С, Средства администрирования Установлены|Green"
					$result += "INSTALL_SERVICE_REQUIRED|OK"
				}
				elseif ($Install1C -eq 3) {
					Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$($GetFileMsi.FullName)`" /quiet /norestart TRANSFORMS=`"1049.mst`" INSTALLSRVRASSRVC=0 HASPInstall=no SERVER=1 SERVERCLIENT=1 DESIGNERALLCLIENTS=1 THICKCLIENT=1 THINCLIENT=1 LANGUAGES=RU THINCLIENTFILE=0 WEBSERVEREXT=0 CONFREPOSSERVER=0 CONVERTER77=0" -Wait
					Start-Sleep -Seconds 5
					$result += "[OK] Сервер 1С, Средства администрирования, Толстый клиент, Тонкий клиент Установлены|Green"
					$result += "INSTALL_SERVICE_REQUIRED|OK"
				}
			}
			catch {
				$result += "[ОШИБКА] $($_.Exception.Message)|Red"
			}
			
			return $result
		}
		
		# Запускаем Job локально через Start-Job
		$installJob = Start-Job -ScriptBlock $localInstallScriptBlock -ArgumentList $distribPath, $msiFile, $selectedInstall
	} else {
		# Для удаленного сервера создаем отдельный скрипт-блок, который выполняется напрямую на удаленном сервере
		# без повторного вызова Invoke-Command внутри
		$remoteInstallScriptBlock = {
			param([string]$PathSource, [string]$FileMsi1C, [int]$Install1C)
			
			$result = @()
			
			try {
				$GetFileMsi = Get-ChildItem "$PathSource" -File | Where-Object {($_.Name) -like $FileMsi1C}
				
				if ($Install1C -eq 1) {
					Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$($GetFileMsi.FullName)`" /quiet /norestart TRANSFORMS=`"1049.mst`" INSTALLSRVRASSRVC=0 HASPInstall=no SERVER=1 SERVERCLIENT=0 DESIGNERALLCLIENTS=0 THICKCLIENT=0 THINCLIENT=0 LANGUAGES=RU THINCLIENTFILE=0 WEBSERVEREXT=0 CONFREPOSSERVER=0 CONVERTER77=0" -Wait
					Start-Sleep -Seconds 5
					$result += "[OK] Сервер 1С Установлен|Green"
					$result += "INSTALL_SERVICE_REQUIRED|OK"
				}
				elseif ($Install1C -eq 2) {
					Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$($GetFileMsi.FullName)`" /quiet /norestart TRANSFORMS=`"1049.mst`" INSTALLSRVRASSRVC=0 HASPInstall=no SERVER=1 SERVERCLIENT=1 DESIGNERALLCLIENTS=1 THICKCLIENT=0 THINCLIENT=0 LANGUAGES=RU THINCLIENTFILE=0 WEBSERVEREXT=0 CONFREPOSSERVER=0 CONVERTER77=0" -Wait
					Start-Sleep -Seconds 5
					$result += "[OK] Сервер 1С, Средства администрирования Установлены|Green"
					$result += "INSTALL_SERVICE_REQUIRED|OK"
				}
				elseif ($Install1C -eq 3) {
					Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$($GetFileMsi.FullName)`" /quiet /norestart TRANSFORMS=`"1049.mst`" INSTALLSRVRASSRVC=0 HASPInstall=no SERVER=1 SERVERCLIENT=1 DESIGNERALLCLIENTS=1 THICKCLIENT=1 THINCLIENT=1 LANGUAGES=RU THINCLIENTFILE=0 WEBSERVEREXT=0 CONFREPOSSERVER=0 CONVERTER77=0" -Wait
					Start-Sleep -Seconds 5
					$result += "[OK] Сервер 1С, Средства администрирования, Толстый клиент, Тонкий клиент Установлены|Green"
					$result += "INSTALL_SERVICE_REQUIRED|OK"
				}
			}
			catch {
				$result += "[ОШИБКА] $($_.Exception.Message)|Red"
			}
			
			return $result
		}
		
		# Запускаем Job на удаленном сервере через Invoke-Command -AsJob
		$installJob = Invoke-Command -ComputerName $Server -ScriptBlock $remoteInstallScriptBlock -ArgumentList $distribPath, $msiFile, $selectedInstall -AsJob
	}
	
	# Ждем завершения Job с активным обновлением UI для анимации
	# Используем очень короткие задержки и множественные вызовы DoEvents()
	# для обеспечения плавной анимации прогресс-бара
	# КРИТИЧЕСКИ ВАЖНО: цикл должен быть максимально легким для UI потока
	while ($installJob.State -eq "Running") {
		# Принудительно обновляем прогресс-бар для анимации Marquee
		if ($Global:ProgressBar -ne $null -and $Global:ProgressForm.Visible) {
			# Убеждаемся, что прогресс-бар в режиме Marquee
			if ($Global:ProgressBar.Style -ne "Marquee") {
				$Global:ProgressBar.Style = "Marquee"
			}
			$Global:ProgressBar.MarqueeAnimationSpeed = 50
			# Принудительно обновляем прогресс-бар и форму
			$Global:ProgressBar.Refresh()  # Используем Refresh вместо Update для более агрессивного обновления
			$Global:ProgressForm.Refresh()
		}
		# Множественные вызовы DoEvents() для обработки всех событий UI
		# Это критически важно для работы анимации Marquee
		# Увеличено количество вызовов для более плавной анимации
		for ($i = 0; $i -lt 10; $i++) {
			[System.Windows.Forms.Application]::DoEvents()
		}
		# БЕЗ задержки - это позволяет максимально быстро обновлять UI
		# Задержка не нужна, так как проверка состояния Job сама по себе легкая операция
	}
	
	# Останавливаем таймер анимации после завершения установки
	Stop-ProgressBarAnimation
	
	# Получаем результат после завершения Job
	$jobResult = Receive-Job -Job $installJob -ErrorAction SilentlyContinue
	
	# Получаем ошибки из Job через свойство Error
	$jobErrors = $null
	try {
		if ($installJob.HasMoreData) {
			$jobErrors = Receive-Job -Job $installJob -ErrorAction SilentlyContinue 2>&1 | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
		}
		# Также проверяем свойство Error у Job
		if ($installJob.Error -and $installJob.Error.Count -gt 0) {
			$jobErrors = $installJob.Error
		}
	} catch {
		# Игнорируем ошибки при получении ошибок Job
	}
	
	Stop-Job -Job $installJob -ErrorAction SilentlyContinue
	Remove-Job -Job $installJob -Force -ErrorAction SilentlyContinue
	
	# Закрываем сессию, если Job имеет свойство Runspace (для PSSessionJob)
	try {
		if ($installJob.PSObject.Properties['Runspace'] -and $installJob.Runspace) {
			$session = $installJob.Runspace
			if ($session -and $session.GetType().Name -eq 'RemoteRunspace') {
				Remove-PSSession -Session $session -ErrorAction SilentlyContinue
			}
		}
	} catch {
		# Игнорируем ошибки закрытия сессии
	}
	
	# Обрабатываем результат - Receive-Job может вернуть массив массивов
	$output = @()
	if ($null -ne $jobResult -and $jobResult -is [System.Array]) {
		# Если это массив массивов, разворачиваем его
		foreach ($item in $jobResult) {
			if ($item -is [System.Array]) {
				$output += $item
			} else {
				$output += $item
			}
		}
	} else {
		$output = $jobResult
	}
	
	# Вывод результатов установки с обработкой маркеров [OK] и [ОШИБКА]
	$installServiceRequired = $false
	$filteredOutput = @()
	foreach ($line in $output) {
		if ($line -eq "INSTALL_SERVICE_REQUIRED|OK") {
			$installServiceRequired = $true
		}
		else {
			$filteredOutput += $line
		}
	}
	# Используем Write-OutputResults для правильной обработки маркеров [OK] и [ОШИБКА]
	Write-OutputResults -OutputLines $filteredOutput
	
	# Выводим ошибки, если они есть
	if ($null -ne $jobErrors -and $jobErrors.Count -gt 0) {
		foreach ($err in $jobErrors) {
			if ($err -is [System.Management.Automation.ErrorRecord]) {
				Write-ToOutputColored "[ОШИБКА] $($err.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			} else {
				Write-ToOutputColored "[ОШИБКА] $err" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			}
		}
	}
	
	if ($installServiceRequired) {
		Write-ToOutput "Запущена функция установки службы 1С" ([System.Drawing.Color]::Cyan)
		
		# Получаем список версий для установки службы (полная версия 8.3.xx.xxxx из пути или реестра)
		$versionsResult = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
			$result = @()
			Get-Package | Where-Object {($_.Name -match "1С:Предприятие 8") -and ($_.Source -notmatch "(x86)")} | ForEach-Object {
				$versionString = $null
				# 1) Полная версия из пути установки (например, C:\Program Files\1cv8\8.3.27.1859)
				if ($_.Source -match '\\(8\.\d+\.\d+\.\d+)(?:\\|$)') {
					$versionString = $matches[1]
				}
				# 2) Запасной вариант: DisplayVersion из реестра по пути установки этого пакета
				if (-not $versionString) {
					$pkgSource = $_.Source
					$displayVer = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { ($_.DisplayName -like "*1С:Предприятие*" -or $_.DisplayName -like "*1С:Enterprise*") -and $_.InstallLocation -and ($pkgSource -like "*$($_.InstallLocation)*" -or $_.InstallLocation -like "*$pkgSource*") } | Select-Object -First 1).DisplayVersion
					if ($displayVer -and $displayVer -match '^8\.\d+\.\d+\.\d+') { $versionString = $displayVer }
				}
				# 3) Иначе из объекта Version (может быть укорочен при сериализации, например "1.8")
				if (-not $versionString) { $versionString = $_.Version.ToString() }
				# Добавляем только полную версию (8.3.xx.xxxx), чтобы в диалоге не отображалась "1.8"
				if ($versionString -and $versionString -match '^8\.\d+\.\d+\.\d+') { $result += $versionString }
			}
			return $result
		}
		
		# Обрабатываем результат - используем foreach для правильного извлечения элементов
		# Проблема: $versionsResult[$i] возвращает только "8", а $versionsResult - полную версию "8.3.27.1859"
		# Поэтому используем foreach для итерации по элементам и создания нового массива
		$versionItems = @()
		$versionsArray = @()  # Сохраняем для последующего использования
		$index = 0
		foreach ($item in $versionsResult) {
			# Явно преобразуем каждый элемент в строку для сохранения полной версии
			$versionStr = $item.ToString()
			$versionItems += $versionStr
			$versionsArray += $versionStr
			$index++
		}
		
		if ($versionItems.Count -eq 0) {
			Write-ToOutputColored "[ОШИБКА] Не найдено установленных версий 1С:Предприятие 8" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			return
		}
		
		$selectedVersionIndex = Show-SelectionDialog -Title "Выбор версии для службы" -Prompt "Выберите версию для установки службы" -Items $versionItems -CancelText "Отмена"
		
		if ($null -eq $selectedVersionIndex) {
			Write-ToOutputColored "[ОШИБКА] Выбор версии для установки службы прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			return
		}
		
		# Получаем выбранную версию из $versionItems через foreach с индексом
		# Это гарантирует получение полной версии, а не только "8"
		$selectedVersion = $null
		$currentIndex = 0
		foreach ($version in $versionItems) {
			if ($currentIndex -eq ($selectedVersionIndex - 1)) {
				$selectedVersion = $version.ToString()
				break
			}
			$currentIndex++
		}
		
		if ($null -eq $selectedVersion) {
			Write-ToOutputColored "[ОШИБКА] Не удалось получить выбранную версию" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			return
		}
		
		# Диалоги для ввода портов и других параметров
		# Функция для проверки конфликтов портов с существующими службами 1С
		function Test-1CServicePortConflict {
			param(
				[string]$Server,
				[int]$CheckPort,
				[string]$PortType  # "server", "cluster", или "range"
			)
			
			try {
				# Получаем все службы 1С на удаленном сервере
				$services1C = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
					return Get-WmiObject win32_service | Where-Object {$_.PathName -Like "*ragent.exe*"} | Select-Object Name, PathName
				}
				
				if (-not $services1C -or $services1C.Count -eq 0) {
					return $false  # Нет служб 1С - конфликтов нет
				}
				
				foreach ($service in $services1C) {
					$pathName = $service.PathName
					
					# Извлекаем порты из PathName службы
					# Формат: "C:\Program Files\1cv8\8.3.27.1859\Bin\ragent.exe" -srvc -agent -regport 1741 -port 1740 -range 1760:1791 -debug -d "C:\..."
					
					# Извлекаем regport (порт кластера) - проверяем для всех типов портов
					if ($pathName -match "-regport\s+(\d+)") {
						$regPort = [int]$matches[1]
						if ($CheckPort -eq $regPort) {
							return $true  # Конфликт найден - проверяемый порт совпадает с regport существующей службы
						}
					}
					
					# Извлекаем port (порт сервера) - проверяем для всех типов портов
					if ($pathName -match "-port\s+(\d+)") {
						$port = [int]$matches[1]
						if ($CheckPort -eq $port) {
							return $true  # Конфликт найден - проверяемый порт совпадает с port существующей службы
						}
					}
					
					# Извлекаем range (диапазон портов) - проверяем для всех типов портов
					if ($pathName -match "-range\s+(\d+):(\d+)") {
						$rangeStart = [int]$matches[1]
						$rangeEnd = [int]$matches[2]
						
						# Проверяем, попадает ли проверяемый порт в диапазон существующей службы
						if ($CheckPort -ge $rangeStart -and $CheckPort -le $rangeEnd) {
							return $true  # Конфликт найден - проверяемый порт попадает в range существующей службы
						}
					}
				}
				
				return $false  # Конфликтов не найдено
			}
			catch {
				# В случае ошибки возвращаем false, чтобы не блокировать установку
				return $false
			}
		}
		
		# Функция для проверки конфликтов диапазона портов с существующими службами 1С
		function Test-1CServiceRangeConflict {
			param(
				[string]$Server,
				[int]$RangeStart,
				[int]$RangeEnd
			)
			
			try {
				# Получаем все службы 1С на удаленном сервере
				$services1C = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
					return Get-WmiObject win32_service | Where-Object {$_.PathName -Like "*ragent.exe*"} | Select-Object Name, PathName
				}
				
				if (-not $services1C -or $services1C.Count -eq 0) {
					return $false  # Нет служб 1С - конфликтов нет
				}
				
				$checkRange = $RangeStart..$RangeEnd
				
				foreach ($service in $services1C) {
					$pathName = $service.PathName
					
					# Извлекаем regport (порт кластера)
					if ($pathName -match "-regport\s+(\d+)") {
						$regPort = [int]$matches[1]
						if ($regPort -ge $RangeStart -and $regPort -le $RangeEnd) {
							return $true  # Конфликт найден
						}
					}
					
					# Извлекаем port (порт сервера)
					if ($pathName -match "-port\s+(\d+)") {
						$port = [int]$matches[1]
						if ($port -ge $RangeStart -and $port -le $RangeEnd) {
							return $true  # Конфликт найден
						}
					}
					
					# Извлекаем range (диапазон портов)
					if ($pathName -match "-range\s+(\d+):(\d+)") {
						$existingRangeStart = [int]$matches[1]
						$existingRangeEnd = [int]$matches[2]
						
						# Проверяем пересечение диапазонов
						if (-not ($RangeEnd -lt $existingRangeStart -or $RangeStart -gt $existingRangeEnd)) {
							return $true  # Диапазоны пересекаются - конфликт найден
						}
					}
				}
				
				return $false  # Конфликтов не найдено
			}
			catch {
				# В случае ошибки возвращаем false, чтобы не блокировать установку
				return $false
			}
		}
		
		# Ввод порта сервера с проверкой на пустое значение и занятость порта
		$serverPort = $null
		$serverPortValid = $false
		do {
			$serverPort = Show-InputDialog -Title "Порт сервера" -Prompt "Введите порт для сервера.`nПример: 1740" -DefaultValue "" -CancelText "Отмена"
			
			# Если нажата кнопка "Отмена", выходим из функции
			if ($null -eq $serverPort) {
				Write-ToOutputColored "[ОШИБКА] Ввод порта сервера прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				return
			}
			
			# Если введено пустое значение, показываем ошибку и продолжаем цикл
			if ($serverPort -eq "") {
				Write-ToOutputColored "[ОШИБКА] Не введено значение порта сервера. Пожалуйста, введите порт." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$serverPortValid = $false
				continue
			}
			
			# Проверка что порт является числом
			try {
				[int]$tmpServerPort = $serverPort
			}
			catch {
				Write-ToOutputColored "[ОШИБКА] Порт должен быть числом. Введите корректное значение порта." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$serverPortValid = $false
				continue
			}
			
			# Проверка занятости порта удалённо
			try {
				$portOccupied = Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $tmpServerPort -ScriptBlock {
					param([int]$Port)
					return (Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {$_.LocalPort -eq $Port}) -ne $null
				}
				
				if ($portOccupied) {
					Write-ToOutputColored "[ОШИБКА] Порт $tmpServerPort занят. Выберите другой порт." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					$serverPortValid = $false
					continue
				}
				
				# Проверка что порт не используется другими службами 1С (проверяем port, regport и range)
				$portConflict = Test-1CServicePortConflict -Server $Server -CheckPort $tmpServerPort -PortType "server"
				if ($portConflict) {
					Write-ToOutputColored "[ОШИБКА] Порт $tmpServerPort уже используется другой службой 1С (port, regport или входит в range). Выберите другой порт." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					$serverPortValid = $false
					continue
				}
				
				# Порт валиден
				$serverPortValid = $true
				Write-ToOutputColored "[OK] Проверка порта сервера" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
			}
			catch {
				Write-ToOutputColored "[ОШИБКА] Ошибка при проверке порта: $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$serverPortValid = $false
			}
		} while (-not $serverPortValid)
		
		# Ввод порта кластера с проверкой на пустое значение и занятость порта
		$clusterPort = $null
		$clusterPortValid = $false
		do {
			$clusterPort = Show-InputDialog -Title "Порт кластера" -Prompt "Введите порт для кластера.`nПример: 1741" -DefaultValue "" -CancelText "Отмена"
			
			# Если нажата кнопка "Отмена", выходим из функции
			if ($null -eq $clusterPort) {
				Write-ToOutputColored "[ОШИБКА] Ввод порта кластера прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				return
			}
			
			# Если введено пустое значение, показываем ошибку и продолжаем цикл
			if ($clusterPort -eq "") {
				Write-ToOutputColored "[ОШИБКА] Не введено значение порта кластера. Пожалуйста, введите порт." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$clusterPortValid = $false
				continue
			}
			
			# Проверка что порт является числом
			try {
				[int]$tmpClusterPort = $clusterPort
			}
			catch {
				Write-ToOutputColored "[ОШИБКА] Порт должен быть числом. Введите корректное значение порта." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$clusterPortValid = $false
				continue
			}
			
			# Проверка занятости порта удалённо
			try {
				$portOccupied = Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $tmpClusterPort -ScriptBlock {
					param([int]$Port)
					return (Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {$_.LocalPort -eq $Port}) -ne $null
				}
				
				if ($portOccupied) {
					Write-ToOutputColored "[ОШИБКА] Порт $tmpClusterPort занят. Выберите другой порт." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					$clusterPortValid = $false
					continue
				}
				
				# Проверка что порт кластера не используется другими службами 1С (проверяем port, regport и range)
				$portConflict = Test-1CServicePortConflict -Server $Server -CheckPort $tmpClusterPort -PortType "cluster"
				if ($portConflict) {
					Write-ToOutputColored "[ОШИБКА] Порт $tmpClusterPort уже используется другой службой 1С (port, regport или входит в range). Выберите другой порт." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					$clusterPortValid = $false
					continue
				}
				
				# Порт валиден
				$clusterPortValid = $true
				Write-ToOutputColored "[OK] Проверка порта кластера" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
			}
			catch {
				Write-ToOutputColored "[ОШИБКА] Ошибка при проверке порта: $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$clusterPortValid = $false
			}
		} while (-not $clusterPortValid)
		
		# Ввод диапазона портов с проверкой на пустое значение, формата и занятость портов
		$rangePort = $null
		$rangePortValid = $false
		do {
			$rangePort = Show-InputDialog -Title "Диапазон портов" -Prompt "Введите диапазон портов для процессов.`nПример: 1760:1791" -DefaultValue "" -CancelText "Отмена"
			
			# Если нажата кнопка "Отмена", выходим из функции
			if ($null -eq $rangePort) {
				Write-ToOutputColored "[ОШИБКА] Ввод диапазона портов прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				return
			}
			
			# Если введено пустое значение, показываем ошибку и продолжаем цикл
			if ($rangePort -eq "") {
				Write-ToOutputColored "[ОШИБКА] Не введен диапазон портов. Пожалуйста, введите диапазон портов." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$rangePortValid = $false
				continue
			}
			
			# Проверка формата диапазона (должен содержать :)
			if (-not ($rangePort -match ":")) {
				Write-ToOutputColored "[ОШИБКА] Неверно указан диапазон. Диапазон должен быть в формате начало:конец (например, 1760:1791)." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$rangePortValid = $false
				continue
			}
			
			# Проверка и парсинг диапазона портов
			try {
				$tmp = $rangePort.Split(":")
				if ($tmp.Length -ne 2) {
					throw "Неверный формат диапазона"
				}
				
				[int]$tmp1 = $tmp[0]
				[int]$tmp2 = $tmp[1]
				
				if ($tmp1 -ge $tmp2) {
					Write-ToOutputColored "[ОШИБКА] Начальный порт должен быть меньше конечного порта." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					$rangePortValid = $false
					continue
				}
				
				$tmpRange = $tmp1..$tmp2
				
				# Проверка занятости каждого порта в диапазоне удалённо
				$occupiedPorts = @()
				$portCheckResult = Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $tmpRange -ScriptBlock {
					param([int[]]$PortRange)
					$occupied = @()
					$allConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
					foreach ($port in $PortRange) {
						if ($allConnections | Where-Object {$_.LocalPort -eq $port}) {
							$occupied += $port
						}
					}
					return $occupied
				}
				
				if ($portCheckResult.Count -gt 0) {
					$occupiedPortsList = $portCheckResult -join ", "
					Write-ToOutputColored "[ОШИБКА] Порты $occupiedPortsList заняты. Выберите другой диапазон портов." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					$rangePortValid = $false
					continue
				}
				
				# Проверка что диапазон портов не конфликтует с существующими службами 1С
				$rangeConflict = Test-1CServiceRangeConflict -Server $Server -RangeStart $tmp1 -RangeEnd $tmp2
				if ($rangeConflict) {
					Write-ToOutputColored "[ОШИБКА] Диапазон портов $rangePort конфликтует с портами существующей службы 1С (port, regport или range). Выберите другой диапазон портов." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					$rangePortValid = $false
					continue
				}
				
				# Диапазон портов валиден
				$rangePortValid = $true
				Write-ToOutputColored "[OK] Проверка диапазона портов" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
			}
			catch {
				Write-ToOutputColored "[ОШИБКА] Ошибка при проверке диапазона портов: $($_.Exception.Message). Проверьте формат (например, 1760:1791)." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$rangePortValid = $false
			}
		} while (-not $rangePortValid)
		
		# Получаем домен автоматически из текущего пользователя
		$defaultDomain = $null
		try {
			# Пробуем получить домен из переменной окружения
			if (-not [string]::IsNullOrEmpty($env:USERDOMAIN)) {
				$defaultDomain = $env:USERDOMAIN
			} else {
				# Если не получилось, пробуем через WMI
				$defaultDomain = (Get-WmiObject Win32_ComputerSystem).Domain
				# Если домен в формате FQDN (например, domain.local), берём только первую часть
				if ($defaultDomain -match "^([^.]+)") {
					$defaultDomain = $matches[1]
				}
			}
		}
		catch {
			# Если не удалось получить домен, используем пустую строку
			$defaultDomain = ""
		}
		
		# Ввод учётной записи и пароля: при неверных учётных данных снова показываем окно ввода учётной записи
		$credentialsValid = $false
		do {
			# Диалог ввода учётной записи с автоматической подстановкой домена
			$serviceUser = $null
			$serviceUserValid = $false
			do {
				# Формируем текст подсказки с информацией о домене
				$promptText = "Введите имя доменной учётной записи от имени которого будет работать служба 1С."
				if ($defaultDomain) {
					$promptText += "`nДомен будет автоматически подставлен: $defaultDomain"
					$promptText += "`nПример: User1C (будет использовано: $defaultDomain\User1C)"
					$promptText += "`nИли введите полное имя: домен\пользователь"
				} else {
					$promptText += "`nВведите в формате: домен\пользователь"
					$promptText += "`nПример: domen\User1C"
				}
				
				$serviceUser = Show-InputDialog -Title "Доменная учётная запись" -Prompt $promptText -DefaultValue "" -CancelText "Отмена"
				
				# Если нажата кнопка "Отмена", выходим из функции
				if ($null -eq $serviceUser) {
					Write-ToOutputColored "[ОШИБКА] Ввод доменной учётной записи прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					# Очищаем SecureString из памяти, если он был создан ранее (на случай повторного входа)
					if ($null -ne $servicePasswordSecure) {
						$servicePasswordSecure.Dispose()
						$servicePasswordSecure = $null
						[System.GC]::Collect()
					}
					return
				}
				
				# Если введено пустое значение, показываем ошибку и продолжаем цикл
				if ($serviceUser -eq "") {
					Write-ToOutputColored "[ОШИБКА] Не введено имя пользователя. Пожалуйста, введите имя пользователя." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					$serviceUserValid = $false
					continue
				}
				
				# Обработка ввода: если указан домен - используем как есть, если нет - добавляем автоматически
				if ($serviceUser -match "\\") {
					# Пользователь ввёл полное имя "домен\пользователь" - используем как есть
					$serviceUserValid = $true
				} else {
					# Пользователь ввёл только имя пользователя - добавляем домен автоматически
					if ($defaultDomain) {
						$serviceUser = "$defaultDomain\$serviceUser"
						$serviceUserValid = $true
					} else {
						# Если домен не удалось определить автоматически, требуем ввод в формате "домен\пользователь"
						Write-ToOutputColored "[ОШИБКА] Не удалось определить домен автоматически. Введите учётную запись в формате домен\пользователь." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
						$serviceUserValid = $false
						continue
					}
				}
				
				# Существование учётной записи и пароль проверяются вместе в Test-DomainCredentials (после ввода пароля)
			} while (-not $serviceUserValid)
			
			# Диалог ввода пароля с использованием SecureString
			$servicePasswordSecure = $null
			$isEmpty = $true
			do {
				$servicePasswordSecure = Show-PasswordDialog -Title "Ввод пароля" -Prompt "Введите пароль от учётной записи $serviceUser" -CancelText "Отмена"
				
				# Если нажата кнопка "Отмена", выходим из функции
				if ($null -eq $servicePasswordSecure) {
					Write-ToOutputColored "[ОШИБКА] Ввод пароля прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					# Очищаем SecureString из памяти
					if ($null -ne $servicePasswordSecure) {
						$servicePasswordSecure.Dispose()
						$servicePasswordSecure = $null
					}
					[System.GC]::Collect()
					return
				}
				
				# Проверяем, что пароль не пустой (проверяем длину SecureString)
				$testBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($servicePasswordSecure)
				$testPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($testBSTR)
				$isEmpty = [string]::IsNullOrEmpty($testPlain)
				[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($testBSTR)
				$testPlain = $null
				
				if ($isEmpty) {
					Write-ToOutputColored "[ОШИБКА] Не введен пароль. Пожалуйста, введите пароль." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					# Очищаем SecureString из памяти
					if ($null -ne $servicePasswordSecure) {
						$servicePasswordSecure.Dispose()
						$servicePasswordSecure = $null
					}
					[System.GC]::Collect()
					continue
				}
				
				# Проверяем доменную учётную запись и пароль
				Write-ToOutput "Проверка учётных данных..." ([System.Drawing.Color]::Yellow)
				$credentialsValid = Test-DomainCredentials -Username $serviceUser -SecurePassword $servicePasswordSecure
				
				if (-not $credentialsValid) {
					Write-ToOutputColored "[ОШИБКА] Неверный пароль или учётная запись не найдена в домене. Проверьте правильность ввода." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					# Очищаем SecureString из памяти перед повторным вводом
					if ($null -ne $servicePasswordSecure) {
						$servicePasswordSecure.Dispose()
						$servicePasswordSecure = $null
					}
					[System.GC]::Collect()
					# Выходим из цикла пароля — внешний цикл повторится и снова откроется окно ввода учётной записи
					break
				} else {
					Write-ToOutputColored "[OK] Учётные данные проверены успешно" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
					# Выходим из цикла - пароль валиден
					break
				}
			} while ($true)
			
			# Если учётные данные приняты — выходим из внешнего цикла
			if ($credentialsValid) { break }
		} while ($true)
		
		# Диалог ввода пути для рабочих процессов: проверка формата, существования диска/родителя, создание папки (при ошибке — повторный ввод)
		$jobProcessPath = $null
		$jobProcessPathValid = $false
		do {
			$jobProcessPath = Show-InputDialog -Title "Путь для рабочих процессов" -Prompt "Введите полный путь где будут храниться рабочие процессы.`nПример: C:\srvinfo_1740" -DefaultValue "" -CancelText "Отмена"
			
			# Если нажата кнопка "Отмена", выходим из функции
			if ($null -eq $jobProcessPath) {
				Write-ToOutputColored "[ОШИБКА] Ввод пути для рабочих процессов прерван пользователем." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				# Очищаем SecureString из памяти при выходе
				if ($null -ne $servicePasswordSecure) {
					$servicePasswordSecure.Dispose()
					$servicePasswordSecure = $null
				}
				[System.GC]::Collect()
				return
			}
			
			# Если введено пустое значение, показываем ошибку и продолжаем цикл
			if ($jobProcessPath -eq "") {
				Write-ToOutputColored "[ОШИБКА] Не введен путь для рабочих процессов. Пожалуйста, введите путь." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$jobProcessPathValid = $false
				continue
			}
			
			# Проверка формата пути (должен содержать :\ для локального диска)
			if (-not ($jobProcessPath -match ":"+"\\")) {
				Write-ToOutputColored "[ОШИБКА] Неверно указан путь. Путь должен содержать диск, например C:\" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$jobProcessPathValid = $false
				continue
			}
			
			# Проверка существования пути и создание папки (локально или на удалённом сервере)
			try {
				$pathCreated = $false
				if ($isLocal) {
					# Локально: проверяем диск/родитель, создаём папку
					$drive = (Split-Path -Path $jobProcessPath -Qualifier -ErrorAction SilentlyContinue)
					if (-not $drive) { $drive = $jobProcessPath.Substring(0, 2) }
					if (-not (Test-Path -LiteralPath $drive -ErrorAction SilentlyContinue)) {
						Write-ToOutputColored "[ОШИБКА] Диск или путь не существует: $drive Укажите существующий путь." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
						$jobProcessPathValid = $false
						continue
					}
					try {
						$null = New-Item -Path $jobProcessPath -ItemType Directory -Force -ErrorAction Stop
						$pathCreated = Test-Path -LiteralPath $jobProcessPath -PathType Container -ErrorAction SilentlyContinue
					} catch {
						Write-ToOutputColored "[ОШИБКА] Не удалось создать папку: $($_.Exception.Message) Укажите другой путь." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
						$jobProcessPathValid = $false
						continue
					}
				} else {
					# Удалённо: создаём папку на сервере через Invoke-Command
					$createResult = Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $jobProcessPath -ScriptBlock {
						param([string]$Path)
						try {
							$drive = (Split-Path -Path $Path -Qualifier -ErrorAction SilentlyContinue)
							if (-not $drive) { $drive = $Path.Substring(0, [Math]::Min(2, $Path.Length)) }
							if (-not (Test-Path -LiteralPath $drive -ErrorAction SilentlyContinue)) {
								return @{ Success = $false; Message = "Диск или путь не существует: $drive" }
							}
							$null = New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
							$exists = Test-Path -LiteralPath $Path -PathType Container -ErrorAction SilentlyContinue
							return @{ Success = $exists; Message = if ($exists) { "OK" } else { "Папка не создана" } }
						} catch {
							return @{ Success = $false; Message = $_.Exception.Message }
						}
					}
					$pathCreated = $createResult.Success
					if (-not $pathCreated) {
						Write-ToOutputColored "[ОШИБКА] $($createResult.Message) Укажите другой путь." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
						$jobProcessPathValid = $false
						continue
					}
				}
				if ($pathCreated) {
					$jobProcessPathValid = $true
					Write-ToOutputColored "[OK] Папка для рабочих процессов создана или уже существует: $jobProcessPath" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
				} else {
					Write-ToOutputColored "[ОШИБКА] Папка не создана. Укажите другой путь." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
					$jobProcessPathValid = $false
				}
			} catch {
				Write-ToOutputColored "[ОШИБКА] Ошибка при проверке/создании пути: $($_.Exception.Message) Укажите другой путь." "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				$jobProcessPathValid = $false
			}
		} while (-not $jobProcessPathValid)
		
		# Передача пароля через зашифрованный файл с ключом AES-256 для максимальной безопасности
		# Пароль шифруется локально, передается зашифрованный файл и ключ отдельно
		# Это предотвращает попадание пароля в логи WinRM и защищает от восстановления удаленных файлов
		Write-ToOutput "Шифрование пароля для безопасной передачи на удаленный сервер..." ([System.Drawing.Color]::Yellow)
		
		# Конвертируем SecureString в обычную строку для шифрования
		$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($servicePasswordSecure)
		$servicePasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
		[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
		
		# Шифруем пароль локально с использованием AES-256
		# Создаем переменные для ключа и IV, которые будут заполнены функцией через [ref]
		# Для [ref] параметров в PowerShell нужно создать переменные с явным указанием типа
		[byte[]]$encryptionKeyBytes = $null
		[byte[]]$ivBytes = $null
		$encryptedPasswordBase64 = $null
		
		try {
			$encryptedPasswordBase64 = Encrypt-Password -Password $servicePasswordPlain -EncryptionKey ([ref]$encryptionKeyBytes) -IV ([ref]$ivBytes)
			
			# Очищаем пароль из локальной памяти сразу после шифрования
			$servicePasswordPlain = $null
			[System.GC]::Collect()
			
			Write-ToOutputColored "[OK] Пароль зашифрован с использованием AES-256" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
		}
		catch {
			Write-ToOutputColored "[ОШИБКА] Не удалось зашифровать пароль: $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			# Очищаем пароль из памяти при ошибке
			if ($null -ne $servicePasswordPlain) {
				$servicePasswordPlain = $null
			}
			if ($null -ne $servicePasswordSecure) {
				$servicePasswordSecure.Dispose()
				$servicePasswordSecure = $null
			}
			[System.GC]::Collect()
			return
		}
		
		# Создаем временный файл для зашифрованного пароля на удаленном сервере
		$tempPasswordFile = $null
		try {
			$tempPasswordFile = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
				# Создаем временный файл с уникальным именем
				$tempFile = Join-Path $env:TEMP "1C_Password_Encrypted_$(New-Guid).tmp"
				
				# Возвращаем путь к файлу (файл будет создан позже)
				return $tempFile
			}
			
			# Записываем зашифрованный пароль в файл на удаленном сервере через Invoke-Command
			Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $tempPasswordFile, $encryptedPasswordBase64 -ScriptBlock {
				param([string]$TempFilePath, [string]$EncryptedPassword)
				
				# Записываем зашифрованный пароль в файл
				$EncryptedPassword | Out-File -FilePath $TempFilePath -Encoding UTF8 -NoNewline -Force
				
				# Устанавливаем права доступа: только текущий пользователь может читать и удалять файл
				$acl = Get-Acl $TempFilePath
				$acl.SetAccessRuleProtection($true, $false)  # Отключить наследование, удалить все существующие правила
				$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
				$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
					$currentUser, 
					"Read,Delete", 
					"Allow"
				)
				$acl.SetAccessRule($accessRule)
				Set-Acl -Path $TempFilePath -AclObject $acl
			}
			
			# Очищаем зашифрованный пароль из локальной памяти после записи в файл
			$encryptedPasswordBase64 = $null
			[System.GC]::Collect()
			
			Write-ToOutputColored "[OK] Зашифрованный файл с паролем создан на удаленном сервере с ограниченными правами доступа" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
		}
		catch {
			Write-ToOutputColored "[ОШИБКА] Не удалось создать зашифрованный файл с паролем на удаленном сервере: $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			# Очищаем данные из памяти при ошибке
			if ($null -ne $servicePasswordPlain) {
				$servicePasswordPlain = $null
			}
			if ($null -ne $servicePasswordSecure) {
				$servicePasswordSecure.Dispose()
				$servicePasswordSecure = $null
			}
			$encryptedPasswordBase64 = $null
			$encryptionKeyBytes = $null
			$ivBytes = $null
			[System.GC]::Collect()
			return
		}
		
		# Выполняем установку службы удалённо
		# Пароль будет расшифрован из зашифрованного файла на удаленном сервере с использованием переданного ключа
		try {
			# Передаем ключ и IV для расшифровки пароля через отдельный Invoke-Command
			# Ключ передается отдельно от зашифрованного файла для дополнительной безопасности
			$serviceOutput = Invoke-Command -ComputerName $Server -ErrorAction Stop -ArgumentList $selectedVersion, $serverPort, $clusterPort, $rangePort, $serviceUser, $tempPasswordFile, $jobProcessPath, $encryptionKeyBytes, $ivBytes -ScriptBlock {
			param([string]$PackageVersion, [string]$InputPort, [string]$InputRegPort, [string]$InputRangePort, [string]$InputUser, [string]$InputPasswordFilePath, [string]$InputPathJobProcess, [byte[]]$EncryptionKey, [byte[]]$IV)
			
			$result = @()
			
			# Функция для расшифровки пароля (локальная функция в ScriptBlock)
			function Decrypt-PasswordLocal {
				param(
					[string]$EncryptedPasswordBase64,
					[byte[]]$Key,
					[byte[]]$IVLocal
				)
				
				try {
					$aes = New-Object System.Security.Cryptography.AesManaged
					$aes.KeySize = 256
					$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
					$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
					$aes.Key = $Key
					$aes.IV = $IVLocal
					
					$decryptor = $aes.CreateDecryptor()
					$encryptedBytes = [Convert]::FromBase64String($EncryptedPasswordBase64)
					$decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
					$decryptedPassword = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
					
					# Очищаем память
					$encryptedBytes = $null
					$decryptedBytes = $null
					$decryptor.Dispose()
					$aes.Dispose()
					
					return $decryptedPassword
				}
				catch {
					throw "Ошибка при расшифровке пароля: $($_.Exception.Message)"
				}
			}
			
			# Читаем и расшифровываем пароль из зашифрованного файла
			$InputPasswordPlain = $null
			$encryptedPasswordBase64 = $null
			try {
				if (-not (Test-Path $InputPasswordFilePath -ErrorAction SilentlyContinue)) {
					throw "Зашифрованный файл с паролем не найден: $InputPasswordFilePath"
				}
				
				# Читаем зашифрованный пароль из файла
				$encryptedPasswordBase64 = Get-Content $InputPasswordFilePath -Raw -ErrorAction Stop
				if ([string]::IsNullOrEmpty($encryptedPasswordBase64)) {
					throw "Зашифрованный файл с паролем пуст"
				}
				
				# Немедленно удаляем файл после чтения
				Remove-Item $InputPasswordFilePath -Force -ErrorAction Stop
				
				# Расшифровываем пароль с использованием ключа и IV
				$InputPasswordPlain = Decrypt-PasswordLocal -EncryptedPasswordBase64 $encryptedPasswordBase64 -Key $EncryptionKey -IVLocal $IV
				
				# Очищаем зашифрованные данные из памяти
				$encryptedPasswordBase64 = $null
				$EncryptionKey = $null
				$IV = $null
				[System.GC]::Collect()
			}
			catch {
				$result += "[ОШИБКА] Не удалось прочитать и расшифровать пароль из файла: $($_.Exception.Message)|Red"
				# Очищаем данные из памяти при ошибке
				if ($null -ne $encryptedPasswordBase64) {
					$encryptedPasswordBase64 = $null
				}
				if ($null -ne $EncryptionKey) {
					$EncryptionKey = $null
				}
				if ($null -ne $IV) {
					$IV = $null
				}
				[System.GC]::Collect()
				return $result
			}
			
			try {
				$Package = $PackageVersion
				[string]$PackageSource = (Get-Package | Where-Object {($_.Name -match "1С:Предприятие 8") -and ($_.Source -notmatch "(x86)") -and ($_.Source -match $Package)}).Source
				[string]$PackageName = (Get-Package | Where-Object {($_.Name -match "1С:Предприятие 8") -and ($_.Source -notmatch "(x86)") -and ($_.Source -match $Package)}).Name
				
				$SplitPackageSource = $PackageSource.Split("\")
				$SplitPackageSource1 = $SplitPackageSource[3].Split(".")
				$SplitPackageName = $PackageName.Split(" ")
				
				$HomeCat = "$InputPathJobProcess\"
				$PathToBin = "$PackageSource\Bin\ragent.exe"
				$Name = "1C:Enterprise $($SplitPackageSource1[0]).$($SplitPackageSource1[1]) Server Agent ($InputPort)"
				$ImagePath = "`"$PathToBin`" -srvc -agent -regport $InputRegPort -port $InputPort -range $InputRangePort -debug -d `"$HomeCat`""
				$Description = "Агент сервера $($SplitPackageName[0]) $($SplitPackageSource1[0]).$($SplitPackageSource1[1]) ($InputPort)"
				
				# Проверка и создание папки для рабочих процессов
				if (Test-Path "$InputPathJobProcess" -ErrorAction Stop) {
					$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($InputUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
					$parentACL = Get-Acl -Path $InputPathJobProcess
					$parentACL.SetAccessRule($AccessRule)
					Set-Acl -Path $InputPathJobProcess -AclObject $parentACL
				} else {
					[void](New-Item $InputPathJobProcess -ItemType Directory)
					$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($InputUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
					$parentACL = Get-Acl -Path $InputPathJobProcess
					$parentACL.SetAccessRule($AccessRule)
					Set-Acl -Path $InputPathJobProcess -AclObject $parentACL
				}
				
				# Установка службы БЕЗ учетных данных (создаем с системной учетной записью)
				# New-Service -Credential иногда не устанавливает пароль правильно при удаленном выполнении
				# Поэтому сначала создаем службу, а затем устанавливаем учетную запись и пароль через sc.exe
				[void](New-Service -Name $Name -BinaryPathName $ImagePath -Description $Description -DisplayName $Description -StartupType Boot)
				
				# Установка учетной записи и пароля через sc.exe config (более надежный способ)
				# sc.exe config устанавливает пароль напрямую в реестр службы, что гарантирует правильную установку
				# ВАЖНО: sc.exe получает пароль в командной строке, что является известным ограничением безопасности Windows
				# Пароль может быть виден в списке процессов во время выполнения команды
				$scConfigResult = & sc.exe config "$Name" obj= "$InputUser" password= "$InputPasswordPlain" 2>&1
				$scExitCode = $LASTEXITCODE
				
				# Безопасная очистка пароля из памяти на удаленной стороне сразу после использования
				# Создаем копию пароля для безопасной перезаписи памяти
				# ВАЖНО: В .NET строки неизменяемы (immutable), поэтому полная перезапись памяти невозможна
				# Однако мы минимизируем время жизни пароля и принудительно очищаем память
				$passwordLength = if ($null -ne $InputPasswordPlain) { $InputPasswordPlain.Length } else { 0 }
				$InputPasswordPlain = $null
				
				# Принудительная сборка мусора для очистки памяти на удаленной стороне
				# Вызываем несколько раз для более надежной очистки
				[System.GC]::Collect()
				[System.GC]::WaitForPendingFinalizers()
				[System.GC]::Collect()
				
				# Проверяем результат выполнения sc.exe после очистки пароля
				if ($scExitCode -ne 0) {
					throw "Не удалось установить учетную запись для службы через sc.exe: $scConfigResult"
				}
				
				$result += "[OK] Служба $Name Зарегистрирована|Green"
			}
			catch {
				$result += "[ОШИБКА] $($_.Exception.Message)|Red"
				# Безопасная очистка пароля из памяти даже при ошибке
				# Минимизируем время жизни пароля в памяти
				if ($null -ne $InputPasswordPlain) {
					$passwordLength = $InputPasswordPlain.Length
					$InputPasswordPlain = $null
				}
				# Принудительная сборка мусора для очистки памяти
				[System.GC]::Collect()
				[System.GC]::WaitForPendingFinalizers()
				[System.GC]::Collect()
			}
			finally {
				# Дополнительная очистка в блоке finally для гарантии очистки памяти
				# Это гарантирует, что пароль будет очищен даже если произойдет неожиданная ошибка
				if ($null -ne $InputPasswordPlain) {
					$InputPasswordPlain = $null
				}
				# Очищаем ключ и IV из памяти
				if ($null -ne $EncryptionKey) {
					$EncryptionKey = $null
				}
				if ($null -ne $IV) {
					$IV = $null
				}
				# Удаляем зашифрованный файл с паролем, если он еще существует (на случай ошибки)
				if (Test-Path $InputPasswordFilePath -ErrorAction SilentlyContinue) {
					Remove-Item $InputPasswordFilePath -Force -ErrorAction SilentlyContinue
				}
				[System.GC]::Collect()
				[System.GC]::WaitForPendingFinalizers()
				[System.GC]::Collect()
			}
			
			return $result
		}
		}
		catch {
			# Обработка ошибок при выполнении Invoke-Command
			Write-ToOutputColored "[ОШИБКА] Ошибка при установке службы: $($_.Exception.Message)" "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
			
			# Очистка пароля из памяти при ошибке
			if ($null -ne $servicePasswordPlain) {
				$servicePasswordPlain = $null
			}
			if ($null -ne $servicePasswordSecure) {
				$servicePasswordSecure.Dispose()
				$servicePasswordSecure = $null
			}
			
			# Удаляем зашифрованный файл с паролем на удаленном сервере при ошибке
			if ($null -ne $tempPasswordFile) {
				try {
					Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ArgumentList $tempPasswordFile -ScriptBlock {
						param([string]$TempFilePath)
						if (Test-Path $TempFilePath -ErrorAction SilentlyContinue) {
							Remove-Item $TempFilePath -Force -ErrorAction SilentlyContinue
						}
					}
				}
				catch {
					# Игнорируем ошибки удаления файла
				}
			}
			
			# Очищаем ключ шифрования и IV из памяти при ошибке
			if ($null -ne $encryptionKeyBytes) {
				$encryptionKeyBytes = $null
			}
			if ($null -ne $ivBytes) {
				$ivBytes = $null
			}
			if ($null -ne $encryptedPasswordBase64) {
				$encryptedPasswordBase64 = $null
			}
			
			[System.GC]::Collect()
			
			# Проверка логов WinRM на наличие паролей при ошибке установки
			# ВАЖНО: Проверка выполняется на том же сервере, где происходила установка (через Invoke-Command)
			Write-ToOutput "" ([System.Drawing.Color]::White)
			$passwordCheckResult = Test-WinRMPasswordInLogs -Server $Server -CheckPeriodMinutes 15
			if (-not $passwordCheckResult) {
				Write-ToOutputColored "[ВНИМАНИЕ] Рекомендуется проверить логи WinRM на сервере $Server вручную для подтверждения безопасности." "[ВНИМАНИЕ]" ([System.Drawing.Color]::Yellow) ([System.Drawing.Color]::White)
			}
			
			# Проверка логов WinRM на локальном сервере (с которого запускается скрипт)
			Write-ToOutput "" ([System.Drawing.Color]::White)
			$localPasswordCheckResult = Test-WinRMPasswordInLogs -CheckPeriodMinutes 15
			if (-not $localPasswordCheckResult) {
				$localServerName = $env:COMPUTERNAME
				Write-ToOutputColored "[ВНИМАНИЕ] Рекомендуется проверить логи WinRM на локальном сервере $localServerName вручную для подтверждения безопасности." "[ВНИМАНИЕ]" ([System.Drawing.Color]::Yellow) ([System.Drawing.Color]::White)
			}
			
			# Выходим из функции при ошибке
			return
		}
		
		# Вывод результатов установки службы
		foreach ($line in $serviceOutput) {
			if (-not [string]::IsNullOrEmpty($line)) {
				$parts = $line -split '\|', 2
				$text = $parts[0]
				$colorName = if ($parts.Length -gt 1) { $parts[1] } else { "White" }
				
				# Проверяем, содержит ли текст маркеры [ОШИБКА] или [OK]
				if ($text -match '\[ОШИБКА\]') {
					Write-ToOutputColored $text "[ОШИБКА]" ([System.Drawing.Color]::Red) ([System.Drawing.Color]::White)
				}
				elseif ($text -match '\[OK\]') {
					# Специальная обработка для сообщения о регистрации службы
					# Формат: [OK] <Название службы> Зарегистрирована
					if ($text -match '\[OK\]\s+(.+?)\s+Зарегистрирована') {
						$serviceName = $matches[1]
						
						# Используем прямой доступ к RichTextBox для вывода без переводов строк между частями
						try {
							if ($Global:OutputTextBox -ne $null -and -not $Global:OutputTextBox.IsDisposed) {
								$Global:OutputTextBox.SelectionStart = $Global:OutputTextBox.TextLength
								$Global:OutputTextBox.SelectionLength = 0
								
								# Выводим [OK] зеленым
								$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
								$Global:OutputTextBox.AppendText("[OK] ")
								
								# Выводим название службы белым
								$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::White
								$Global:OutputTextBox.AppendText("$serviceName ")
								
								# Выводим "Зарегистрирована" зеленым
								$Global:OutputTextBox.SelectionColor = [System.Drawing.Color]::Green
								$Global:OutputTextBox.AppendText("Зарегистрирована")
								
								# Добавляем перевод строки и сбрасываем цвет
								$Global:OutputTextBox.AppendText("`r`n")
								$Global:OutputTextBox.SelectionColor = $Global:OutputTextBox.ForeColor
								$Global:OutputTextBox.ScrollToCaret()
								[System.Windows.Forms.Application]::DoEvents()
							}
						}
						catch {
							# Если ошибка, используем стандартный вывод
							Write-ToOutputColored $text "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
						}
					}
					else {
						# Стандартная обработка для других сообщений с [OK]
						Write-ToOutputColored $text "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
					}
				}
				else {
					# Для остальных случаев используем стандартный вывод
					$color = switch ($colorName) {
						"Green" { [System.Drawing.Color]::Green }
						"Red" { [System.Drawing.Color]::Red }
						"Yellow" { [System.Drawing.Color]::Yellow }
						"Cyan" { [System.Drawing.Color]::Cyan }
						"Gray" { [System.Drawing.Color]::Gray }
						"Magenta" { [System.Drawing.Color]::Magenta }
						default { [System.Drawing.Color]::White }
					}
					
					Write-ToOutput $text $color
				}
			}
		}
		
		# Удаляем зашифрованный файл с паролем на удаленном сервере после успешной установки (на случай если он еще существует)
		if ($null -ne $tempPasswordFile) {
			try {
				Invoke-Command -ComputerName $Server -ErrorAction SilentlyContinue -ArgumentList $tempPasswordFile -ScriptBlock {
					param([string]$TempFilePath)
					if (Test-Path $TempFilePath -ErrorAction SilentlyContinue) {
						Remove-Item $TempFilePath -Force -ErrorAction SilentlyContinue
					}
				}
				Write-ToOutputColored "[OK] Зашифрованный файл с паролем удален с удаленного сервера" "[OK]" ([System.Drawing.Color]::Green) ([System.Drawing.Color]::White)
			}
			catch {
				# Игнорируем ошибки удаления файла (файл мог быть уже удален в ScriptBlock)
			}
		}
		
		# Очистка ключа шифрования и IV из памяти
		if ($null -ne $encryptionKeyBytes) {
			$encryptionKeyBytes = $null
		}
		if ($null -ne $ivBytes) {
			$ivBytes = $null
		}
		
		# Очистка пароля из памяти после использования
		# Очищаем обычную строку пароля (использовалась для шифрования)
		if ($null -ne $servicePasswordPlain) {
			$servicePasswordPlain = $null
		}
		if ($null -ne $encryptedPasswordBase64) {
			$encryptedPasswordBase64 = $null
		}
		
		# Очищаем SecureString
		if ($null -ne $servicePasswordSecure) {
			$servicePasswordSecure.Dispose()
			$servicePasswordSecure = $null
		}
		
		# Очищаем буфер обмена на случай, если там случайно остался пароль
		try {
			[System.Windows.Forms.Clipboard]::Clear()
		}
		catch {
			# Игнорируем ошибки очистки буфера обмена
		}
		
		# Принудительная сборка мусора для очистки памяти
		[System.GC]::Collect()
		[System.GC]::WaitForPendingFinalizers()
		[System.GC]::Collect()
		
		# Проверка логов WinRM на наличие паролей после установки службы
		# Пароль передавался через временный файл, но проверяем логи для дополнительной безопасности
		# ВАЖНО: Проверка выполняется на том же сервере, где происходила установка (через Invoke-Command)
		Write-ToOutput "" ([System.Drawing.Color]::White)
		$passwordCheckResult = Test-WinRMPasswordInLogs -Server $Server -CheckPeriodMinutes 15
		if (-not $passwordCheckResult) {
			Write-ToOutputColored "[ВНИМАНИЕ] Рекомендуется проверить логи WinRM на сервере $Server вручную для подтверждения безопасности." "[ВНИМАНИЕ]" ([System.Drawing.Color]::Yellow) ([System.Drawing.Color]::White)
		}
		
		# Проверка логов WinRM на локальном сервере (с которого запускается скрипт)
		Write-ToOutput "" ([System.Drawing.Color]::White)
		$localPasswordCheckResult = Test-WinRMPasswordInLogs -CheckPeriodMinutes 15
		if (-not $localPasswordCheckResult) {
			$localServerName = $env:COMPUTERNAME
			Write-ToOutputColored "[ВНИМАНИЕ] Рекомендуется проверить логи WinRM на локальном сервере $localServerName вручную для подтверждения безопасности." "[ВНИМАНИЕ]" ([System.Drawing.Color]::Yellow) ([System.Drawing.Color]::White)
		}
	}
	
	Clear-Variable -Name "Server"
}


# |========================================|
# |     Создание и отображение формы       |
# |========================================|

# Важно: форма создается ДО переопределения Write-Host, чтобы GUI был готов
$Global:MainForm = Create-MainForm

# Инициализация приветственного сообщения
Write-ToOutput "Добро пожаловать в 1C Automation Tool!" ([System.Drawing.Color]::Cyan)
Write-ToOutput "Подключитесь к серверу для начала работы." ([System.Drawing.Color]::Yellow)

# Запуск GUI формы
# Проверяем, запущены ли мы в ISE или обычном PowerShell
if ($Host.Name -eq "Windows PowerShell ISE Host") {
    # В ISE: перехват исключений — не завершаем процесс, чтобы окно ISE оставалось открытым
    [System.Windows.Forms.Application]::Add_ThreadException({
        param($sender, [System.Threading.ThreadExceptionEventArgs]$e)
        try {
            if ($Global:MainForm -ne $null -and -not $Global:MainForm.IsDisposed) { $Global:MainForm.Close() }
        } catch { }
    })
    # Перехват на уровне AppDomain — в ISE не вызываем Exit(0), чтобы не закрывать ISE
    $null = [AppDomain]::CurrentDomain.add_UnhandledException({
        param($sender, [System.UnhandledExceptionEventArgs]$e)
        if ($e.ExceptionObject -is [System.Management.Automation.PipelineStoppedException] -and $Host.Name -ne "Windows PowerShell ISE Host") {
            [Environment]::Exit(0)
        }
    })
    # В ISE используем ShowDialog() — при закрытии формы (крестик или Выход) процесс не завершаем, ISE остаётся открытым
    $Global:MainForm.Add_FormClosed({
        try {
            if ($Global:ProgressForm -ne $null -and -not $Global:ProgressForm.IsDisposed) {
                try { $Global:ProgressForm.Close() } catch { }
            }
        } catch { }
    })
    $Global:MainForm.ShowDialog() | Out-Null
}
else {
    # В обычном PowerShell используем Application::Run
    [System.Windows.Forms.Application]::Run($Global:MainForm)
}

# Очистка при закрытии формы
if ($Global:MainForm -ne $null -and -not $Global:MainForm.IsDisposed) {
    $Global:MainForm.Dispose()
}