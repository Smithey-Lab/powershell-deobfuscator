// Evidence heuristics, not malware verdicts. Patterns never come from submitted text.
export const extraRules = [
  [
    "Indirect command invocation",
    /(?:^|[\s;(|])&\s*(?=[($'"{])|\.\s+(?=\()/i,
    "Uses an invocation operator with a constructed command name. Literal parts may decode, but variable or environment values can determine what actually runs.",
  ],
  [
    "Environment-based name construction",
    /\bEnv:\\?[^\s)]+|\$\{?env:[\w]+/i,
    "Reads an environment-provider value. Indexing or joining its characters can hide a command name. The target environment is unknown; this tool does not substitute its own environment.",
  ],
  [
    "Character indexing or reversal",
    /\]\s*\[\s*-?\d|\[\s*-\d+\s*\.\.\s*-\d+\s*\]|\.value\s*\[/i,
    "Selects characters or elements by index, potentially in reverse order. This is a common way to conceal strings and command names.",
  ],
  [
    "Constructs strings with formatting",
    /-f\s*(?=['"(])|\{\d+\}/i,
    "Uses numbered placeholders to reorder pieces of text. Literal-only expressions can be reconstructed; dynamic pieces may remain unknown.",
  ],
  [
    "Joins pieces of text",
    /-join\b/i,
    "Combines characters or strings. An unknown separator or pipeline value can prevent full reconstruction.",
  ],
  [
    "Uses pipeline-dependent values",
    /\$_\b|\$PSItem\b/i,
    "Uses the current pipeline item. Its value depends on surrounding execution; it is not assumed to be empty.",
  ],
  [
    "Wildcard command discovery",
    /\b(?:gcm|Get-Command|gal|Get-Alias)\s+[^;\r\n]*[?*]/i,
    "Discovers a command or alias by wildcard rather than spelling its name. Available commands and aliases determine the result.",
  ],
  [
    "Alias manipulation",
    /\b(?:Set-Alias|New-Alias|sal|nal)\b/i,
    "Defines or changes an alias, which may hide later command execution behind another name.",
  ],
  [
    "Encoded payload",
    /FromBase64String|-(?:enc|encodedcommand)\b|FromHexString/i,
    "References encoded data. Encoding alone is not malicious; inspect decoded candidates and how the data is used.",
  ],
  [
    "Compression wrapper",
    /\b(?:GZipStream|DeflateStream|BrotliStream|CompressionMode)\b/i,
    "References compressed content. Supported literal gzip payloads are expanded within strict size limits; other wrappers may remain unresolved.",
  ],
  [
    "XOR or bitwise transformation",
    /-(?:bxor|band|bor|shl|shr)\b/i,
    "Transforms numeric values using bitwise operations. Constant expressions can decode; loops and runtime keys are not executed.",
  ],
  [
    "Cryptographic transformation",
    /\b(?:AesManaged|RijndaelManaged|CreateDecryptor|CryptoStream|ProtectedData|FromSecureString|ConvertTo-SecureString)\b/i,
    "References encryption, decryption, or protected strings. The key and runtime context may be necessary to recover the payload.",
  ],
  [
    "Remote command execution capability",
    /\b(?:Invoke-Command|Enter-PSSession|New-PSSession|Invoke-WmiMethod|Invoke-CimMethod|Win32_Process)\b/i,
    "References remoting or management primitives that can invoke actions locally or remotely. Inspect target hosts and method arguments.",
  ],
  [
    "System discovery",
    /\b(?:Get-ComputerInfo|Get-WmiObject|Get-CimInstance|Get-Process|Get-Service|whoami|systeminfo|ipconfig|Get-NetIPConfiguration|Get-LocalUser|Get-ADUser)\b/i,
    "Enumerates system, process, network, or account information. This is also common in legitimate administration.",
  ],
  [
    "Network discovery",
    /\b(?:Test-NetConnection|Resolve-DnsName|nslookup|netstat|Get-NetTCPConnection|Get-ADComputer)\b/i,
    "References network or host discovery. Check targets and loops to determine scope.",
  ],
  [
    "Registry access",
    /\b(?:Set-ItemProperty|New-ItemProperty|Remove-ItemProperty)\b|\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)[:\\]/i,
    "Reads or changes registry-related data. Registry access alone does not establish persistence or malicious behavior.",
  ],
  [
    "WMI event subscription",
    /\b(?:CommandLineEventConsumer|ActiveScriptEventConsumer|__EventFilter|__FilterToConsumerBinding)\b/i,
    "References WMI event subscription components, which can support execution when a specified event occurs.",
  ],
  [
    "Startup-folder reference",
    /\bStart Menu\\Programs\\Startup\b|\bStartupPath\b/i,
    "References a startup location. Writing a program or shortcut here may arrange future execution.",
  ],
  [
    "Security exclusions or disabled scanning",
    /\b(?:DisableRealtimeMonitoring|DisableScriptScanning|ExclusionPath|ExclusionProcess|DisableBehaviorMonitoring)\b/i,
    "References settings that can weaken scanning or add exclusions. Inspect the value being assigned.",
  ],
  [
    "Event-log or history changes",
    /\b(?:Clear-EventLog|wevtutil|Clear-History|HistorySaveStyle|Remove-EventLog)\b/i,
    "References event logs or shell history. Check whether the operation reads, clears, or disables recording.",
  ],
  [
    "Shadow-copy or recovery changes",
    /\b(?:vssadmin|wbadmin|Win32_ShadowCopy|bcdedit)\b/i,
    "References backup, shadow-copy, or boot configuration tools. Some arguments can impair recovery; their presence alone is not enough to conclude that.",
  ],
  [
    "File collection or archive creation",
    /\b(?:Compress-Archive|CreateFromDirectory|ZipFile|tar\.exe|7z\.exe)\b/i,
    "References archiving, which can package files for backup or collection. Inspect source and destination paths.",
  ],
  [
    "Possible outbound data transfer",
    /\b(?:UploadString|UploadData|UploadFile|Send-MailMessage)\b|-Method\s+['"]?(?:POST|PUT)\b/i,
    "Contains an upload, mail, or HTTP write indicator. Inspect the destination and content to determine whether sensitive data could leave the host.",
  ],
  [
    "Living-off-the-land utility",
    /\b(?:certutil|bitsadmin|msbuild|installutil|wmic|forfiles)\b/i,
    "References a built-in or commonly installed utility that can perform sensitive actions. Behavior depends on its arguments.",
  ],
  [
    "Clipboard access",
    /\b(?:Get-Clipboard|Set-Clipboard|Windows\.Forms\.Clipboard)\b/i,
    "References reading or writing the clipboard. Clipboard contents are runtime data and are not inspected by this analyzer.",
  ],
  [
    "Sleep or delayed execution",
    /\b(?:Start-Sleep|Thread\]\s*::\s*Sleep|timeout\.exe)\b/i,
    "Introduces a delay. This may be ordinary timing logic or may postpone a later action.",
  ],
  [
    "Dynamic member access",
    /\.\s*\$[\w]+\s*\(|\.\s*\(\s*['"$]/i,
    "Builds a method or member name dynamically. The resolved object and member determine the effect.",
  ],
  [
    "Script-block invocation",
    /\.\s*Invoke\s*\(|&\s*\{/i,
    "Contains an invocation form that may run a script block or callable object. The target must be examined.",
  ],
];
