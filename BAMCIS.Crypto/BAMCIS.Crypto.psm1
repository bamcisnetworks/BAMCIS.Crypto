Function ConvertFrom-PEM {
	<#
		
	#>
	[CmdletBinding()]
	[OutputType([System.Byte[]], [System.Security.Cryptography.RSACryptoServiceProvider])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Content")]
		[ValidateNotNullOrEmpty()]
		[System.String]$PEM,

		[Parameter()]
		[ValidateSet("Public", "Private")]
		[System.String]$KeyType,

		[Parameter(Mandatory = $true, ParameterSetName = "Path")]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[System.String]$Path
	)

	Begin {
	}

	Process {
        Write-Verbose -Message "Getting PEM data"

		if ($PSCmdlet.ParameterSetName -eq "Path")
		{
			$PEM = Get-Content -Path $Path -Raw
		}

		$Text = ""

		switch ($KeyType)
		{
			"Public" {
				$Text = "CERTIFICATE"
			}
			"Private" {
				$Text = "PRIVATE KEY"
				break
			}
		}

		$Header = [System.String]::Format("-----BEGIN {0}-----", $Text)
		$Footer = [System.String]::Format("-----END {0}-----", $Text)

		$StartIndex = $PEM.IndexOf($Header, [System.StringComparison]::OrdinalIgnoreCase) 
        $EndIndex = $PEM.IndexOf($Footer, [System.StringComparison]::OrdinalIgnoreCase)

        if ($StartIndex -lt 0 -or $EndIndex -lt 0)
        {
            Write-Error -Exception (New-Object -TypeName System.Security.Cryptography.CryptographicException("The key is not formatted correctly.")) -ErrorAction Stop
        }

        $StartIndex += $Header.Length
        $CharsToTake = $EndIndex - $StartIndex

        $Data = $PEM.Substring($StartIndex, $CharsToTake).Replace("\n", "").Replace("\r", "").Trim()

        Write-Verbose -Message $Data

		if ($KeyType -eq "Public")
		{
			[System.Byte[]]$KeyBytes = [System.Convert]::FromBase64String($Data)
			Write-Output -InputObject $KeyBytes
		}
		else
		{
			[System.Collections.Hashtable]$Result = Read-ASN1Content -Base64String $Data

			# This has a tag, length, and data property
			[System.Collections.Hashtable]$TopLevelSequence = $Result["0"]

			# This has numbered properties, i.e. 0, 1, 2
			[System.Collections.Hashtable]$SequenceData = $TopLevelSequence["Data"]

			[System.String]$OID = $SequenceData["1"]["Data"]["0"]["Data"]
			Write-Verbose -Message "PEM OID: $OID"

			# The number 2 index is an octet stream, it's data element is a hashtable with 1 property, "0", which is another hash table and represents a sequence,
			# This hash table has a data property whose value is another hash table, its keys are numbers 0 - 8 and each represents part of the RSA key
			$KeyParts = $SequenceData["2"]["Data"]["0"]["Data"]

            [System.Byte[]]$AlgorithmVersion = [System.Convert]::FromBase64String($KeyParts["0"]["Data"])
            
            if ([System.BitConverter]::IsLittleEndian)
            {
                [System.Array]::Reverse($AlgorithmVersion)
            }

            # Length of 256
            [System.Byte[]]$Modulus = [System.Convert]::FromBase64String($KeyParts["1"]["Data"])
            
            if ([System.BitConverter]::IsLittleEndian)
            {
                [System.Array]::Reverse($Modulus)
            }

            $Modulus = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $Modulus -DesiredLength 256 -TrimStart) -Length 256

			# Length of 3
			[System.Byte[]]$Exponent = [System.Convert]::FromBase64String($KeyParts["2"]["Data"])
            
            if ([System.BitConverter]::IsLittleEndian)
            {
                [System.Array]::Reverse($Exponent)
            }

            # This will probably come out as at least 4 bytes
            $Exponent = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $Exponent -DesiredLength 3 -TrimStart) -Length 3

			# Length of 256
			[System.Byte[]]$D = [System.Convert]::FromBase64String($KeyParts["3"]["Data"])
            
            if ([System.BitConverter]::IsLittleEndian)
            {
                [System.Array]::Reverse($D)
            }

            $D = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $D -DesiredLength 256 -TrimStart) -Length 256

			# Length of 128
			[System.Byte[]]$P = [System.Convert]::FromBase64String($KeyParts["4"]["Data"])
            
            if ([System.BitConverter]::IsLittleEndian)
            {
                [System.Array]::Reverse($P)
            }

            $P = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $P -DesiredLength 128 -TrimStart) -Length 128

			# Length of 128
			[System.Byte[]]$Q = [System.Convert]::FromBase64String($KeyParts["5"]["Data"])

            if ([System.BitConverter]::IsLittleEndian)
            {
                [System.Array]::Reverse($Q)
            }

            $Q = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $Q -DesiredLength 128 -TrimStart) -Length 128

			# Length of 128
			[System.Byte[]]$DP =[System.Convert]::FromBase64String($KeyParts["6"]["Data"])

            if ([System.BitConverter]::IsLittleEndian)
            {
                [System.Array]::Reverse($DP)
            }

            $DP = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $DP -DesiredLength 128 -TrimStart) -Length 128

			# Length of 128
			[System.Byte[]]$DQ = [System.Convert]::FromBase64String($KeyParts["7"]["Data"])

            if ([System.BitConverter]::IsLittleEndian)
            {
                [System.Array]::Reverse($DQ)
            }

            $DQ = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $DQ -DesiredLength 128 -TrimStart) -Length 128

			# Length of 128
			[System.Byte[]]$IQ = [System.Convert]::FromBase64String($KeyParts["8"]["Data"])

            if ([System.BitConverter]::IsLittleEndian)
            {
                [System.Array]::Reverse($IQ)
            }

            $IQ = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $IQ -DesiredLength 128 -TrimStart) -Length 128

			[System.Security.Cryptography.RSAParameters]$Params = New-Object -TypeName System.Security.Cryptography.RSAParameters
			$Params.Modulus = $Modulus
			$Params.Exponent = $Exponent
			$Params.D = $D
			$Params.P = $P
			$Params.Q = $Q
			$Params.DP = $DP
			$Params.DQ = $DQ
			$Params.InverseQ = $IQ

            [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = New-Object -TypeName System.Security.Cryptography.RSACryptoServiceProvider

			$RSA.ImportParameters($Params)
                
			Write-Verbose -Message "Returning RSA key"

			Write-Output -InputObject $RSA
		}
	}

	End {
	}
}