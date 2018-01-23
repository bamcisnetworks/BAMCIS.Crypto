Function ConvertFrom-RSAPrivateKeyPEM {
	[CmdletBinding()]
	[OutputType([System.Security.Cryptography.RSACryptoServiceProvider])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$PEM
	)

	Begin {

	}

	Process {
		Write-Verbose -Message $PEM

		[System.Collections.Hashtable]$Result = Read-ASN1Content -Base64String $PEM

		[System.Collections.Hashtable]$KeyParts = $Result["0"]["Data"]

		[System.Security.Cryptography.RSACryptoServiceProvider]$RSA = New-RSACryptoServiceProvider -Version $KeyParts["0"]["Data"] `
			-Modulus $KeyParts["1"]["Data"] `
			-Exponent $KeyParts["2"]["Data"] `
			-D $KeyParts["3"]["Data"] `
			-P $KeyParts["4"]["Data"] `
			-Q $KeyParts["5"]["Data"] `
			-DP $KeyParts["6"]["Data"] `
			-DQ $KeyParts["7"]["Data"] `
			-IQ $KeyParts["8"]["Data"]

		Write-Output -InputObject $RSA
	}

	End {

	}
}

Function ConvertFrom-PrivateKeyPEM {
	[CmdletBinding()]
	[OutputType([System.Security.Cryptography.RSACryptoServiceProvider])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$PEM
	)

	Begin {
	}

	Process {
		Write-Verbose -Message $PEM

		[System.Collections.Hashtable]$Result = Read-ASN1Content -Base64String $PEM
            
        # Contains data about the key as well as the key data itself

		# This has a tag, length, and data property
		[System.Collections.Hashtable]$TopLevelSequence = $Result["0"]

		# This has numbered properties, i.e. 0, 1, 2
		[System.Collections.Hashtable]$SequenceData = $TopLevelSequence["Data"]

		[System.String]$OID = $SequenceData["1"]["Data"]["0"]["Data"]
		Write-Verbose -Message "Private Key OID: $OID"

		switch ($OID)
		{
			# RSA
            "1.2.840.113549.1.1.1" {
				# The number 2 index is an octet stream, it's data element is a hashtable with 1 property, "0", which is another hash table and represents a sequence,
				# This hash table has a data property whose value is another hash table, its keys are numbers 0 - 8 and each represents part of the RSA key
				$KeyParts = $SequenceData["2"]["Data"]["0"]["Data"]

				[System.Security.Cryptography.RSACryptoServiceProvider]$RSA = New-RSACryptoServiceProvider -Version $KeyParts["0"]["Data"] `
					-Modulus $KeyParts["1"]["Data"] `
					-Exponent $KeyParts["2"]["Data"] `
					-D $KeyParts["3"]["Data"] `
					-P $KeyParts["4"]["Data"] `
					-Q $KeyParts["5"]["Data"] `
					-DP $KeyParts["6"]["Data"] `
					-DQ $KeyParts["7"]["Data"] `
					-IQ $KeyParts["8"]["Data"]

				Write-Output -InputObject $RSA

				break
			}
			default {
				Write-Error -Exception (New-Object -TypeName System.Security.Cryptography.CryptographicException("Currently the only OID supported for PUBLIC KEY type PEM content is RSA.")) -ErrorAction Stop
            }
		}
	}

	End {
	}
}

Function ConvertFrom-PublicKeyPEM {
	[CmdletBinding()]
	[OutputType([System.Security.Cryptography.RSACryptoServiceProvider])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$PEM
	)

	Begin {
	}

	Process {
		Write-Verbose -Message $PEM

		$Results = Read-ASN1Content -Base64String $PEM
                    
        # 0 is the top level sequence, it's data is another hashtable with 2 properties,
        # 0 is another sequence and 1 is a bit string with the key data
        # This 0 is a sequence that contains the OID
        $OID = $Results["0"]["Data"]["0"]["Data"]["0"]["Data"]

        Write-Verbose -Message "Public key OID: $OID"

        # 1 is a bit string, its contents are a sequence
        # The sequence has 2 elements,
        $KeyParts = $Results["0"]["Data"]["1"]["Data"]["0"]["Data"]
    					
        switch ($OID)
        {
			# RSA
            "1.2.840.113549.1.1.1" {
				[System.Security.Cryptography.RSACryptoServiceProvider]$RSA = New-RSACryptoServiceProvider `
					-Modulus $KeyParts["0"]["Data"] `
					-Exponent $KeyParts["1"]["Data"]

			    Write-Output -InputObject $RSA

                break
            }
            default {
				Write-Error -Exception (New-Object -TypeName System.Security.Cryptography.CryptographicException("Currently the only OID supported for PUBLIC KEY type PEM content is RSA.")) -ErrorAction Stop
            }
        }
	}

	End {
	}
}

Function ConvertFrom-RSAPublicKeyPEM {
	[CmdletBinding()]
	[OutputType([System.Security.Cryptography.RSACryptoServiceProvider])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$PEM
	)

	Begin {
	}

	Process {
		Write-Verbose -Message $PEM

		$Results = Read-ASN1Content -Base64String $PEM

		[System.Security.Cryptography.RSACryptoServiceProvider]$RSA = New-RSACryptoServiceProvider `
			-Modulus $Results["0"]["Data"]["0"]["Data"] `
			-Exponent $Results["0"]["Data"]["1"]["Data"]

		Write-Output -InputObject $RSA		
	}

	End {
	}
}

Function ConvertFrom-CertificatePEM {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$PEM
	)

	Begin {
	}

	Process {
		Write-Verbose -Message $PEM

		$Results = Read-ASN1Content -Base64String $PEM

		[System.Collections.Hashtable]$Cert = @{}

		$OID = $Results["0"]["Data"]["1"]["Data"]["0"]["Data"]

        Write-Verbose -Message "Certificate OID: $OID"

        $Data = $Results["0"]["Data"]["2"]["Data"]
                   
        $CertInfo1 = $Results["0"]["Data"]["0"]["Data"]["3"]["Data"]

        $Cert.Add("Info", @{})

        foreach ($Item in $CertInfo1.GetEnumerator())
        {
			$TempOID = $Item.Value["Data"]["0"]["Data"]["0"]["Data"]
            $TempStr = $Item.Value["Data"]["0"]["Data"]["1"]["Data"]
            $Cert["Info"].Add($TempOID, $TempStr)
        }

        $ExpiryInfo = $Results["0"]["Data"]["0"]["Data"]["4"]["Data"]

        [System.UInt64]$NET = $ExpiryInfo["0"]["Data"]

        [System.DateTime]$Epoch = New-Object -TypeName System.DateTime(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
        $Cert.Add("Issued", $Epoch.AddMilliseconds($NET))


        $NLT = $ExpiryInfo["1"]["Data"]
        $Cert.Add("Expires", $Epoch.AddMilliseconds($NLT))

        Write-Output -InputObject $Cert
	}

	End {
	}
}

Function ConvertFrom-PEM {
	<#
		
	#>
	[CmdletBinding()]
	[OutputType([System.Byte[]], [System.Security.Cryptography.RSACryptoServiceProvider])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Content")]
		[ValidateNotNullOrEmpty()]
		[System.String]$PEM,

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
		if ($PSCmdlet.ParameterSetName -eq "Path")
		{
            Write-Verbose -Message "Getting PEM data from $Path."

			$PEM = Get-Content -Path $Path -Raw
		}

        # Remove all new line encoding
        $PEM = $PEM.Replace("\n", "").Replace("\r", "").Replace("`n", "").Replace("`r", "")

        $Public = "(CERTIFICATE|PUBLIC KEY|RSA PUBLIC KEY)"
        $Private = "(RSA PRIVATE KEY|PRIVATE KEY)"

        $Header = "-----BEGIN {0}-----"
		$Footer = "-----END {0}-----"


        # These have 2 capture groups, the header key type and the body
        $PublicRegex = New-Object -TypeName System.Text.RegularExpressions.Regex("^$([System.String]::Format($Header, $Public))\s*(.*?)\s*$([System.String]::Format($Footer, $Public))$", [System.Text.RegularExpressions.RegexOptions]::Singleline)
        $PrivateRegex = New-Object -TypeName System.Text.RegularExpressions.Regex("^$([System.String]::Format($Header, $Private))\s*(.*?)\s*$([System.String]::Format($Footer, $Private))$", [System.Text.RegularExpressions.RegexOptions]::Singleline)

        [System.Text.RegularExpressions.Match]$PublicMatch = $PublicRegex.Match($PEM)
        [System.Text.RegularExpressions.Match]$PrivateMatch = $PrivateRegex.Match($PEM)

        # Some type of public key or certificate
        if ($PublicMatch.Success)
        {
            $KeyType = $PublicMatch.Groups[1].Value
            $Data = $PublicMatch.Groups[2].Value

            Write-Verbose -Message $KeyType

            switch ($KeyType)
            {
                "CERTIFICATE" {
					$Cert = ConvertFrom-CertificatePEM -PEM $Data
                   
					Write-Output -InputObject $Cert
                    
                    break
                }
                "PUBLIC KEY" {
                    [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = ConvertFrom-PublicKeyPEM -PEM $Data
					
					Write-Output -InputObject $RSA

                    break
                }
                "RSA PUBLIC KEY" {
					[System.Security.Cryptography.RSACryptoServiceProvider]$RSA = ConvertFrom-RSAPublicKeyPEM -PEM $Data

			        Write-Output -InputObject $RSA

                    break
                }
            }

        }
        # Some type of private key
        elseif ($PrivateMatch.Success)
        {
            $KeyType = $PrivateMatch.Groups[1].Value
            $Data = $PrivateMatch.Groups[2].Value

            Write-Verbose -Message $KeyType
            
            switch ($KeyType) 
			{
                "RSA PRIVATE KEY" {
                    [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = ConvertFrom-RSAPrivateKeyPEM -PEM $Data

					Write-Output -InputObject $RSA

                    break
                }
                "PRIVATE KEY" {
                    [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = ConvertFrom-PrivateKeyPEM -PEM $Data

					Write-Output -InputObject $RSA

                    break
                }
            }
        }
        # Unknown type
        else
        {
             Write-Error -Exception (New-Object -TypeName System.Security.Cryptography.CryptographicException("The presented PEM data is of an unknown type.")) -ErrorAction Stop
        }
	}

	End {
	}
}

Function New-RSACryptoServiceProvider {
	[CmdletBinding(DefaultParameterSetName = "Public")]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Modulus,

		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Exponent,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$Version,

		[Parameter(Mandatory = $true, ParameterSetName = "Private")]
		[ValidateNotNullOrEmpty()]
		[System.String]$D,

		[Parameter(Mandatory = $true, ParameterSetName = "Private")]
		[ValidateNotNullOrEmpty()]
		[System.String]$P,

		[Parameter(Mandatory = $true, ParameterSetName = "Private")]
		[ValidateNotNullOrEmpty()]
		[System.String]$Q,

		[Parameter(Mandatory = $true, ParameterSetName = "Private")]
		[ValidateNotNullOrEmpty()]
		[System.String]$DP,

		[Parameter(Mandatory = $true, ParameterSetName = "Private")]
		[ValidateNotNullOrEmpty()]
		[System.String]$DQ,

		[Parameter(Mandatory = $true, ParameterSetName = "Private")]
		[ValidateNotNullOrEmpty()]
		[System.String]$IQ
	)

	Begin {
	}

	Process {
		if (-not [System.String]::IsNullOrEmpty($Version))
		{
			[System.Byte[]]$VersionBytes = [System.Convert]::FromBase64String($Version)
            
			$VersionBytes = Set-ByteArrayPadding -Length 4 -InputObject (Invoke-ByteArrayTrim -InputObject $VersionBytes -DesiredLength 4 -TrimStart)

			# Reverse here because we want to use ToUInt32 to convert it
			if ([System.BitConverter]::IsLittleEndian)
			{
				[System.Array]::Reverse($VersionBytes)
			}

			$VersionNumber = [System.BitConverter]::ToUInt32($VersionBytes, 0)

			Write-Verbose -Message "Algorithm version: $VersionNumber."
		}

        # Length of 256
        [System.Byte[]]$ModulusBytes = [System.Convert]::FromBase64String($Modulus)

		# Trim from the start of a big endian array, then set the padding on the left
		# in case the array was actually less than the desired length
        $ModulusBytes = Set-ByteArrayPadding -Length 256 -InputObject (Invoke-ByteArrayTrim -InputObject $ModulusBytes -DesiredLength 256 -TrimStart)

		# Length of 3
		[System.Byte[]]$ExponentBytes = [System.Convert]::FromBase64String($Exponent)
          
		# This will probably come out as at least 4 bytes
		# Trim from the start of a big endian array, then set the padding on the left
		# in case the array was actually less than the desired length
        $ExponentBytes = Set-ByteArrayPadding -Length 3 -InputObject (Invoke-ByteArrayTrim -InputObject $ExponentBytes -DesiredLength 3 -TrimStart)

		# Create the params here to simplify processing for the
		# private key components
		[System.Security.Cryptography.RSAParameters]$Params = New-Object -TypeName System.Security.Cryptography.RSAParameters
		$Params.Modulus = $ModulusBytes
		$Params.Exponent = $ExponentBytes

		if ($PSCmdlet.ParameterSetName -eq "Private")
		{
			# Length of 256
			[System.Byte[]]$DBytes = [System.Convert]::FromBase64String($D)        
			# Trim from the start of a big endian array, then set the padding on the left
			# in case the array was actually less than the desired length
			$DBytes = Set-ByteArrayPadding -Length 256 -InputObject (Invoke-ByteArrayTrim -InputObject $DBytes -DesiredLength 256 -TrimStart)

			# Length of 128
			[System.Byte[]]$PBytes = [System.Convert]::FromBase64String($P)
			# Trim from the start of a big endian array, then set the padding on the left
			# in case the array was actually less than the desired length
			$PBytes = Set-ByteArrayPadding -Length 128 -InputObject (Invoke-ByteArrayTrim -InputObject $PBytes -DesiredLength 128 -TrimStart)

			# Length of 128
			[System.Byte[]]$QBytes = [System.Convert]::FromBase64String($Q)
			$QBytes = Set-ByteArrayPadding -Length 128 -InputObject (Invoke-ByteArrayTrim -InputObject $QBytes -DesiredLength 128 -TrimStart)

			# Length of 128
			[System.Byte[]]$DPBytes =[System.Convert]::FromBase64String($DP)
			$DPBytes = Set-ByteArrayPadding -Length 128 -InputObject (Invoke-ByteArrayTrim -InputObject $DPBytes -DesiredLength 128 -TrimStart) 

			# Length of 128
			[System.Byte[]]$DQBytes = [System.Convert]::FromBase64String($DQ)
			$DQBytes = Set-ByteArrayPadding -Length 128 -InputObject (Invoke-ByteArrayTrim -InputObject $DQBytes -DesiredLength 128 -TrimStart)

			# Length of 128
			[System.Byte[]]$IQBytes = [System.Convert]::FromBase64String($IQ)
			$IQBytes = Set-ByteArrayPadding -Length 128 -InputObject (Invoke-ByteArrayTrim -InputObject $IQBytes -DesiredLength 128 -TrimStart)

			# RSA Params need to be in Big Endian format
			$Params.D = $DBytes
			$Params.P = $PBytes
			$Params.Q = $QBytes
			$Params.DP = $DPBytes
			$Params.DQ = $DQBytes
			$Params.InverseQ = $IQBytes
		}
		
		[System.Security.Cryptography.RSACryptoServiceProvider]$RSA = New-Object -TypeName System.Security.Cryptography.RSACryptoServiceProvider

		$RSA.ImportParameters($Params)
                
		Write-Output -InputObject $RSA
	}

	End {
	}
}
