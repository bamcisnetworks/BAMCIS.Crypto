Function ConvertFrom-RSAPrivateKeyPEM {
	[CmdletBinding()]
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

	End {

	}
}

Function ConvertFrom-PrivateKeyPEM {
	[CmdletBinding()]
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
            Write-Verbose -Message $Data

            switch ($KeyType)
            {
                "CERTIFICATE" {
                    $Cert = @{}
                    $Results = Read-ASN1Content -Base64String $Data

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
                    Write-Host $NET

                    [System.DateTime]$Epoch = New-Object -TypeName System.DateTime(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
                    $Cert.Add("Issued", $Epoch.AddMilliseconds($NET))


                    $NLT = $ExpiryInfo["1"]["Data"]
                    $Cert.Add("Expires", $Epoch.AddMilliseconds($NLT))

                    Write-Host (ConvertTo-Json -InputObject $Cert)

                    break
                }
                "PUBLIC KEY" {
                    $Results = Read-ASN1Content -Base64String $Data
                    
                    # 0 is the top level sequence, it's data is another hashtable with 2 properties,
                    # 0 is another sequence and 1 is a bit string with the key data
                    # This 0 is a sequence that contains the OID
                    $OID = $Results["0"]["Data"]["0"]["Data"]["0"]["Data"]

                    Write-Verbose -Message "Public key OID: $OID"

                    # 1 is a bit string, its contents are a sequence
                    # The sequence has 2 elements,
                    $KeyParts = $Results["0"]["Data"]["1"]
    
                     # Length of 256
                    [System.Byte[]]$Modulus = [System.Convert]::FromBase64String($KeyParts["Data"]["0"]["Data"]["0"]["Data"])
            
                    if ([System.BitConverter]::IsLittleEndian)
                    {
                        [System.Array]::Reverse($Modulus)
                    }

                    $Modulus = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $Modulus -DesiredLength 256 -TrimStart) -Length 256

			        # Length of 3
			        [System.Byte[]]$Exponent = [System.Convert]::FromBase64String($KeyParts["Data"]["0"]["Data"]["1"]["Data"])
            
                    if ([System.BitConverter]::IsLittleEndian)
                    {
                        [System.Array]::Reverse($Exponent)
                    }

                    # This will probably come out as at least 4 bytes
                    $Exponent = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $Exponent -DesiredLength 3 -TrimStart) -Length 3

                    switch ($OID)
                    {
                        # RSA
                        "1.2.840.113549.1.1.1" {
                            [System.Security.Cryptography.RSAParameters]$Params = New-Object -TypeName System.Security.Cryptography.RSAParameters
			                $Params.Modulus = $Modulus
			                $Params.Exponent = $Exponent

                            [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = New-Object -TypeName System.Security.Cryptography.RSACryptoServiceProvider

			                $RSA.ImportParameters($Params)
                
			                Write-Verbose -Message "Returning RSA Public key"

			                Write-Output -InputObject $RSA

                            break
                        }
                        default {
                            Write-Error -Exception (New-Object -TypeName System.Security.Cryptography.CryptographicException("Currently the only OID supported for PUBLIC KEY type PEM content is RSA.")) -ErrorAction Stop
                        }
                    }

                    break
                }
                "RSA PUBLIC KEY" {
                    $Results = Read-ASN1Content -Base64String $Data

                    [System.Byte[]]$Modulus = [System.Convert]::FromBase64String($Results["0"]["Data"]["0"]["Data"])

                    if ([System.BitConverter]::IsLittleEndian)
                    {
                        [System.Array]::Reverse($Modulus)
                    }

                    $Modulus = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $Modulus -DesiredLength 256 -TrimStart) -Length 256

			        # Length of 3
			        [System.Byte[]]$Exponent = [System.Convert]::FromBase64String($Results["0"]["Data"]["1"]["Data"])
            
                    if ([System.BitConverter]::IsLittleEndian)
                    {
                        [System.Array]::Reverse($Exponent)
                    }

                    # This will probably come out as at least 4 bytes
                    $Exponent = Set-ByteArrayPadding -InputObject (Invoke-ByteArrayTrim -InputObject $Exponent -DesiredLength 3 -TrimStart) -Length 3

                    [System.Security.Cryptography.RSAParameters]$Params = New-Object -TypeName System.Security.Cryptography.RSAParameters
			        $Params.Modulus = $Modulus
			        $Params.Exponent = $Exponent

                    [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = New-Object -TypeName System.Security.Cryptography.RSACryptoServiceProvider

			        $RSA.ImportParameters($Params)
                
			        Write-Verbose -Message "Returning RSA Public key"

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
                    Write-Output -InputObject (ConvertFrom-RSAPrivateKeyPEM -PEM $Data)
                    break
                }
                "PRIVATE KEY" {
                    Write-Output -InputObject (ConvertFrom-PrivateKeyPEM -PEM $Data)
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