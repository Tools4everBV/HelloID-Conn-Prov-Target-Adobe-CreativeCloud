#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json

$success = $False
$auditLogs = [Collections.Generic.List[PSCustomObject]]@()
#endregion Initialize default properties

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

function New-Jwt {
    <#
    .SYNOPSIS
    Creates a JWT (JSON Web Token).
     
    .DESCRIPTION
    Creates signed JWT given a signing certificate and claims in JSON.
     
    .PARAMETER Payload
    Specifies the claim to sign in JSON. Mandatory.
     
    .PARAMETER Cert
    Specifies the signing certificate. Mandatory.
     
    .PARAMETER Header
    Specifies a JWT header. Optional. Defaults to '{"alg":"RS256","typ":"JWT"}'.
     
    .INPUTS
    You can pipe a string object (the JSON payload) to New-Jwt.
     
    .OUTPUTS
    System.String. New-Jwt returns a string with the signed JWT.
     
    .EXAMPLE
    PS Variable:\> $cert = (Get-ChildItem Cert:\CurrentUser\My)[1]
     
    PS Variable:\> New-Jwt -Cert $cert -PayloadJson '{"token1":"value1","token2":"value2"}'
    eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbjEiOiJ2YWx1ZTEiLCJ0b2tlbjIiOiJ2YWx1ZTIifQ.Kd12ryF7Uuk9Y1UWsqdSk6cXNoYZBf9GBoqcEz7R5e4ve1Kyo0WmSr-q4XEjabcbaG0hHJyNGhLDMq6BaIm-hu8ehKgDkvLXPCh15j9AzabQB4vuvSXSWV3MQO7v4Ysm7_sGJQjrmpiwRoufFePcurc94anLNk0GNkTWwG59wY4rHaaHnMXx192KnJojwMR8mK-0_Q6TJ3bK8lTrQqqavnCW9vrKoWoXkqZD_4Qhv2T6vZF7sPkUrgsytgY21xABQuyFrrNLOI1g-EdBa7n1vIyeopM4n6_Uk-ttZp-U9wpi1cgg2pRIWYV5ZT0AwZwy0QyPPx8zjh7EVRpgAKXDAg
     
    .EXAMPLE
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("/mnt/c/PS/JWT/jwt.pfx","jwt")
     
    $now = (Get-Date).ToUniversalTime()
    $createDate = [Math]::Floor([decimal](Get-Date($now) -UFormat "%s"))
    $expiryDate = [Math]::Floor([decimal](Get-Date($now.AddHours(1)) -UFormat "%s"))
    $rawclaims = [Ordered]@{
        iss = "examplecom:apikey:uaqCinPt2Enb"
        iat = $createDate
        exp = $expiryDate
    } | ConvertTo-Json
     
    $jwt = New-Jwt -PayloadJson $rawclaims -Cert $cert
     
    $apiendpoint = "https://api.example.com/api/1.0/systems"
     
    $splat = @{
        Method="GET"
        Uri=$apiendpoint
        ContentType="application/json"
        Headers = @{authorization="bearer $jwt"}
    }
     
    Invoke-WebRequest @splat
     
    .LINK
    https://github.com/SP3269/posh-jwt
    .LINK
    https://jwt.io/
     
    #>
    
    
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$false)][string]$Header = '{"alg":"RS256","typ":"JWT"}',
            [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$PayloadJson,
            [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
        )
    
        Write-Verbose "Payload to sign: $PayloadJson"
        Write-Verbose "Signing certificate: $($Cert.Subject)"
    
        try { ConvertFrom-Json -InputObject $payloadJson -ErrorAction Stop | Out-Null } # Validating that the parameter is actually JSON - if not, generate breaking error
        catch { throw "The supplied JWT payload is not JSON: $payloadJson" }
    
        $encodedHeader = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Header)) -replace '\+','-' -replace '/','_' -replace '='
        $encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PayloadJson)) -replace '\+','-' -replace '/','_' -replace '='
    
        $jwt = $encodedHeader + '.' + $encodedPayload # The first part of the JWT
    
        $toSign = [System.Text.Encoding]::UTF8.GetBytes($jwt)
        
        $rsa = $Cert.PrivateKey
        if ($null -eq $rsa) { # Requiring the private key to be present; else cannot sign!
            throw "There's no private key in the supplied certificate - cannot sign" 
        }
        else {
            # Overloads tested with RSACryptoServiceProvider, RSACng, RSAOpenSsl
            try { $sig = [Convert]::ToBase64String($rsa.SignData($toSign,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) -replace '\+','-' -replace '/','_' -replace '=' }
            catch { throw "Signing with SHA256 and Pkcs1 padding failed using private key $rsa" }
        }
    
        $jwt = $jwt + '.' + $sig
    
        return $jwt 
}

$jsonPayload = @{ 
    'exp' = ([DateTimeOffset]::Now.ToUnixTimeSeconds() + 60*60) #JWT expires in one hour
    'iss' = $config.orgId;
    "sub" = $config.technicalAccountID;
    'https://ims-na1.adobelogin.com/s/ent_user_sdk' = $true;
    'aud' = 'https://ims-na1.adobelogin.com/c/' + $config.clientId;
}

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($config.certPath);

$jwt = New-Jwt -PayloadJson ($jsonPayload | ConvertTo-Json) -Cert $cert;

$headers = @{
    'Content-Type'  = 'application/x-www-form-urlencoded';
    'Cache-Control' = "no-cache";
};

$body = 'client_id=' + $config.clientId;
$body += '&client_secret=' + $config.clientSecret;
$body += '&jwt_token=' + $jwt;

#Get Adobe token
Write-Verbose -Verbose "Obtaining token from Adobe..."

$uri = 'https://ims-na1.adobelogin.com/ims/exchange/jwt';
$response = Invoke-RestMethod $uri -Method POST -Headers $headers -Body $body;

$headers = @{
    'Accept'  = 'application/json';
    'Content-Type'  = 'application/json';
    'Cache-Control' = "no-cache";    
    'x-api-key' = $config.clientId;
    'Authorization' = 'Bearer ' + $response.access_token;
};

#Set the user attributes
$user = @(@{
    'user' = $p.emailAddress;
    'requestID' = 'HelloIDCreate_' + $p.externalId;
    'do' = @(@{
        'addAdobeID' = @{
            'email' = $p.emailAddress;
            'country' = 'US';
            'firstname' = $p.firstName;
            'lastname' = $p.lastName;
            'option' = 'ignoreIfAlreadyExists';
        }
    },
    @{
      'add' = @{
        'group' = @( 'License - CCE' )
      }
    })
});

try {
    $uri = 'https://usermanagement.adobe.io/v2/usermanagement/action/' + $config.orgId;
    $response = Invoke-RestMethod $uri -Method POST -Headers $headers -Body ("[" + ($user | ConvertTo-Json -Depth 10) + "]");

    $auditLogs.Add([PSCustomObject]@{
        Action = "CreateAccount"
        Message = "Created account for Email $($p.emailAddress)"
        IsError = $false;
    });
    $success = $True
}
catch
{
    $auditLogs.Add([PSCustomObject]@{
                Action = "CreateAccount"
                Message = "Account failed to create:  $_"
                IsError = $True
            });
	Write-Error $_;
}

#region Build up result
$result = [PSCustomObject]@{
    Success = $success
    AccountReference = $aRef
    AuditLogs = $auditLogs;
    Account = $newAccount
    PreviousAccount = $previousAccount

    # Optionally return data for use in other systems
    ExportData = [PSCustomObject]@{
        Email = $p.emailAddress
    }
}

Write-Output ($result | ConvertTo-Json -Depth 10)
#endregion build up result