Function Get-FDTicket {
    Param(
    [string]$ID,
    [string]$Domain,
    [string]$APIKey
    )
    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
        $pair = "$($APIKey):$($APIKey)"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)
        $basicAuthValue = "Basic $base64"
        $headers = @{ Authorization = $basicAuthValue }
        $webRequestURI = "https://$($Domain).freshdesk.com/api/v2/tickets/$($ID)"
        
    }
    Process {
        #
        $webRequest = Invoke-WebRequest -uri $webRequestURI -Headers $headers -Method GET -ContentType application/json
        $webRequest = $webRequest | ConvertFrom-Json

    }
    End {
     return $webRequest
    }

}

Function Get-FDContact {
    Param(
    [string]$ID,
    [string]$Domain,
    [string]$APIKey
    )
    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
        $pair = "$($APIKey):$($APIKey)"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)
        $basicAuthValue = "Basic $base64"
        $headers = @{ Authorization = $basicAuthValue }
        $webRequestURI = "https://$($Domain).freshdesk.com/api/v2/contacts/$($ID)"
        
    }
    Process {
        #
        $webRequest = Invoke-WebRequest -uri $webRequestURI -Headers $headers -Method GET -ContentType application/json
        $webRequest = $webRequest | ConvertFrom-Json

    }
    End {
     return $webRequest
    }

}

Function Get-FDAgent {
    Param(
    [string]$ID,
    [string]$Domain,
    [string]$APIKey
    )
    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
        $pair = "$($APIKey):$($APIKey)"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)
        $basicAuthValue = "Basic $base64"
        $headers = @{ Authorization = $basicAuthValue }
        $webRequestURI = "https://$($Domain).freshdesk.com/api/v2/agents/$($ID)"
        
    }
    Process {
        #
        $webRequest = Invoke-WebRequest -uri $webRequestURI -Headers $headers -Method GET -ContentType application/json
        $webRequest = $webRequest | ConvertFrom-Json

    }
    End {
     return $webRequest
    }

}

Function Get-FDPendingTickets{
    Param(
    [string]$Domain,
    [string]$APIKey
    )
    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
        $pair = "$($APIKey):$($APIKey)"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)
        $basicAuthValue = "Basic $base64"
        $headers = @{ Authorization = $basicAuthValue }
        $webRequestURI = "https://$($Domain).freshdesk.com/api/v2/search/tickets?query=`"agent_id:null%20AND%20status:2`""
        
    }
    Process {
        #
        $webRequest = Invoke-WebRequest -uri $webRequestURI -Headers $headers -Method GET -ContentType application/json
        $webRequest = ($webRequest | ConvertFrom-Json).results

    }
    End {
     return $webRequest
    }

}

Function Get-StringHash 
{ 
    param
    (
        [String] $String,
        $HashName = "MD5"
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
    $algorithm = [System.Security.Cryptography.HashAlgorithm]::Create('MD5')
    $StringBuilder = New-Object System.Text.StringBuilder 
  
    $algorithm.ComputeHash($bytes) | 
    ForEach-Object { 
        $null = $StringBuilder.Append($_.ToString("x2")) 
    } 
  
    $StringBuilder.ToString() 
}

Function Update-FDTicket {
    Param(
    [int]$ID,
    [string]$Domain,
    [string]$APIKey,
    [string]$Type,
    [int]$GroupID,
    [ValidateSet("Open", "Pending", "Resolved","Closed")]
    [String[]]
    $Status,
    [ValidateSet("Low", "Medium", "High","Urgent")]
    [String[]]
    $Priority,
    [ValidateSet("Email", "Portal", "Phone","Chat","Mobihelp","Feedback Widget","Outbound Email")]
    [String[]]
    $Source
)
    Begin {

        switch ($status){
            "Open" {[int]$statusSelect = 2}
            "Pending" {[int]$statusSelect = 3}
            "Resolved" {[int]$statusSelect = 4}
            "Closed" {[int]$statusSelect = 5}
        }

        if($Priority){
            switch ($Priority){
                "Low" {[int]$PrioritySelect = 1}
                "Medium" {[int]$PrioritySelect = 2}
                "High" {[int]$PrioritySelect = 3}
                "Urgent" {[int]$PrioritySelect = 4}
            }
        }
        

        #Validate ticket exists
        $ticket = Get-FDTicket -ID $ID -APIKey $APIKey -Domain $Domain 
        #consider API rate limits https://developers.freshdesk.com/api/#ratelimit
        start-sleep 1 

        #stop processing if the ticket is invalid
        if(!$ticket){write-verbose "Unable to locate existing ticket" -Verbose;break}


        #init new hash
        $hashTicket = @{}

        #Update Group ID
        if($GroupID){$hashTicket.add('group_id',$GroupID)}
        
        #Update Status
        if($statusSelect){$hashTicket.add('status',$statusSelect)}
        
        #Update Priority
        if($PrioritySelect){$hashTicket.add('priority',$PrioritySelect)}
        
        #Update Source
        if($Source){$hashTicket.add('source',$Source)}  

        #build auth headers
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
        $pair = "$($APIKey):$($APIKey)"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)
        $basicAuthValue = "Basic $base64"
        $headers = @{ Authorization = $basicAuthValue }
        
        #build URL using domain/ticket ID
        $webRequestURI = "https://$($Domain).freshdesk.com/api/v2/tickets/$($ID)"
        
    }
    Process {

        try {
            Invoke-RestMethod $webRequestURI `
                -Body (ConvertTo-Json $hashTicket) `
                -ContentType "application/json" `
                -Headers $headers `
                -Method Put
            }
        catch {
            $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            $ErrResp = $streamReader.ReadToEnd() | ConvertFrom-Json
            $streamReader.Close()
        }

    }
    End {
        #consider API rate limits https://developers.freshdesk.com/api/#ratelimit
        start-sleep 2 
     return $webRequest
    }

}
