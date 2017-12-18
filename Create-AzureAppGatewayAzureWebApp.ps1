# Azure PowerShell Version
Get-Module -ListAvailable -Name Azure -Refresh

# Sign in to your Azure account
$subscriptionId = 'YOUR AZURE SUBSCRIPTION ID'
Login-AzureRmAccount
# Select a subscription
Set-AzureRmContext -SubscriptionId $subscriptionId

# Solution Variable Declariations
$location = 'Canada Central' # Get-AzureRmLocation | Format-Table -AutoSize
$baseTags = @{Envrionment="dev";Project="App solution demo";Department="Marketing";Owner="John Doe";Purpose="Application";Version="1.0";}

##################
# Resource Group #
##################
$rgName = 'RK2AppDEMO'
New-AzureRmResourceGroup -Name $rgName -Location $location
$resourceInfo = Find-AzureRmResource -ResourceNameEquals $rgName -ResourceGroupNameEquals $rgName 
Set-AzureRmResource -Tags $baseTags -ResourceName $rgName -ResourceType $azureResourceInfo.ResourceType -ResourceGroupName $rgName

$appServicePlanName = 'RK2AppDemo-AppServicePlan'
New-AzureRmAppServicePlan -Name $appServicePlanName -Location $location -Tier Standard -ResourceGroupName $rgName

$webAppName = "RK2AppDemo-WebApp"
New-AzureRmWebApp -Name $webAppName -AppServicePlan $appServicePlanName -Location $location -ResourceGroupName $rgName -Verbose
$webapp = Get-AzureRmWebApp -ResourceGroupName $rgName -Name $webAppName

# Azure SQL Server and Database #
$sqlServerName = 'rk2appdemo-sqldbserver'
$sqlAdminUsername = 'sqladmin'
$dbName = "rk2AppDemo-DB"
$dbPassword = "P@ssword1"
$pword = ConvertTo-SecureString -String $dbPassword -AsPlainText -Force
$sqlAdminCredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $sqlAdminUsername, $pword
New-AzureRmSqlServer -ServerName $sqlServerName -SqlAdministratorCredentials $sqlAdminCredential -AssignIdentity `
    -Tags $baseTags -Location $location -ResourceGroupName $rgName -Verbose
New-AzureRmSqlDatabase -ServerName $sqlServerName -DatabaseName $dbName -Edition Basic -ResourceGroupName $rgName -Tags $baseTags
New-AzureRmSqlServerFirewallRule -ServerName $sqlServerName -AllowAllAzureIPs `
   -ResourceGroupName $rgName -Verbose
Get-AzureRmSqlServerFirewallRule -ServerName $sqlServerName -ResourceGroupName $rgName
  
# Virtual Network #
$vnetName = 'RK2appdemo-vnet'
$addressPrefix = "10.1.0.0/16"
$wafSubnet = New-AzureRmVirtualNetworkSubnetConfig -Name wafSubnet -AddressPrefix "10.1.0.0/24"
$webSubnet = New-AzureRmVirtualNetworkSubnetConfig -Name webSubnet -AddressPrefix "10.1.1.0/24"
$dataSubnet = New-AzureRmVirtualNetworkSubnetConfig -Name dataSubnet -AddressPrefix "10.1.4.0/24"
$batchSubnet = New-AzureRmVirtualNetworkSubnetConfig -Name batchSubnet -AddressPrefix "10.1.3.0/24"
$gatewaySubnet = New-AzureRmVirtualNetworkSubnetConfig -Name 'GatewaySubnet' -AddressPrefix "10.1.5.0/24"
$vnet = New-AzureRmVirtualNetwork -Name $vnetName -AddressPrefix $addressPrefix -Subnet $wafSubnet,$webSubnet,$dataSubnet,$batchSubnet,$gatewaySubnet -Location $location -ResourceGroupName $rgName -Verbose
$wafSubnet = $vnet.Subnets[0]

#####################################################################################################################################################
# Manually prepare SSL certificate (.pfx) and public authentication certificate (.cer)
# Prerequisite for App Gateway
#####################################################################################################################################################
$AuthenticationCertificateFile = 'C:\temp\azurewebsites.cer' #From Azure App Service Web App created by default
$SSLCertificateFile = 'C:\temp\appservicecertificate.pfx' #From SSL certificate the application owner creates
#$SSLCertificateFilePassword = $pword = ConvertTo-SecureString -String "<GETPasswordFromCertFile>" -AsPlainText -Force

############################################################################################################################################################################
# App Gateway
# Refererences: #https://blog.brooksjc.com/2017/10/22/end-to-end-ssl-with-application-gateway-and-azure-web-apps-102017/
# https://docs.microsoft.com/en-us/azure/application-gateway/application-gateway-configure-redirect-powershell#http-to-https-redirect-on-an-existing-application-gateway
# https://stackoverflow.com/questions/46353542/modify-azure-appservice-ipsecurity-during-release-from-vsts
############################################################################################################################################################################
$appGatewayName = "RK2webappdemo-appgateway"
$appGatewaypublicIPName = "appGatewaypublicIP"
$publicip = New-AzureRmPublicIpAddress -ResourceGroupName $rgName -name $appGatewaypublicIPName -location $location -AllocationMethod Dynamic

# Create a new IP configuration & set to VNET subnet
$gipconfig = New-AzureRmApplicationGatewayIPConfiguration -Name gatewayIPConfig -Subnet $wafSubnet
# Create a backend pool with the hostname of the web app
$pool = New-AzureRmApplicationGatewayBackendAddressPool -Name appGatewayBackendPool -BackendFqdns $webapp.HostNames
# Define the status codes to match for the probe
$match = New-AzureRmApplicationGatewayProbeHealthResponseMatch -StatusCode 200-399
# Create a probe with the PickHostNameFromBackendHttpSettings switch for web apps
$probeconfig = New-AzureRmApplicationGatewayProbeConfig -name webappprobe -Protocol Https -Path / -Interval 30 -Timeout 120 -UnhealthyThreshold 3 -PickHostNameFromBackendHttpSettings -Match $match
# Define the backend http settings
$authcert = New-AzureRmApplicationGatewayAuthenticationCertificate -Name 'appserviceCert' -CertificateFile $AuthenticationCertificateFile
$poolSetting = New-AzureRmApplicationGatewayBackendHttpSettings -Name appGatewayBackendHttpSettings -Port 443 -Protocol Https -CookieBasedAffinity Disabled -RequestTimeout 120 -PickHostNameFromBackendAddress -Probe $probeconfig -AuthenticationCertificates $authcert
# Create a new front-end port
$fpHttp = New-AzureRmApplicationGatewayFrontendPort -Name frontEndPortHttp01 -Port 80
$fpHttps = New-AzureRmApplicationGatewayFrontendPort -Name frontEndPortHttps01 -Port 443
# Create a new front end IP configuration
$fipconfig = New-AzureRmApplicationGatewayFrontendIPConfig -Name fipconfig01 -PublicIPAddress $publicip
# Create a new HTTP and HTTPS listeners
$httpListener = New-AzureRmApplicationGatewayHttpListener -Name httplistener01 -Protocol Http -FrontendIPConfiguration $fipconfig -FrontendPort $fpHttp -HostName myapp.com
# Set SSL Cert to http listener
$cert = New-AzureRmApplicationGatewaySSLCertificate -Name sslert -CertificateFile $SSLCertificateFile -Password $SSLCertificateFilePassword
$httpsListener = New-AzureRmApplicationGatewayHttpListener -Name httpslistener01 -Protocol Https -FrontendIPConfiguration $fipconfig -FrontendPort $fpHttps -HostName myapp.com -SslCertificate $cert
# redirect http to https
$redirectconfig = New-AzureRmApplicationGatewayRedirectConfiguration -Name redirectHttptoHttps -RedirectType Permanent -TargetListener $httpslistener -IncludePath $true -IncludeQueryString $true

# Rules http, https
$ruleHttps01 = New-AzureRmApplicationGatewayRequestRoutingRule -Name ruleHttps -RuleType Basic -BackendHttpSettings $poolSetting -HttpListener $httpsListener -BackendAddressPool $pool
$ruleHttp01 = New-AzureRmApplicationGatewayRequestRoutingRule -Name ruleHttp -RuleType Basic -HttpListener $httpListener -RedirectConfiguration $redirectconfig

$SSLPolicy = New-AzureRmApplicationGatewaySSLPolicy -MinProtocolVersion TLSv1_2 -CipherSuite "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256" -PolicyType Custom

# Define the application gateway SKU to use
$sku = New-AzureRmApplicationGatewaySku -Name WAF_Medium -Tier WAF -Capacity 1
$wafConfig = New-AzureRmApplicationGatewayWebApplicationFirewallConfiguration -Enabled $true -FirewallMode Prevention -RuleSetType OWASP

# Provision the application gateway
$appgw = New-AzureRmApplicationGateway -Name $appGatewayName -BackendAddressPools $pool `
    -BackendHttpSettingsCollection $poolSetting -Probes $probeconfig -FrontendIpConfigurations $fipconfig  `
    -GatewayIpConfigurations $gipconfig -FrontendPorts $fpHttp, $fpHttps `
    -HttpListeners $httpListener, $httpsListener -SslCertificates $cert `
    -RequestRoutingRules $ruleHttp01, $ruleHttps01 `
    -Sku $sku -AuthenticationCertificates $authcert -SslPolicy $SSLPolicy -WebApplicationFirewallConfiguration $wafConfig -RedirectConfigurations $redirectconfig `
    -ResourceGroupName $rgName -Location $location

########################################################
# Azure App Service IP Restriction to only App Gateway #
########################################################
# Reference: https://stackoverflow.com/questions/46353542/modify-azure-appservice-ipsecurity-during-release-from-vsts

$r = Get-AzureRmResource -ResourceGroupName $rgName -ResourceType "Microsoft.Web/sites/config" -ResourceName "$webAppName/web"  -ApiVersion 2016-08-01
$publicip = Get-AzureRmPublicIpAddress -Name $appGatewaypublicIPName -ResourceGroupName $rgName
$p = $r.Properties
$p.ipSecurityRestrictions = @()
$restriction = @{}
$restriction.Add("ipAddress",$publicip.IpAddress)
$restriction.Add("subnetMask","255.255.255.255")
$p.ipSecurityRestrictions += $restriction
Set-AzureRmResource -ResourceType Microsoft.Web/sites/config -ResourceName $webAppName/web -ApiVersion 2016-08-01 -PropertyObject $p -ResourceGroupName $rgName -Force


# Manually Verify - azureportal.com
