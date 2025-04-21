/*
 * Darkweb Access Detection Rules
 * 
 * This Yara ruleset contains signatures for detecting darkweb access attempts
 * and references to darkweb content.
 */

rule Darkweb_Tor_Access
{
    meta:
        description = "Detects access to Tor network and .onion domains"
        severity = "MEDIUM"
        confidence = 75
    
    strings:
        $domain1 = ".onion" nocase
        $domain2 = ".onion/" nocase
        $domain3 = ".onion:" nocase
        
        $port1 = ":9050" // Default Tor SOCKS port
        $port2 = ":9051" // Default Tor control port
        $port3 = ":9150" // Default Tor Browser SOCKS port
        
        $browser1 = "Tor Browser" nocase
        $browser2 = "Tor bundle" nocase
        $browser3 = "HTTPHEADER User-Agent: Tor" nocase
        
        $protocol1 = "tor protocol" nocase
        $protocol2 = "tor network" nocase
        $protocol3 = "onion routing" nocase
    
    condition:
        any of them
}

rule Darkweb_I2P_Access
{
    meta:
        description = "Detects strong indicators of access to the I2P network"
        severity = "MEDIUM"
        confidence = 85

    strings:
        $domain1 = ".i2p/" nocase
        $domain2 = ".i2p:" nocase
        $domain3 = ".i2p " nocase
        $domain4 = ".i2p\r\n" nocase
        $domain5 = ".i2p\n" nocase
        $i2p_ua = "User-Agent: I2P" nocase
        $proxy_port = ":4444"
        $mention1 = "i2p network" nocase
        $mention2 = "i2p router" nocase
        $mention3 = "Invisible Internet Project" nocase

    condition:
        (any of ($domain*) and any of ($mention*)) or
        ($proxy_port and any of ($mention*)) or
        ($i2p_ua and any of ($mention*))
}

rule Darkweb_Marketplace_References
{
    meta:
        description = "Detects references to darkweb marketplaces and services"
        severity = "HIGH"
        confidence = 80
    
    strings:
        // Historical and current darknet markets
        $market1 = "Silk Road" nocase
        $market2 = "AlphaBay" nocase
        $market3 = "Dream Market" nocase
        $market4 = "Hansa Market" nocase
        $market5 = "Empire Market" nocase
        $market6 = "DarkMarket" nocase
        $market7 = "White House Market" nocase
        $market8 = "ToRReZ" nocase
        $market9 = "Hydra Market" nocase
        $market10 = "Monopoly Market" nocase
        $market11 = "Dark0de" nocase
        $market12 = "Cannazon" nocase
        $market13 = "CannaHome" nocase
        $market14 = "Spurdomarket" nocase
        $market15 = "Televend" nocase
        
        // General terms
        $term1 = "dark web" nocase
        $term2 = "darknet" nocase
        $term3 = "hidden service" nocase
        $term4 = "hidden marketplace" nocase
        $term5 = "anonymous marketplace" nocase
    
    condition:
        any of ($market*) or any of ($term*)
}

rule Darkweb_Illegal_Content
{
    meta:
        description = "Detects references to illegal content typically found on darkweb"
        severity = "HIGH"
        confidence = 85
    
    strings:
        $content1 = "illegal drugs" nocase
        $content2 = "narcotics" nocase
        $content3 = "buy cocaine" nocase
        $content4 = "buy heroin" nocase
        $content5 = "buy mdma" nocase
        $content6 = "buy lsd" nocase
        $content7 = "counterfeit" nocase
        $content8 = "fake passport" nocase
        $content9 = "fake id" nocase
        $content10 = "stolen credit" nocase
        $content11 = "stolen credentials" nocase
        $content12 = "hacked account" nocase
        $content13 = "hire hitman" nocase
        $content14 = "murder for hire" nocase
        $content15 = "assassin service" nocase
        $content16 = "illegal weapon" nocase
        $content17 = "buy weapon" nocase
        $content18 = "human trafficking" nocase
        
        $currency1 = "bitcoin" nocase
        $currency2 = "monero" nocase
        $currency3 = "cryptocurrency" nocase
    
    condition:
        1 of ($content*) and 1 of ($currency*)
}
