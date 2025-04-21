/*
 * DoS/DDoS Attack Detection Rules
 * 
 * This Yara ruleset contains signatures for detecting DoS and DDoS attacks.
 */

rule DoS_Tool_References
{
    meta:
        description = "Detects references to DoS/DDoS tools in traffic"
        severity = "HIGH"
        confidence = 85
    
    strings:
        $tool1 = "LOIC" nocase fullword
        $tool2 = "HOIC" nocase fullword
        $tool3 = "Slowloris" nocase
        $tool4 = "R-U-Dead-Yet" nocase
        $tool5 = "RUDY" nocase fullword
        $tool6 = "Tor's Hammer" nocase
        $tool7 = "PyLoris" nocase
        $tool8 = "Slowhttptest" nocase
        $tool9 = "GoldenEye" nocase
        $tool10 = "DDoSIM" nocase
        $tool11 = "Hulk" nocase fullword
        $tool12 = "HTTPDosTool" nocase
        $tool13 = "THC-SSL-DoS" nocase
        $tool14 = "Torshammer" nocase
        
        $type1 = "SYN flood" nocase
        $type2 = "ACK flood" nocase
        $type3 = "UDP flood" nocase
        $type4 = "ICMP flood" nocase
        $type5 = "HTTP flood" nocase
        $type6 = "DNS amplification" nocase
        $type7 = "NTP amplification" nocase
        $type8 = "Smurf attack" nocase
        $type9 = "DNS flood" nocase
        $type10 = "Ping of death" nocase
        $type11 = "Slowloris" nocase
        $type12 = "slow POST" nocase
        $type13 = "slow READ" nocase
    
    condition:
        any of ($tool*) or any of ($type*)
}


rule DoS_Command_Control
{
    meta:
        description = "Detects potential DoS/DDoS C2 traffic (refined for accuracy)"
        severity = "HIGH"
        confidence = 90

    strings:
        // C2 patterns (less likely in normal traffic)
        $cmd1 = "ddos.start" nocase
        $cmd2 = "ddos.stop" nocase
        $cmd3 = "attack.start" nocase
        $cmd4 = "attack.stop" nocase
        $cmd5 = "start flood" nocase
        $cmd6 = "stop flood" nocase
        $cmd7 = "bot status" nocase

        // Keywords only if multiple appear
        $low1 = "target:" nocase
        $low2 = "duration=" nocase
        $low3 = "power=" nocase
        $low4 = "method=" nocase
        $low5 = "threads=" nocase

    condition:
        2 of ($cmd*) or (1 of ($cmd*) and 2 of ($low*))
}

