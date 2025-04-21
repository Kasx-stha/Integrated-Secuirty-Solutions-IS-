/*
 * Phishing Detection Rules
 * 
 * This Yara ruleset contains signatures for detecting phishing attempts.
 */

rule Phishing_Form_Indicators
{
    meta:
        description = "Detects phishing forms with common suspicious elements"
        severity = "MEDIUM"
        confidence = 75
    
    strings:
        $form1 = "<form" nocase
        $form2 = "</form>" nocase
        
        $input1 = "type=\"password\"" nocase
        $input2 = "name=\"password\"" nocase
        $input3 = "name=\"pass\"" nocase
        $input4 = "name=\"pwd\"" nocase
        
        $input5 = "name=\"username\"" nocase
        $input6 = "name=\"user\"" nocase
        $input7 = "name=\"email\"" nocase
        $input8 = "name=\"ssn\"" nocase
        $input9 = "name=\"card\"" nocase
        $input10 = "name=\"credit\"" nocase
        $input11 = "name=\"ccnum\"" nocase
        $input12 = "name=\"cc\"" nocase
        
        $action1 = "action=\"" nocase
        $action2 = "method=\"post\"" nocase
    
    condition:
        ($form1 and $form2) and 
        (1 of ($input1, $input2, $input3, $input4)) and
        (1 of ($input5, $input6, $input7, $input8, $input9, $input10, $input11, $input12)) and
        (1 of ($action1, $action2))
}

rule Phishing_Brand_Spoofing
{
    meta:
        description = "Detects phishing attempts spoofing major brands with urgency"
        severity = "HIGH"
        confidence = 80

    strings:
        // Targeted brand keywords
        $brand1 = "paypal" nocase
        $brand2 = "apple" nocase
        $brand3 = "microsoft" nocase
        $brand4 = "google" nocase
        $brand5 = "facebook" nocase
        $brand6 = "amazon" nocase
        $brand7 = "netflix" nocase

        // Typical phishing actions
        $action1 = "verify your account" nocase
        $action2 = "confirm your identity" nocase
        $action3 = "update your information" nocase
        $action4 = "login to secure" nocase
        $action5 = "validate your access" nocase

        // Urgency or pressure terms
        $urgency1 = "urgent" nocase
        $urgency2 = "immediately" nocase
        $urgency3 = "within 24 hours" nocase
        $urgency4 = "limited access" nocase
        $urgency5 = "account suspended" nocase

    condition:
        // Require 1 brand, 1 action, and 1 urgency phrase for a match
        1 of ($brand*) and 1 of ($action*) and 1 of ($urgency*)
}


rule Phishing_Credential_Theft
{
    meta:
        description = "Detects common credential theft patterns in phishing attacks"
        severity = "HIGH"
        confidence = 85
    
    strings:
        $s1 = "password expired" nocase
        $s2 = "account expired" nocase
        $s3 = "unusual activity" nocase
        $s4 = "suspicious activity" nocase
        $s5 = "account verification" nocase
        $s6 = "security update" nocase
        $s7 = "confirm your information" nocase
        $s8 = "confirm your details" nocase
        $s9 = "click here to verify" nocase
        $s10 = "security alert" nocase
        $s11 = "account notification" nocase
        $s12 = "account will be locked" nocase
        $s13 = "account will be suspended" nocase
        $s14 = "account has been limited" nocase
        $s15 = "unusual login" nocase
        
        $form1 = "<form" nocase
        $input1 = "password" nocase
    
    condition:
        1 of ($s*) and ($form1 and $input1)
}

rule Phishing_Obfuscation
{
    meta:
        description = "Detects obfuscation techniques commonly used in phishing pages"
        severity = "HIGH"
        confidence = 90
    
    strings:
        $obf1 = "eval(" nocase
        $obf2 = "document.write" nocase
        $obf3 = "escape(" nocase
        $obf4 = "unescape(" nocase
        $obf5 = "fromCharCode" nocase
        $obf6 = "decodeURIComponent" nocase
        $obf7 = "atob(" nocase
        $obf8 = "base64" nocase
        
        $steal1 = "password" nocase
        $steal2 = "credentials" nocase
        $steal3 = "login" nocase
        $steal4 = "credit card" nocase
        $steal5 = "card number" nocase
    
    condition:
        1 of ($obf*) and 1 of ($steal*)
}
