/*
 * Cross-Site Scripting (XSS) Detection Rules
 * 
 * This Yara ruleset contains signatures for detecting XSS attacks.
 */

rule XSS_Basic_Script_Tags
{
    meta:
        description = "Detects basic XSS using script tags with suspicious payloads"
        severity = "HIGH"
        confidence = 90

    strings:
        $open_tag = "<script" nocase
        $close_tag = "</script>" nocase
        $js_url = "javascript:" nocase
        $cookie = "document.cookie" nocase
        $loc = "document.location" nocase
        $write = "document.write" nocase
        $winloc = "window.location" nocase
        $onload = "onload=" nocase
        $onerror = "onerror=" nocase
        $alert = "alert(" nocase

    condition:
        (
            ($open_tag and $close_tag) and
            1 of ($cookie, $loc, $write, $winloc, $alert, $onload, $onerror)
        )
        or
        (
            $js_url and 1 of ($cookie, $loc, $alert)
        )
}


rule XSS_Event_Handlers
{
    meta:
        description = "Detects XSS using event handlers"
        severity = "MEDIUM"
        confidence = 80
    
    strings:
        $e1 = "onabort=" nocase
        $e2 = "onblur=" nocase
        $e3 = "onchange=" nocase
        $e4 = "onclick=" nocase
        $e5 = "ondblclick=" nocase
        $e6 = "onerror=" nocase
        $e7 = "onfocus=" nocase
        $e8 = "onkeydown=" nocase
        $e9 = "onkeypress=" nocase
        $e10 = "onkeyup=" nocase
        $e11 = "onload=" nocase
        $e12 = "onmousedown=" nocase
        $e13 = "onmousemove=" nocase
        $e14 = "onmouseout=" nocase
        $e15 = "onmouseover=" nocase
        $e16 = "onmouseup=" nocase
        $e17 = "onreset=" nocase
        $e18 = "onselect=" nocase
        $e19 = "onsubmit=" nocase
        $e20 = "onunload=" nocase
        
        $alert = "alert(" nocase
        $cookie = "cookie" nocase
        $eval = "eval(" nocase
    
    condition:
        any of ($e*) and ($alert or $cookie or $eval)
}

rule XSS_DOM_Based
{
    meta:
        description = "Detects DOM-based XSS"
        severity = "HIGH"
        confidence = 85
    
    strings:
        $s1 = "document.URL" nocase
        $s2 = "document.documentURI" nocase
        $s3 = "document.location" nocase
        $s4 = "document.referrer" nocase
        $s5 = "document.write" nocase
        $s6 = "document.body.innerHTML" nocase
        $s7 = "window.location" nocase
        $s8 = "location.href" nocase
        $s9 = "location.search" nocase
        $s10 = "location.hash" nocase
        $s11 = "innerHTML" nocase
        $s12 = "outerHTML" nocase
        
        $evil1 = "eval(" nocase
        $evil2 = "setTimeout(" nocase
        $evil3 = "setInterval(" nocase
        $evil4 = "Function(" nocase
        $evil5 = "document.write(" nocase
    
    condition:
        any of ($s*) and any of ($evil*)
}

rule XSS_Encoded
{
    meta:
        description = "Detects potentially encoded XSS payloads (stricter)"
        severity = "HIGH"
        confidence = 90

    strings:
        // Encoded patterns
        $enc1 = /&#x[0-9a-f]{2,4};?/ nocase
        $enc2 = /%u00[0-9a-f]{2}/ nocase
        $enc3 = /\\u00[0-9a-f]{2}/ nocase
        $enc4 = /\\x[0-9a-f]{2}/ nocase
        $enc5 = "String.fromCharCode" nocase
        $enc6 = "unescape(" nocase
        $enc7 = "decodeURIComponent(" nocase
        $enc8 = "atob(" nocase

        // JavaScript-related indicators
        $js1 = "<script" nocase
        $js2 = "alert(" nocase
        $js3 = "eval(" nocase
        $js4 = "document.write" nocase
        $js5 = "window.location" nocase
        $js6 = "document.cookie" nocase

    condition:
        1 of ($enc*) and 2 of ($js*) and filesize < 100000
}
