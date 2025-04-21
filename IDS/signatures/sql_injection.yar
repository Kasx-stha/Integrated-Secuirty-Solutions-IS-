/*
 * SQL Injection Detection Rules
 * 
 * This Yara ruleset contains signatures for detecting SQL injection attacks.
 */

rule SQL_Injection_Basic
{
    meta:
        description = "Detects basic SQL injection patterns"
        severity = "HIGH"
        confidence = 80
        reference = "https://owasp.org/www-community/attacks/SQL_Injection"
    
    strings:
        $s1 = "SELECT" nocase
        $s2 = "INSERT" nocase
        $s3 = "UPDATE" nocase
        $s4 = "DELETE" nocase
        $s5 = "UNION" nocase
        $s6 = "DROP" nocase
        $s7 = "FROM" nocase
        $s8 = "WHERE" nocase
        $s9 = "OR 1=1" nocase
        $s10 = "OR '1'='1'" nocase
        $s11 = "OR \"1\"=\"1\"" nocase
        $s12 = ";--" nocase
        $s13 = "1' OR '1'='1" nocase
        $s14 = "1\" OR \"1\"=\"1" nocase
        $s15 = "' OR ''='" nocase
        $s16 = "HAVING 1=1" nocase
        $s17 = "GROUP BY" nocase
    
    condition:
        ($s5 and $s1 and $s7) or
        ($s12 and ($s1 or $s2 or $s3 or $s4)) or
        ($s9 or $s10 or $s11 or $s13 or $s14 or $s15 or $s16 or $s17) or
        ($s6 and $s7) or
        ($s1 and $s8)
}

rule SQL_Injection_Time_Based
{
    meta:
        description = "Detects time-based SQL injection"
        severity = "HIGH"
        confidence = 85
    
    strings:
        $s1 = "SLEEP(" nocase
        $s2 = "BENCHMARK(" nocase
        $s3 = "WAIT FOR DELAY" nocase
        $s4 = "PG_SLEEP" nocase
        $s5 = "WAITFOR DELAY" nocase
    
    condition:
        any of them
}

rule SQL_Injection_Error_Based
{
    meta:
        description = "Detects error-based SQL injection"
        severity = "HIGH"
        confidence = 85
    
    strings:
        $s1 = "@@version" nocase
        $s2 = "extractvalue(" nocase
        $s3 = "updatexml(" nocase
        $s4 = "DBMS_PIPE.RECEIVE_MESSAGE" nocase
        $s5 = "UTL_INADDR.GET_HOST_ADDRESS" nocase
        $s6 = "CAST(" nocase wide
        $s7 = "convert(" nocase
        $s8 = "information_schema" nocase
    
    condition:
        any of them
}
