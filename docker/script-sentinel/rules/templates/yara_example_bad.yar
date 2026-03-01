/*
 * ANTI-PATTERNS - Do NOT write rules like this!
 * These examples show common mistakes to avoid.
 */

// BAD: Too generic - will match legitimate admin scripts
rule BAD_Too_Generic {
    strings:
        $a = "powershell" nocase  // Too broad!
    condition:
        $a
}

// BAD: Missing metadata - no context for scoring
rule BAD_No_Metadata {
    strings:
        $a = "evil"
    condition:
        $a
}

// BAD: Overly complex condition - hard to understand/maintain
rule BAD_Complex_Condition {
    strings:
        $a = "a"
        $b = "b"
    condition:
        (#a > 5 and #b < 3) or (#a < 2 and #b > 7) or
        (@a[1] < @b[1] and @a[2] > @b[2])
}

// BAD: Matches common words - high false positive rate
rule BAD_Common_Words {
    strings:
        $a = "function" nocase
        $b = "return" nocase
    condition:
        $a and $b
}
