/*
  Canary-token marker for a FICTIONAL organization ("Example Co.").
  Defenders plant decoy documents carrying a unique marker; finding the marker on a file
  share, in a mail gateway or in an outbound upload means a decoy was copied.
*/
rule ExampleCo_Canary_Document
{
    meta:
        author = "DC TECH INC"
        description = "Decoy document marker EXCO-CANARY-<16 hex> in text or UTF-16 form"
        date = "2026-10-22"

    strings:
        $ascii = /EXCO-CANARY-[0-9a-f]{16}/
        $wide = "EXCO-CANARY-" wide

    condition:
        $ascii or $wide
}
