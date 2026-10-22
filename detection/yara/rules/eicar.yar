/*
  EICAR anti-malware test file.
  The EICAR string is harmless by design; it exists so detection pipelines can be tested
  without real malware. The prefix is written in hex so this rule file is not itself
  flagged by antivirus. Spec: https://www.eicar.org/download-anti-malware-testfile/
*/
rule EICAR_Test_File
{
    meta:
        author = "DC TECH INC"
        description = "EICAR standard anti-virus test file (68-byte string at offset 0)"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        date = "2026-10-22"

    strings:
        // "X5O!P%@AP[4\PZX54(P^)7CC)7}"
        $prefix = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D }
        $marker = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        // The spec allows trailing whitespace only, so the file stays under 128 bytes.
        $prefix at 0 and $marker at 27 and filesize < 128
}
