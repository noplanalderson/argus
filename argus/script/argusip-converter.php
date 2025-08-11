<?php
/**
 * Convert a plain text IP list into a .cdb file
 * Usage: php argusip-converter.php iplist.txt iplist.cdb [default_value]
 */

if ($argc < 3) {
    echo "Usage: php {$argv[0]} <input.txt> <output.cdb> [default_value]\n";
    exit(1);
}

$inputFile = $argv[1];
$outputFile = $argv[2];
$defaultValue = $argv[3] ?? "";

// Check input file
if (!file_exists($inputFile)) {
    echo "Error: Input file not found: $inputFile\n";
    exit(1);
}

// Open CDB for writing
$db = dba_open($outputFile, "n", "cdb_make");
if (!$db) {
    echo "Error: Unable to create CDB file.\n";
    exit(1);
}

// Read IP list
$lines = file($inputFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
foreach ($lines as $line) {
    $ip = trim($line);
    if ($ip === "" || strpos($ip, "#") === 0) {
        continue;
    }
    $ip = preg_replace('/\s+/', '', $ip);
    dba_insert($ip, $defaultValue, $db);
}

dba_close($db);

echo "[+] CDB file created: $outputFile\n";
