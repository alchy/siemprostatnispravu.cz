
<?php

$in = fopen($argv[1], "r");
$out = fopen($argv[2], "w+");

$start = microtime(true);

while(($line = fgets($in)) !== false) {
    $converted = iconv("cp1250", "utf-8", $line);
    fwrite($out, $converted);
}

fclose($out);
fclose($in);

$in = fopen($argv[2], "r");
$out = fopen($argv[1], "w+");
while($line = fgets($in)) {
  fwrite($out, trim($line).";");
}
fclose($out);
fclose($in);

$in = fopen($argv[1], "r");
$out = fopen($argv[2], "w+");
while($line = fgets($in)) {
	$line = str_replace("wstrPar9;", "wstrPar9\n", $line);
	$line = str_replace("-202", "\n202", $line);
	$line = str_replace(";202", "\n202", $line);
  	fwrite($out, $line);
}
fclose($out);
fclose($in);

$elapsed = microtime(true) - $start;
echo "\r\n", "[d] PHP: input file:  ", $argv[1], "\r\n";
echo "\r\n", "[d] PHP: output file: ", $argv[2], "\r\n";
echo "\r\n", "[d] PHP: iconv took $elapsed seconds\r\n";
?>
