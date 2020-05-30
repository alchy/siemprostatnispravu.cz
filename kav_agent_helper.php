
<?php

$in = fopen($argv[1], "r");
$out = fopen($argv[2], "w+");

$start = microtime(true);

$lines_in = 0;
while(($line = fgets($in)) !== false) {
    $converted = iconv("cp1250", "ASCII//TRANSLIT", $line);
    #$converted = iconv("cp1250", "US-ASCII", $line);
    $lines_in = $lines_in + 1;
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
	$line = str_replace("-20", "\n20", $line);
	$line = str_replace(";20", "\n20", $line);
  	fwrite($out, $line);
}
fclose($out);
fclose($in);

$lines_out = 0;
$out = fopen($argv[2], "r");
while($line = fgets($out)) {
	$lines_out = $lines_out + 1;
}

$elapsed = microtime(true) - $start;
echo "[d] PHP: input file:  ", $argv[1];
echo "[d] PHP: output file: ", $argv[2];
echo "[d] PHP: iconv took $elapsed seconds";
echo "[d] PHP: lines_in:  " , $lines_in;
echo "[d] PHP: lines_out: " , $lines_out;
?>
