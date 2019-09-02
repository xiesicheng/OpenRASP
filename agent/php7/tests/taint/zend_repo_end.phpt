--TEST--
hook ZEND_REPO_END
--SKIPIF--
<?php
if (PHP_MAJOR_VERSION != 7) die('Skipped: ZEND_REPO_END is available in PHP7.');
include(__DIR__.'/../skipif.inc');
?>
--INI--
openrasp.root_dir=/tmp/openrasp
openrasp.taint_enable=1
--GET--
a=openrasp&b=test
--FILE--
<?php
$a = $_GET['a'];
$b = $_GET['b'];
$a0 = <<<EOT
This is $b of $a, do you like it?
EOT;
var_dump(taint_dump($a0));
?>
--EXPECT--
array(2) {
  [0]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['b']"
    ["startIndex"]=>
    int(8)
    ["endIndex"]=>
    int(11)
  }
  [1]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(16)
    ["endIndex"]=>
    int(23)
  }
}
