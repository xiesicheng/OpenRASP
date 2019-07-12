--TEST--
hook strval IS_STRING
--SKIPIF--
<?php
include(__DIR__.'/../skipif.inc');
?>
--INI--
openrasp.root_dir=/tmp/openrasp
--GET--
a=openrasp&b=test
--FILE--
<?php
$a0 = strval($_GET['a']);
var_dump(taint_dump($a0));
?>
--EXPECT--
array(1) {
  [0]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(0)
    ["endIndex"]=>
    int(7)
  }
}
