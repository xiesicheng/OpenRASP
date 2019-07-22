--TEST--
hook stristr
--SKIPIF--
<?php
include(__DIR__.'/../skipif.inc');
?>
--INI--
openrasp.root_dir=/tmp/openrasp
--GET--
a=OPENRASP&b=test
--FILE--
<?php
$a = $_GET['a'];
$a0 = stristr($a, "as");
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
    int(2)
  }
}
