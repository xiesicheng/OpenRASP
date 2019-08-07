--TEST--
hook implode
--SKIPIF--
<?php
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
$arr = array($a, array(), $a);
$a0 = @implode($arr);
var_dump(taint_dump($a0));
?>
--EXPECT--
array(2) {
  [0]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(0)
    ["endIndex"]=>
    int(7)
  }
  [1]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(13)
    ["endIndex"]=>
    int(20)
  }
}