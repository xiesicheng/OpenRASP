--TEST--
hook ZEND_ADD_STRING UNUSED CONST
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
$a = $_GET['a'];
$a0 = "abc$a";
var_dump(taint_dump($a0));
?>
--EXPECT--
array(1) {
  [0]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(3)
    ["endIndex"]=>
    int(10)
  }
}