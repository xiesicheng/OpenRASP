--TEST--
hook ZEND_CONCAT CONST CV
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
$a0 = "name"."$a";
var_dump(taint_dump($a0));
?>
--EXPECT--
array(1) {
  [0]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(4)
    ["endIndex"]=>
    int(11)
  }
}
