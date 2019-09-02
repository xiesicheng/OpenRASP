--TEST--
hook ZEND_ASSIGN_REF CV VAR
--SKIPIF--
<?php
die("Skipped: ZEND_FETCH_DIM_W has not been handled.");
include(__DIR__.'/../skipif.inc');
?>
--INI--
openrasp.root_dir=/tmp/openrasp
openrasp.taint_enable=1
--GET--
a=openrasp&b=test
--FILE--
<?php
var_dump(taint_dump($_GET['a']));
$a0 = &$_GET['a'];
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
