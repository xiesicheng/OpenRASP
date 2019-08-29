--TEST--
hook array_walk_recursive callable ref arg
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
function test(&$item, $key)
{
}
$a = $_GET['a'];
$a1 = $a;
$sub = array('a' => $a);
$arr = array('sub' => $sub);
$arr1 = $arr;
array_walk_recursive($arr, 'test');
var_dump(taint_dump($arr['sub']['a']));
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
