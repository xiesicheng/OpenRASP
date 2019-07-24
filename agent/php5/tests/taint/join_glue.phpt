--TEST--
hook join glue "+"
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
$arr = array($a, $a, $a, $a, $a);
$a0 = join("+", $arr);
var_dump(taint_dump($a0));
?>
--EXPECT--
array(5) {
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
    int(9)
    ["endIndex"]=>
    int(16)
  }
  [2]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(18)
    ["endIndex"]=>
    int(25)
  }
  [3]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(27)
    ["endIndex"]=>
    int(34)
  }
  [4]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(36)
    ["endIndex"]=>
    int(43)
  }
}