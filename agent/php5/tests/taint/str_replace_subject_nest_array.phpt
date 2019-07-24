--TEST--
hook str_replace
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
$subject = array("name $a", array("$a", "nest $a"));
$a0 = str_replace("enra", " ", $subject);
var_dump(taint_dump($a0[0]));
var_dump(taint_dump($a0[1][0]));
var_dump(taint_dump($a0[1][1]));
?>
--EXPECT--
array(2) {
  [0]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(5)
    ["endIndex"]=>
    int(6)
  }
  [1]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(8)
    ["endIndex"]=>
    int(9)
  }
}
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
array(1) {
  [0]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(5)
    ["endIndex"]=>
    int(12)
  }
}
