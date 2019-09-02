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
$subject = array("name $a");
$subject1 = $subject;
$search = "enra";
$search1 = $search;
$replace = $_GET['b'];
$replace1 = $replace;
$a0 = str_replace($search1, $replace1, $subject1);
var_dump(taint_dump($a0[0]));
?>
--EXPECT--
array(3) {
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
    string(10) "$_GET['b']"
    ["startIndex"]=>
    int(7)
    ["endIndex"]=>
    int(10)
  }
  [2]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(11)
    ["endIndex"]=>
    int(12)
  }
}
