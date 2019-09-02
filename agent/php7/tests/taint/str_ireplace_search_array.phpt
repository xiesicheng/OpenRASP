--TEST--
hook str_ireplace search array
--SKIPIF--
<?php
include(__DIR__.'/../skipif.inc');
?>
--INI--
openrasp.root_dir=/tmp/openrasp
openrasp.taint_enable=1
--GET--
a=OPENRASP&b=test
--FILE--
<?php
$a = $_GET['a'];
$subject = "name $a";
$a0 = str_ireplace(array("pe", "as"), " ", $subject);
var_dump(taint_dump($a0));
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
    int(5)
  }
  [1]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(7)
    ["endIndex"]=>
    int(8)
  }
  [2]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(10)
    ["endIndex"]=>
    int(10)
  }
}
