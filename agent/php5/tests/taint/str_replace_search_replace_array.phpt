--TEST--
hook str_replace search array replace array
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
$subject = "name $a";
$a0 = str_replace(array("pe", "as"), array("123", "456"), $subject);
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
    int(9)
    ["endIndex"]=>
    int(10)
  }
  [2]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(14)
    ["endIndex"]=>
    int(14)
  }
}
