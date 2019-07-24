--TEST--
hook str_ireplace search array replace array
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
$a0 = str_ireplace(array("pe", "as"), array($_GET['b'], $_GET['b']), $subject);
var_dump(taint_dump($a0));
?>
--EXPECT--
array(5) {
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
    string(10) "$_GET['b']"
    ["startIndex"]=>
    int(6)
    ["endIndex"]=>
    int(9)
  }
  [2]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(10)
    ["endIndex"]=>
    int(11)
  }
  [3]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['b']"
    ["startIndex"]=>
    int(12)
    ["endIndex"]=>
    int(15)
  }
  [4]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(16)
    ["endIndex"]=>
    int(16)
  }
}