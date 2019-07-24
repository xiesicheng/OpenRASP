--TEST--
hook sprintf
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
$a0 = sprintf('a%% b%b c%e d%f e%1$c f%1$d g%2$E h%3$F i%2$g j%3$G k%1$o l%1$u m%1$x n%1$X o%s p%4$s end',
65, 
12345678, 
3.1415926,
$a);
var_dump(taint_dump($a0));
?>
--EXPECT--
array(2) {
  [0]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(104)
    ["endIndex"]=>
    int(111)
  }
  [1]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(114)
    ["endIndex"]=>
    int(121)
  }
}
