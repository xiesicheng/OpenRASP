--TEST--
hook ZEND_ASSIGN VAR CONST
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
$a0[0] = "name";
var_dump(taint_dump($a0[0]));
?>
--EXPECT--
bool(false)
