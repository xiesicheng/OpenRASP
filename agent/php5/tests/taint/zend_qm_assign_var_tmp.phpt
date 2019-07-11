--TEST--
hook ZEND_QM_ASSIGN_VAR CONST
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
$a0 = 1 ? 'a' : $a;
var_dump(taint_dump($a0));
?>
--EXPECT--
bool(false)