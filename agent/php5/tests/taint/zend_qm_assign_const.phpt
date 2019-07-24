--TEST--
hook ZEND_QM_ASSIGN CONST
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
$a0 = 1 ? 'a' : 'b';
var_dump(taint_dump($a0));
?>
--EXPECT--
bool(false)