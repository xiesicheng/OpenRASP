--TEST--
hook MongoDB\Driver\Query::__construct
--SKIPIF--
<?php
if (PHP_VERSION_ID < 50500) die('Skipped: not supported (version < 5.5.0)');
$plugin = <<<EOF
plugin.register('mongodb', params => {
    assert(params.query == '{"likes":100}')
    assert(params.server == 'mongodb')
    assert(params.class.endsWith('Query'))
    assert(params.method == '__construct')
    return block
})
EOF;
include(__DIR__.'/../skipif.inc');
if (!extension_loaded("mongodb")) die("Skipped: mongodb extension required.");
?>
--INI--
openrasp.root_dir=/tmp/openrasp
--FILE--
<?php
$query = new MongoDB\Driver\Query(['likes' => 100]);
?>
--EXPECTREGEX--
<\/script><script>location.href="http[s]?:\/\/.*?request_id=[0-9a-f]{32}"<\/script>