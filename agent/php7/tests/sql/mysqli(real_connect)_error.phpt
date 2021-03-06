--TEST--
hook mysqli::real_connect
--SKIPIF--
<?php
$plugin = <<<EOF
RASP.algorithmConfig = {
    sql_exception: {
        name:      '算法3 - 记录数据库异常',
        action:    'log',
        reference: 'https://rasp.baidu.com/doc/dev/official.html#sql-exception',
        mysql: {
            error_code: [
                1045, // Access denied for user 'bae'@'10.10.1.1'
                1060, // Duplicate column name '5.5.60-0ubuntu0.14.04.1'
                1064, // You have an error in your SQL syntax
                1105, // XPATH syntax error: '~root@localhost~'
                1367, // Illegal non geometric 'user()' value found during parsing
                1690  // DOUBLE value is out of range in 'exp(~((select 'root@localhost' from dual)))'
            ]
        }
    }
}
plugin.register('sql_exception', params => {
    assert(params.hostname == '127.0.0.1')
    assert(params.username == 'nonexistentusername')
    assert(params.error_code == '1045')
    return block
})
EOF;
$conf = <<<CONF
security.enforce_policy: false
CONF;
include(__DIR__.'/../skipif.inc');
if (!extension_loaded("mysqli")) die("Skipped: mysqli extension required.");
?>
--INI--
openrasp.root_dir=/tmp/openrasp
--FILE--
<?php
$mysqli = mysqli_init();
if (!$mysqli) {
    die('mysqli_init failed');
}

if (!$mysqli->real_connect('127.0.0.1', 'nonexistentusername')) {
    die('Connect Error (' . mysqli_connect_errno() . ') '
            . mysqli_connect_error());
}

$mysqli->close();
?>
--EXPECTREGEX--
<\/script><script>location.href="http[s]?:\/\/.*?request_id=[0-9a-f]{32}"<\/script>