--TEST--
hook ZEND_CLONE CV CV
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
class Project {
    protected $description;

    public function setDescription($description) {
        $this->description = $description;

        return $this;
    }

    public function getDescription() {
        return $this->description;
    }
}
$project_one = new Project();
$project_one->setDescription($_GET['a']);
$project_two = clone $project_one; // Cloning to get a new object
var_dump(taint_dump($project_two->getDescription()));
?>
--EXPECT--
array(1) {
  [0]=>
  array(3) {
    ["source"]=>
    string(10) "$_GET['a']"
    ["startIndex"]=>
    int(0)
    ["endIndex"]=>
    int(7)
  }
}
