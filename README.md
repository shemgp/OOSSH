OOSSH - Object Oriented SSH for PHP
===================================

OOSSH is an encapsulation of the php SSH2 library.
Forked and improved from: https://github.com/youknowriad/OOSSH

Warning
-------

OOSSH is not stable.

Basic Usage
-----------

#### Basic login and exec
```php
$con = new OOSSH\SSH2\Connection('server', 22);
$con->connect()
    ->authenticate(new OOSSH\SSH2\Authentication\Password('username', 'password'));
$con->exec('PATH=/sbin:$PATH; uci show wireless.ra0.ssid');
echo $con->getOutput();
```

#### Multiple commands in one go
```php
$con = new OOSSH\SSH2\Connection('server', 22);
$con->connect()
    ->authenticate(new OOSSH\SSH2\Authentication\Password('username', 'password'))
    ->begin()
        ->exec('uci show wireless.ra0.ssid')
        ->exec('ls -R /')
    ->end(null, ['char' => true, 'wait_before_end' => 1000000]);
$con->getOutput();
```

#### Using multiple commands separately
```php
$con = new OOSSH\SSH2\Connection('server', 22);
$con->connect()
    ->authenticate(new OOSSH\SSH2\Authentication\Password('username', 'password'))
    ->setShell(['start' => '/~#/']);
$con->exec('uci show wireless.ra0.ssid', null, ['char' => true]);
echo $con->getOutput();
$con->exec('ls -R /', null, ['char' => true, 'wait_before_end' => 1000000]);
echo $con->getOutput();
```

TODO
----

 * File handling (SCP)
 * Refactoring
 * Tests
