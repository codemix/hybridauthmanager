HybridAuthManager
=================

An AuthManager for Yii that stores the hierarchy in a flat PHP file and the assignmens in DB.

This class is a combination of CDbAuthManager and CPhpAuthManager:

  * The authorization hierarchy is stored in a flat PHP file
  * Authorization assignments are stored in the database

This is useful if the authorization hierarchy is almost static and not very complex.

You can manage the authorization hierarchy in data/auth.php. To not loose the comments there,
you should avoid to call any method to create auth items or add child items - even though it's supported.

## Installation

We recommend to install the extension with [composer](http://getcomposer.org/). Add this to
the `require` section of your `composer.json`:

    'codemix/hybridautmanager' : 'dev-master'

> Note: There's no stable version yet.

If you haven't yet, you should also add an alias to composer's vendor directory.

```php
$vendor = realpath(__DIR__.'/../vendor');
return array(
    'alias' => array(
        'vendor' => realpath(__DIR__.'/../vendor'), // Fix this path
    ),
    ...
```

## Configuration

Add this configuration to your `main.php`:

```php
'components' => array(
    'authManager' => array(
        'class' => 'vendor.codemix.hybridautmanager.HybridAuthManager',
    ),
    ...
),
```

Just as with [`CPhpAuthManager`](http://www.yiiframework.com/doc/api/1.1/CPhpAuthManager) you'll
need to supply a file with auth rules. By default this is in `data/auth.php`. But here you only
have to supply the auth hierarchy:

```php
return array(
    // Admin == Root (Full permissions).
    'Admin' => array(
        'type'          => CAuthItem::TYPE_ROLE,
        'description'   => 'Administrator',
        'children'      => array(
            'manageUser',
            'managePosts',
        ),
    ),
    'manageUser' => array(
        'type' => CAuthItem::TYPE_TASK,
        'children' => array(
            'createUser',
            'updateUser',
            'deleteUser',
            'readUser',
        ),
    ),

    'createUser'    => array('type' => 'CAuthItem::TYPE_OPERATION'),
    'updateUser'    => array('type' => 'CAuthItem::TYPE_OPERATION'),
    'deleteUser'    => array('type' => 'CAuthItem::TYPE_OPERATION'),
    'readUser'      => array('type' => 'CAuthItem::TYPE_OPERATION'),

);
```

The content of this file will be cached unless you set `cacheID` to `null`.

The actual Role assignments will be saved in a DB table `auth_assignments` by default.
You can change this name with the `assignmentTable` property of the `authManager` component.
