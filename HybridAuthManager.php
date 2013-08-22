<?php
/**
 * HybridAuthManager
 *
 * This class is a combination of CDbAuthManager and CPhpAuthManager:
 *
 *   * The authorization hierarchy is stored in a flat PHP file
 *   * Authorization assignments are stored in the database
 *
 * This is useful if the authorization hierarchy is almost static
 * and not very complex.
 *
 * You can manage the authorization hierarchy in data/auth.php. To
 * not loose the comments there, you should avoid to call any method
 * to create auth items or add child items - even though it's supported.
 *
 * It also allows caching of auth assignments.
 */
class HybridAuthManager extends CPhpAuthManager
{
    /**
     * @var string the ID of the {@link CDbConnection} application component. Defaults to 'db'.
     * The database must have the tables as declared in "framework/web/auth/*.sql".
     */
    public $connectionID = 'db';

    /**
     * @var string the ID of the cache application component. Defaults to 'cache'. Set to `null` to disable caching.
     */
    public $cacheID = 'cache';

    /**
     * @var string the name of the table storing authorization item assignments. Defaults to 'auth_assignment'.
     */
    public $assignmentTable='auth_assignment';

    /**
     * @var int|boolean number of seconds to cache auth assignments. Default is 0 which means, that
     * authassignments are only cached during the current request. To completely disable caching
     * set this property to false.
     */
    public $assignmentCachingDuration = 0;

    /**
     * @var int number of seconds to cache the content of the auth hierarchy file. Default is 3600.
     * Set to 0 to disable caching
     */
    public $hierarchyCachingDuration = 3600;

    /**
     * @var array assignments indexed by user id
     */
    protected $_assignments = array();

    protected $_db;
    protected $_loading=false;

    /**
     * Performs access check for the specified user.
     * @param string $itemName the name of the operation that need access check
     * @param mixed $userId the user ID. This should can be either an integer and a string representing
     * the unique identifier of a user. See {@link IWebUser::getId}.
     * @param array $params name-value pairs that would be passed to biz rules associated
     * with the tasks and roles assigned to the user.
     * @return boolean whether the operations can be performed by the user.
     */
    public function checkAccess($itemName,$userId,$params=array())
    {
        $items = parent::getAuthItems();
        if(!isset($items[$itemName])) {
            return false;
        }
        $item           = $items[$itemName];
        $assignments    = $this->getAuthAssignments($userId);

        Yii::trace('Checking permission "'.$item->getName().'"','application.components.authmanager');

        if($this->executeBizRule($item->getBizRule(),$params,$item->getData())) {
            if(in_array($itemName,$this->defaultRoles)) {
                return true;
            }
            if(isset($assignments[$itemName])) {
                $assignment=$assignments[$itemName];
                if($this->executeBizRule($assignment->getBizRule(),$params,$assignment->getData()))
                    return true;
            }
            // Even if the user was not assigned to the item directly, he could
            // have been assigned to a parent item. $this->_children is private
            // so we have to use this workaround:
            foreach($items as $parentName => $item) {
                if($this->hasItemChild($parentName, $itemName) && $this->checkAccess($parentName, $userId, $params)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Assigns an authorization item to a user.
     * @param string $itemName the item name
     * @param mixed $userId the user ID (see {@link IWebUser::getId})
     * @param string $bizRule the business rule to be executed when {@link checkAccess} is called
     * for this particular authorization item.
     * @param mixed $data additional data associated with this assignment
     * @return CAuthAssignment the authorization assignment information.
     * @throws CException if the item does not exist or if the item has already been assigned to the user
     */
    public function assign($itemName,$userId,$bizRule=null,$data=null)
    {
        $this->getDbConnection()
            ->createCommand()
            ->insert($this->assignmentTable, array(
                'itemname'  => $itemName,
                'userid'    => $userId,
                'bizrule'   => $bizRule,
                'data'      => serialize($data)
            ));

        $this->flushAssignmentCache($userId);
        return new CAuthAssignment($this,$itemName,$userId,$bizRule,$data);
    }

    /**
     * Revokes an authorization assignment from a user.
     * @param string $itemName the item name
     * @param mixed $userId the user ID (see {@link IWebUser::getId})
     * @return boolean whether removal is successful
     */
    public function revoke($itemName,$userId)
    {
        $rows = $this->getDbConnection()
            ->createCommand()
            ->delete($this->assignmentTable, 'itemname=:itemname AND userid=:userid', array(
                ':itemname' => $itemName,
                ':userid'   => $userId
            ));

        return $rows > 0;
    }

    /**
     * Returns a value indicating whether the item has been assigned to the user.
     * @param string $itemName the item name
     * @param mixed $userId the user ID (see {@link IWebUser::getId})
     * @return boolean whether the item has been assigned to the user.
     */
    public function isAssigned($itemName,$userId)
    {
        $value = $this->getDbConnection()
            ->createCommand()
            ->select('itemname')
            ->from($this->assignmentTable)
            ->where('itemname=:itemname AND userid=:userid', array(
                ':itemname' => $itemName,
                ':userid'   => $userId))
            ->queryScalar();

        return $value!==false;
    }

    /**
     * Returns the item assignment information.
     * @param string $itemName the item name
     * @param mixed $userId the user ID (see {@link IWebUser::getId})
     * @return CAuthAssignment the item assignment information. Null is returned if
     * the item is not assigned to the user.
     */
    public function getAuthAssignment($itemName,$userId)
    {
        $row = $this->getDbConnection()
            ->createCommand()
            ->select()
            ->from($this->assignmentTable)
            ->where('itemname=:itemname AND userid=:userid', array(
                ':itemname' => $itemName,
                ':userid'   => $userId))
            ->queryRow();

        if($row!==false) {
            if(($data = @unserialize($row['data']))===false) {
                $data = null;
            }
            return new CAuthAssignment($this,$row['itemname'],$row['userid'],$row['bizrule'],$data);
        } else {
            return null;
        }
    }

    /**
     * Returns the item assignments for the specified user.
     * @param mixed $userId the user ID (see {@link IWebUser::getId})
     * @return array the item assignment information for the user. An empty array will be
     * returned if there is no item assigned to the user.
     */
    public function getAuthAssignments($userId)
    {
        $useCache = $this->assignmentCachingDuration!==false;

        if($useCache) {
            if(isset($this->_assignments[$userId])) {
                return $this->_assignments[$userId];
            } else {
                $cacheKey = $this->getAssignmentCacheKey($userId);
                $cache = Yii::app()->getComponent($this->cacheID);
                if(!$cache || ($assignments = $cache->get($cacheKey))!==false) {
                    return $this->_assignments[$userId] = $assignments;
                }
            }
        }

        $rows = $this->getDbConnection()
            ->createCommand()
            ->select()
            ->from($this->assignmentTable)
            ->where('userid=:userid', array(':userid'=>$userId))
            ->queryAll();

        $assignments = array();
        foreach($rows as $row)
        {
            if(($data = @unserialize($row['data']))===false) {
                $data = null;
            }
            $assignments[$row['itemname']] = new CAuthAssignment($this,$row['itemname'],$row['userid'],$row['bizrule'],$data);
        }

        if($useCache) {
            $this->_assignments[$userId] = $assignments;
            if($cache && $this->assignmentCachingDuration!==0) {
                $cache->set($cacheKey, $assignments);
            }
        }
        return $assignments;
    }

    /**
     * @param mixed $userId the user ID (see {@link IWebUser::getId})
     * @return string the cache key used to store auth assignments for this user
     */
    public function getAssignmentCacheKey($userId)
    {
        return '__authassignments__'.$userId.'_'.Yii::app()->id;
    }

    /**
     * Saves the changes to an authorization assignment.
     * @param CAuthAssignment $assignment the assignment that has been changed.
     */
    public function saveAuthAssignment($assignment)
    {
        $userId = $assignment->getUserId();
        $this->getDbConnection()
            ->createCommand()
            ->update($this->assignmentTable,
                array(
                    'bizrule'   => $assignment->getBizRule(),
                    'data'      => serialize($assignment->getData()),
                ),
                'itemname=:itemname AND userid=:userid',
                array(
                    'itemname'  => $assignment->getItemName(),
                    'userid'    => $userId,
                )
            );
        $this->flushAssignmentCache($userId);
    }

    /**
     * Returns the authorization items of the specific type and user.
     * @param integer $type the item type (0: operation, 1: task, 2: role). Defaults to null,
     * meaning returning all items regardless of their type.
     * @param mixed $userId the user ID. Defaults to null, meaning returning all items even if
     * they are not assigned to a user.
     * @return array the authorization items of the specific type.
     */
    public function getAuthItems($type=null,$userId=null)
    {
        $authItems = parent::getAuthItems();
        if($type===null && $userId===null) {
            return $authItems;
        }
        $items = array();
        if($userId===null) {
            foreach($authItems as $name=>$item) {
                if($item->getType()==$type) {
                    $items[$name] = $item;
                }
            }
        } else {
            foreach($this->getAuthAssignments($userId) as $assignment) {
                $name = $assignment->getItemName();
                if(isset($authItems[$name]) && ($type===null || $authItems[$name]->getType()==$type)) {
                    $items[$name]=$authItems[$name];
                }
            }
        }
        return $items;
    }

    /**
     * Removes all authorization assignments.
     */
    public function clearAuthAssignments() {
        // Hack: prevent auth assignments to be cleared during init
        if(!$this->_loading) {
            $this->getDbConnection()->createCommand()->delete($this->assignmentTable);
        }
    }

    /**
     * Flush assignments for specified user from cache
     *
     * @param mixed $userId the user ID (see {@link IWebUser::getId})
     */
    public function flushAssignmentCache($userId)
    {
        if($this->assignmentCachingDuration===false) {
            return;
        }

        if($cache = Yii::app()->getComponent($this->cacheID)) {
            $cache->delete($this->getAssignmentCacheKey($userId));
        }
    }

    /**
     * @return CDbConnection the DB connection instance
     * @throws CException if {@link connectionID} does not point to a valid application component.
     */
    protected function getDbConnection()
    {
        if($this->_db===null) {
            $this->_db =Yii::app()->getComponent($this->connectionID);
            if(!($this->_db instanceof CDbConnection)) {
                throw new CException("CDbAuthManager.connectionID '{$this->connectionID}' is invalid.");
            }
        }
        return $this->_db;
    }

    /**
     * Override parent class to prevent the call to clearAll()
     *
     * @return void
     */
    public function load()
    {
        $this->_loading=true;
        parent::load();
        $this->_loading=false;
    }

    /**
     * Loads the authorization data from a PHP script file.
     * File content is cached
     * @param string $file the file path.
     * @return array the authorization data
     * @see saveToFile
     */
    protected function loadFromFile($file)
    {
        $app    = Yii::app();
        $cache  = ($this->cacheID && $app->hasComponent($this->cacheID)) ? $app->getComponent($this->cacheID) : null;

        if($cache) {
            $key = '__authfile_'.Yii::app()->id;

            if(($content = $cache->get($key))!==false) {
                return $content;
            }
        }

        if(!is_file($file)) {
            return array();
        }

        $content = require($file);

        // Make some keys optional, to not bloat auth.php
        foreach($content as $name => $value) {
            if(!isset($value['description'])) {
                $content[$name]['description'] = null;
            }
            if(!isset($value['bizRule'])) {
                $content[$name]['bizRule'] = null;
            }
            if(!isset($value['data'])) {
                $content[$name]['data'] = null;
            }
        }

        if($cache && $this->hierarchyCachingDuration!==0) {
            $cache->set($key,$content, $this->hierarchyCachingDuration, new CFileCacheDependency($file));
        }

        return $content;
    }
}
