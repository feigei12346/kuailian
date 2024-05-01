// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

// 定义可调用的智能合约接口
interface SomeContract {
    function someFunction(address user) external returns (bytes32);
}

contract CustomAccessControl is AccessControl {
    // 定义角色,目前分为管理员和用户两个角色
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant USER_ROLE = keccak256("USER_ROLE");

    // 定义事件
    event AdminAdded(address indexed account);
    event AdminRemoved(address indexed account);
    event UserAdded(address indexed account, bytes32 indexed role);
    event UserRemoved(address indexed account, bytes32 indexed role);

    // 用户属性结构
    struct UserAttributes {
        string gender;  // 性别
        uint age;       // 年龄
        string phoneNumber; // 电话号码
        bool isMarried; // 是否婚配
        string position;  // 职位
    }

    // 管理员角色
    struct Admin {
        bool exists;
        uint256 index;
    }

    // 用户角色
    struct User {
        bool exists;
        uint256 index;
        UserAttributes attributes;
        bytes32[] roles; // 存储用户的角色数组，包括多种高层，中层，普通职工
    }

    // 所有角色的账户
    address[] public admins;
    address[] public users;

    // 存储角色对应的账户
    mapping(address => Admin) private adminAccounts;
    mapping(address => User) private userAccounts;

    // 仅允许管理员访问的函数
    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "AccessControl: caller is not an admin");
        _;
    }

    // 仅允许用户访问的函数
    modifier onlyUser() {
        require(hasRole(USER_ROLE, msg.sender), "AccessControl: caller is not a user");
        _;
    }

    // 添加管理员角色
    function addAdmin(address account) public onlyAdmin {
        require(!adminAccounts[account].exists, "AccessControl: account already has admin role");
        adminAccounts[account] = Admin(true, admins.length);
        admins.push(account);
        emit AdminAdded(account);
    }

    // 移除管理员角色
    function removeAdmin(address account) public onlyAdmin {
        require(adminAccounts[account].exists, "AccessControl: account does not have admin role");
        uint256 indexToDelete = adminAccounts[account].index;
        address accountToMove = admins[admins.length - 1];
        admins[indexToDelete] = accountToMove;
        adminAccounts[accountToMove].index = indexToDelete;
        admins.pop();
        delete adminAccounts[account];
        emit AdminRemoved(account);
    }

    // 添加用户角色和属性
    function addUser(
        address account,
        bytes32[] memory roles,
        string memory gender,
        uint age,
        string memory phoneNumber,
        bool isMarried,
        string memory position
    ) public onlyAdmin {
        require(!userAccounts[account].exists, "AccessControl: account already has user role");
        userAccounts[account] = User(true, users.length, UserAttributes(gender, age, phoneNumber, isMarried, position), roles);
        users.push(account);
        for (uint i = 0; i < roles.length; i++) {
            emit UserAdded(account, roles[i]);  // 记录每个角色
        }
    }

    // 移除用户角色
    function removeUser(address account, bytes32 role) public onlyAdmin {
        require(userAccounts[account].exists, "AccessControl: account does not have user role");
        uint256 indexToDelete = userAccounts[account].index;
        address accountToMove = users[users.length - 1];
        users[indexToDelete] = accountToMove;
        userAccounts[accountToMove].index = indexToDelete;
        users.pop();
        delete userAccounts[account];
        emit UserRemoved(account, role);
    }

    // 检查是否是管理员账户
    function isAdmin(address account) public view returns (bool) {
        return adminAccounts[account].exists;
    }

    // 检查是否是用户账户
    function isUser(address account) public view returns (bool) {
        return userAccounts[account].exists;
    }

    // 获取用户的角色
    function getUserRoles(address account) public view returns (bytes32[] memory) {
        return userAccounts[account].roles;
    }

    // 获取用户属性
    function getUserAttributes(address account) public view returns (UserAttributes memory) {
        return userAccounts[account].attributes;
    }
    
    // 获取用户的职位
    function getPosition(address account) public view returns (string memory) {
        return userAccounts[account].attributes.position;
    }
    // 添加权限控制函数，仅允许指定属性的用户访问
    function restrictedFunctionByAttribute(string memory attributeName, string memory attributeValue) public view onlyUser {
        require(userAccounts[msg.sender].exists, "AccessControl: caller is not a user");
        UserAttributes memory attributes = userAccounts[msg.sender].attributes;
        if (keccak256(abi.encodePacked(attributeName)) == keccak256(abi.encodePacked("gender"))) {
            require(keccak256(abi.encodePacked(attributes.gender)) == keccak256(abi.encodePacked(attributeValue)), "AccessControl: attribute value does not match");
        } else if (keccak256(abi.encodePacked(attributeName)) == keccak256(abi.encodePacked("age"))) {
            require(attributes.age == uint(keccak256(abi.encodePacked(attributeValue))), "AccessControl: attribute value does not match");
        } else if (keccak256(abi.encodePacked(attributeName)) == keccak256(abi.encodePacked("phoneNumber"))) {
            require(keccak256(abi.encodePacked(attributes.phoneNumber)) == keccak256(abi.encodePacked(attributeValue)), "AccessControl: attribute value does not match");
        } else if (keccak256(abi.encodePacked(attributeName)) == keccak256(abi.encodePacked("isMarried"))) {
            require(attributes.isMarried == (keccak256(abi.encodePacked(attributeValue)) == keccak256(abi.encodePacked("true"))), "AccessControl: attribute value does not match");
        } else if (keccak256(abi.encodePacked(attributeName)) == keccak256(abi.encodePacked("position"))) {
            require(keccak256(abi.encodePacked(attributes.position)) == keccak256(abi.encodePacked(attributeValue)), "AccessControl: attribute value does not match");
        } else {
            revert("AccessControl: invalid attribute name");
        }
        // 执行受限操作
    }
}

contract ResourceManagement is CustomAccessControl {
    // 定义事件
    event ResourceAssigned(bytes32 indexed role, bytes32 indexed resource, address indexed assignedBy);
    event AccessAttempted(address indexed user, bool success, string message);

    // 定义可调用的智能合约
    SomeContract public someContract;
    ManagerRole public managerRoleContract; // 添加声明

    constructor(address _managerRoleContractAddress, address _someContractAddress) {
        managerRoleContract = ManagerRole(_managerRoleContractAddress);
        someContract = SomeContract(_someContractAddress);
    }

     // 给角色分配资源 - 调用可调用的智能合约来分配资源
    function assignResourceToRole(bytes32 role, bytes32 resource) public onlyAdmin {
        // 调用可调用的智能合约来分配资源
        someContract.someFunction(msg.sender);
        emit ResourceAssigned(role, resource, msg.sender);
    }

    /// 获取用户拥有的资源 - 调用可调用的智能合约来获取资源
    function getUserResources(address user) public payable returns (bytes32) {
        // 调用可调用的智能合约来获取用户资源
        (bool success, bytes memory result) = address(someContract).call{value: msg.value}(abi.encodeWithSignature("someFunction(address)", user));
        require(success, "Call to SomeContract failed");
        
        // 将返回的 bytes 类型转换为 bytes32
        bytes32 resultBytes32;
        assembly {
            resultBytes32 := mload(add(result, 32))
        }
        
        return resultBytes32;
    }
}

// ManagerRole 合约
contract ManagerRole is CustomAccessControl {
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    constructor() {
        grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function grantManagerRole(address account) external onlyAdmin {
        grantRole(MANAGER_ROLE, account);
    }

    function revokeManagerRole(address account) external onlyAdmin {
        revokeRole(MANAGER_ROLE, account);
    }

    function isManager(address account) external view returns (bool) {
        return hasRole(MANAGER_ROLE, account);
    }
}

