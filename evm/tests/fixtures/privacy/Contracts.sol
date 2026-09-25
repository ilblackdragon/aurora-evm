// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Small integration fixtures, not production token/AMM/lending implementations.
// No privacy checks or privacy-specific opcodes: policies live in the host.
contract Token {
    string public constant name = "Fixture Token";
    string public constant symbol = "FIX";
    uint8 public constant decimals = 18;
    address private admin;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    error BalanceLeaked(uint256 amount);
    constructor() { admin = msg.sender; }
    function mint(address to, uint256 amount) external {
        require(msg.sender == admin);
        totalSupply += amount; balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount); return true;
    }
    function failBalance(address who) external view { revert BalanceLeaked(balanceOf[who]); }
    function transfer(address to, uint256 amount) external returns (bool) {
        move(msg.sender, to, amount); return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount);
        allowance[from][msg.sender] -= amount;
        move(from, to, amount); return true;
    }
    function move(address from, address to, uint256 amount) private {
        require(to != address(0) && balanceOf[from] >= amount);
        balanceOf[from] -= amount; balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}

contract Pair {
    Token public token0;
    Token public token1;
    uint256 private reserve0;
    uint256 private reserve1;
    bool private locked;
    event Sync(uint256 reserve0, uint256 reserve1);
    event Swap(address indexed sender, address indexed to, uint256 amountIn, uint256 amountOut);
    constructor(Token a, Token b) { token0 = a; token1 = b; }
    function getReserves() external view returns (uint256, uint256) { return (reserve0, reserve1); }
    function sync() public {
        require(!locked);
        reserve0 = token0.balanceOf(address(this));
        reserve1 = token1.balanceOf(address(this));
        emit Sync(reserve0, reserve1);
    }
    // One-direction, no-fee constant-product swap; router sends input first.
    function swap(uint256 amountOut, address to) external {
        require(!locked && amountOut > 0 && amountOut < reserve1);
        locked = true;
        token1.transfer(to, amountOut);
        uint256 b0 = token0.balanceOf(address(this));
        uint256 b1 = token1.balanceOf(address(this));
        require(b0 > reserve0 && b0 * b1 >= reserve0 * reserve1);
        uint256 amountIn = b0 - reserve0;
        reserve0 = b0; reserve1 = b1; locked = false;
        emit Sync(b0, b1); emit Swap(msg.sender, to, amountIn, amountOut);
    }
}

contract Router {
    event Done(address indexed user);
    function swap(Pair pair, Token input, uint256 amountIn, uint256 amountOut, address recipient) external {
        input.transferFrom(msg.sender, address(pair), amountIn);
        pair.swap(amountOut, recipient);
        emit Done(msg.sender);
    }
    function readBalance(Token token, address user) external view returns (uint256) {
        return token.balanceOf(user);
    }
    function errorSize(Token token, address user) external view returns (uint256) {
        try token.failBalance(user) { return 999; } catch (bytes memory result) { return result.length; }
    }
    function delegateRead(Token token, address user) external returns (uint256) {
        (bool ok, bytes memory result) = address(token).delegatecall(abi.encodeCall(token.balanceOf, (user)));
        require(ok); return abi.decode(result, (uint256));
    }
    function transferThenRevert(Token token, address to, uint256 amount) external {
        token.transferFrom(msg.sender, to, amount);
        revert();
    }
    function catchTransfer(Token token, address to, uint256 amount) external {
        try token.transfer(to, amount) { } catch { }
        emit Done(msg.sender);
    }
}

contract DebtLedger {
    address private admin;
    address private controller;
    mapping(address => uint256) public debtOf;
    constructor() { admin = msg.sender; }
    function setController(address pool) external { require(msg.sender == admin && controller == address(0)); controller = pool; }
    function add(address user, uint256 amount) external { require(msg.sender == controller); debtOf[user] += amount; }
    function reduce(address user, uint256 amount) external { require(msg.sender == controller); debtOf[user] -= amount; }
}

contract Lending {
    Token private collateralToken;
    Token private debtToken;
    DebtLedger private ledger;
    address private admin;
    uint256 public price = 2;
    mapping(address => uint256) public collateralOf;
    event Supply(address indexed user, uint256 amount);
    event Borrow(address indexed user, uint256 amount);
    event Liquidation(address indexed user, address indexed liquidator, uint256 repaid, uint256 seized);
    constructor(Token collateral, Token debt, DebtLedger book) {
        admin = msg.sender; collateralToken = collateral; debtToken = debt; ledger = book;
    }
    function setPrice(uint256 value) external { require(msg.sender == admin && value > 0); price = value; }
    function supply(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender] += amount; emit Supply(msg.sender, amount);
    }
    function borrow(uint256 amount) external {
        require((ledger.debtOf(msg.sender) + amount) * 2 <= collateralOf[msg.sender] * price);
        ledger.add(msg.sender, amount); debtToken.transfer(msg.sender, amount);
        emit Borrow(msg.sender, amount);
    }
    function health(address user) external view returns (uint256 collateral, uint256 debt, bool liquidatable) {
        collateral = collateralOf[user]; debt = ledger.debtOf(user);
        liquidatable = debt * 100 > collateral * price * 75;
    }
    function liquidate(address user, uint256 repay) external {
        uint256 debt = ledger.debtOf(user);
        require(debt * 100 > collateralOf[user] * price * 75);
        require(repay > 0 && repay <= debt);
        uint256 seize = repay * 110 / (price * 100);
        require(seize <= collateralOf[user]);
        debtToken.transferFrom(msg.sender, address(this), repay);
        ledger.reduce(user, repay); collateralOf[user] -= seize;
        collateralToken.transfer(msg.sender, seize);
        emit Liquidation(user, msg.sender, repay, seize);
    }
}
