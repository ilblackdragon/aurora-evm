// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IArbToken {
    function balanceOf(address) external view returns (uint256);
    function approve(address,uint256) external returns (bool);
    function transfer(address,uint256) external returns (bool);
}
interface IFlashPool {
    function flashLoanSimple(address,address,uint256,bytes calldata,uint16) external;
}
interface IArbRouter {
    function swapExactTokensForTokens(uint256,uint256,address[] calldata,address,uint256)
        external returns (uint256[] memory);
}

// Test receiver: no prefunding, two real V2 venues, Aave repayment before payout.
contract FlashArbitrage {
    address private immutable pool;
    address private immutable buyRouter;
    address private immutable sellRouter;
    address private immutable asset;
    address private immutable other;
    address private activeOwner;
    uint256 private minimumProfit;
    mapping(address => uint256) public profits;
    event Profit(address indexed owner,uint256 amount);

    constructor(address p,address buy,address sell,address cash,address intermediate) {
        pool=p; buyRouter=buy; sellRouter=sell; asset=cash; other=intermediate;
    }
    function run(address owner,uint256 amount,uint256 minProfit) external {
        require(msg.sender==owner && activeOwner==address(0));
        activeOwner=owner; minimumProfit=minProfit;
        IFlashPool(pool).flashLoanSimple(address(this),asset,amount,"",0);
        uint256 profit=IArbToken(asset).balanceOf(address(this));
        require(profit>=minProfit);
        profits[owner]+=profit;
        activeOwner=address(0);
        require(IArbToken(asset).transfer(owner,profit));
        emit Profit(owner,profit);
    }
    function executeOperation(address token,uint256 amount,uint256 premium,address initiator,bytes calldata)
        external returns (bool)
    {
        require(msg.sender==pool && initiator==address(this) && activeOwner!=address(0) && token==asset);
        address[] memory path=new address[](2);
        path[0]=asset; path[1]=other;
        require(IArbToken(asset).approve(buyRouter,amount));
        uint256[] memory bought=IArbRouter(buyRouter).swapExactTokensForTokens(amount,0,path,address(this),block.timestamp);
        path[0]=other; path[1]=asset;
        require(IArbToken(other).approve(sellRouter,bought[1]));
        uint256[] memory sold=IArbRouter(sellRouter).swapExactTokensForTokens(bought[1],0,path,address(this),block.timestamp);
        require(sold[1]>=amount+premium+minimumProfit);
        require(IArbToken(asset).approve(pool,amount+premium));
        return true;
    }
}
