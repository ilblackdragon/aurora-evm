// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IBalance { function balanceOf(address) external view returns(uint256); }
contract ProxyData {
    bool private initialized;
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 amount);
    function initialize(address owner, uint256 amount) external {
        require(!initialized); initialized=true; balanceOf[owner]=amount;
    }
    function transfer(address to,uint256 amount) external {
        balanceOf[msg.sender]-=amount; balanceOf[to]+=amount;
        emit Transfer(msg.sender,to,amount);
    }
    function selfBalance(IBalance token) external view returns(uint256) { return token.balanceOf(address(this)); }
}
contract Impostor {
    function pretend(IBalance token,address victim) external view returns(uint256) { return token.balanceOf(victim); }
    function spoofSuffix(address target,address victim) external returns(uint256) {
        (bool ok,bytes memory output)=target.call(abi.encodePacked(abi.encodeWithSignature("balanceOf(address)",victim),victim));
        require(ok);return abi.decode(output,(uint256));
    }
    function delegatedRead(address target,address victim) external returns(uint256) {
        (bool ok,bytes memory output)=target.delegatecall(abi.encodeWithSignature("balanceOf(address)",victim));
        require(ok);return abi.decode(output,(uint256));
    }
    function caught(address target,address victim) external view returns(bool,uint256) {
        (bool ok,bytes memory output)=target.staticcall(abi.encodeWithSignature("balanceOf(address)",victim));
        return(ok,output.length);
    }
}
// Same getter selector, malicious semantics: changing implementation cannot
// silently retain the former implementation's code binding.
contract EvilImplementation {
    function balanceOf(address) external pure returns(uint256) { return 0xdeadbeef; }
}

interface IPair {
    function swap(uint256 amount0,uint256 amount1,address to,bytes calldata data) external;
    function token0() external view returns(address);
    function token1() external view returns(address);
}
interface ITransfer { function transfer(address,uint256) external returns(bool); }
contract FlashImpostor {
    bool public leaked;
    uint256 public leakedLength;
    address private pair;
    function attack(address target,address victim,uint256 amount0,uint256 amount1) external {
        pair=target;
        IPair(target).swap(amount0,amount1,address(this),abi.encode(victim));
    }
    function uniswapV2Call(address,uint256 amount0,uint256 amount1,bytes calldata data) external {
        require(msg.sender==pair);
        (bool ok,bytes memory output)=pair.staticcall(abi.encodeWithSignature("balanceOf(address)",abi.decode(data,(address))));
        leaked=ok; leakedLength=output.length;
        if(amount0>0) require(ITransfer(IPair(pair).token0()).transfer(pair,(amount0*1000+996)/997));
        if(amount1>0) require(ITransfer(IPair(pair).token1()).transfer(pair,(amount1*1000+996)/997));
    }
}
contract RewritingProxy {
    address private immutable implementation;
    address private immutable victim;
    constructor(address target,address owner) { implementation=target; victim=owner; }
    fallback() external {
        bytes memory input=msg.data;
        address owner=victim;
        assembly { mstore(add(input,36),owner) }
        (bool ok,bytes memory output)=implementation.delegatecall(input);
        require(ok);
        assembly { return(add(output,32),mload(output)) }
    }
}
