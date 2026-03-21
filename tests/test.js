/**
 * Smart Contract Scanner — Test Suite
 * Tests with real vulnerable Solidity contracts
 */

const { scan, analyzeGas, VULNERABILITY_CATALOG } = require('../src/scanner');
const { generateReport, calculateRiskScore } = require('../src/report');

let passed = 0;
let failed = 0;

function assert(condition, testName) {
  if (condition) {
    console.log(`  PASS  ${testName}`);
    passed++;
  } else {
    console.log(`  FAIL  ${testName}`);
    failed++;
  }
}

function findById(findings, id) {
  return findings.filter((f) => f.id === id);
}

// ─── Sample Contracts ───────────────────────────────────────────────────────────

const VULNERABLE_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;
    uint256 unusedCounter;
    bool public paused;

    constructor() {
        owner = msg.sender;
    }

    // Reentrancy vulnerability: external call before state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    // Missing access control on sensitive function
    function destroyContract() public {
        selfdestruct(payable(msg.sender));
    }

    // tx.origin for auth
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner);
        owner = newOwner;
    }

    // Unchecked external call
    function sendReward(address payable recipient, uint256 amount) public {
        recipient.send(amount);
    }

    // Timestamp dependence
    function isLocked() public view returns (bool) {
        if (block.timestamp > 1700000000) {
            return false;
        }
        return true;
    }

    // Unbounded loop
    function distributeAll(address[] memory recipients) public {
        for (uint i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(1 ether);
        }
    }

    // Front-running: approve without increaseAllowance
    function approve(address spender, uint256 amount) public returns (bool) {
        // allowances[msg.sender][spender] = amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        return true;
    }

    // Missing events on state changes
    function deposit() public payable {
        balances[msg.sender] += amount;
        totalDeposits += amount;
    }

    // Integer overflow (pre-0.8.0, no SafeMath)
    function addBalance(uint256 amount) public {
        uint256 newBal = balances[msg.sender] + amount;
        balances[msg.sender] = newBal;
    }

    receive() external payable {}
}
`;

const SAFE_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeVault is Ownable, ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function pause() external onlyOwner {
        // pause logic
    }
}
`;

const DELEGATECALL_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ProxyDangerous {
    address public implementation;
    address public owner;

    function setImplementation(address _impl) public {
        implementation = _impl;
    }

    function execute(address target, bytes memory data) public {
        (bool success, ) = target.delegatecall(data);
        require(success);
    }
}
`;

// ─── Tests ──────────────────────────────────────────────────────────────────────

console.log('\n========================================');
console.log('  Smart Contract Scanner — Test Suite');
console.log('========================================\n');

// Test 1: Vulnerability Catalog
console.log('[Catalog]');
assert(VULNERABILITY_CATALOG.length === 13, 'Should have 13 vulnerability detectors');

// Test 2: Full scan on vulnerable contract
console.log('\n[Full Scan — Vulnerable Contract]');
const vulnResult = scan(VULNERABLE_CONTRACT);
const vulnFindings = vulnResult.findings;

assert(vulnFindings.length > 0, 'Should find vulnerabilities');
assert(findById(vulnFindings, 'SCS-001').length > 0, 'Detect reentrancy');
assert(findById(vulnFindings, 'SCS-002').length > 0, 'Detect integer overflow (pre-0.8.0)');
assert(findById(vulnFindings, 'SCS-003').length > 0, 'Detect unchecked external call');
assert(findById(vulnFindings, 'SCS-004').length > 0, 'Detect missing access control');
assert(findById(vulnFindings, 'SCS-005').length > 0, 'Detect timestamp dependence');
assert(findById(vulnFindings, 'SCS-006').length > 0, 'Detect tx.origin auth');
assert(findById(vulnFindings, 'SCS-008').length > 0, 'Detect selfdestruct');
assert(findById(vulnFindings, 'SCS-009').length > 0, 'Detect floating pragma');
assert(findById(vulnFindings, 'SCS-010').length > 0, 'Detect unbounded loop');
assert(findById(vulnFindings, 'SCS-011').length > 0, 'Detect front-running');
assert(findById(vulnFindings, 'SCS-012').length > 0, 'Detect missing events');
assert(findById(vulnFindings, 'SCS-013').length > 0, 'Detect unused variables');

// Test 3: Metadata
console.log('\n[Metadata]');
assert(vulnResult.metadata.scanMode === 'full', 'Scan mode should be full');
assert(vulnResult.metadata.linesOfCode > 0, 'Should count lines');
assert(vulnResult.metadata.functionsAnalyzed > 0, 'Should count functions');
assert(vulnResult.metadata.solidityVersion !== null, 'Should detect solidity version');

// Test 4: Report generation
console.log('\n[Report Generation]');
const vulnReport = generateReport(vulnResult);
assert(vulnReport.report.overview.riskScore > 50, 'Vulnerable contract should have high risk score');
assert(vulnReport.report.overview.riskLevel !== 'Safe', 'Should not be rated Safe');
assert(vulnReport.report.recommendations.length > 0, 'Should have recommendations');
assert(vulnReport.report.findings.total > 0, 'Report should include findings');

// Test 5: Safe contract scan
console.log('\n[Full Scan — Safe Contract]');
const safeResult = scan(SAFE_CONTRACT);
const safeFindings = safeResult.findings;
const safeReport = generateReport(safeResult);

assert(findById(safeFindings, 'SCS-001').length === 0, 'No reentrancy in safe contract');
assert(findById(safeFindings, 'SCS-006').length === 0, 'No tx.origin in safe contract');
assert(safeReport.report.overview.riskScore < vulnReport.report.overview.riskScore, 'Safe contract should have lower risk score');

// Test 6: Quick scan
console.log('\n[Quick Scan]');
const quickResult = scan(VULNERABLE_CONTRACT, { quick: true });
assert(quickResult.metadata.scanMode === 'quick', 'Should be quick mode');
assert(quickResult.findings.length < vulnFindings.length, 'Quick scan should find fewer issues');
assert(quickResult.findings.every((f) => ['SCS-001', 'SCS-003', 'SCS-004', 'SCS-006', 'SCS-007'].includes(f.id)), 'Quick scan should only include critical checks');

// Test 7: Gas analysis
console.log('\n[Gas Analysis]');
const gasResult = analyzeGas(VULNERABLE_CONTRACT);
assert(gasResult.length > 0, 'Should have gas optimization suggestions');
assert(gasResult[0].estimatedSaving !== undefined, 'Suggestions should include estimated savings');

// Test 8: Delegatecall detection
console.log('\n[Delegatecall Detection]');
const delegateResult = scan(DELEGATECALL_CONTRACT);
assert(findById(delegateResult.findings, 'SCS-007').length > 0, 'Detect delegatecall vulnerability');
assert(findById(delegateResult.findings, 'SCS-007')[0].severity === 'critical', 'Delegatecall with address param should be critical');

// Test 9: Severity ordering
console.log('\n[Severity Ordering]');
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
let isOrdered = true;
for (let i = 1; i < vulnFindings.length; i++) {
  if (severityOrder[vulnFindings[i].severity] < severityOrder[vulnFindings[i - 1].severity]) {
    isOrdered = false;
    break;
  }
}
assert(isOrdered, 'Findings should be sorted by severity (critical first)');

// Test 10: Empty contract
console.log('\n[Edge Cases]');
const emptyResult = scan('');
assert(emptyResult.findings.length === 0, 'Empty code should have no findings');

const nonsenseResult = scan('not solidity at all');
assert(nonsenseResult.findings.length === 0, 'Non-solidity code should not crash');

// ─── Summary ────────────────────────────────────────────────────────────────────

console.log('\n========================================');
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log('========================================\n');

if (failed > 0) {
  console.log('Some tests failed!');
  process.exit(1);
} else {
  console.log('All tests passed!');
}

// Print sample report overview
console.log('\n--- Sample Report Overview ---');
console.log(`Risk Score: ${vulnReport.report.overview.riskScore}/100`);
console.log(`Risk Level: ${vulnReport.report.overview.riskLevel}`);
console.log(`Total Findings: ${vulnReport.report.findings.total}`);
console.log(`  Critical: ${vulnReport.report.overview.summary.critical}`);
console.log(`  High: ${vulnReport.report.overview.summary.high}`);
console.log(`  Medium: ${vulnReport.report.overview.summary.medium}`);
console.log(`  Low: ${vulnReport.report.overview.summary.low}`);
console.log(`  Info: ${vulnReport.report.overview.summary.info}`);
console.log(`Gas Suggestions: ${vulnReport.report.gasOptimization.totalSuggestions}`);
