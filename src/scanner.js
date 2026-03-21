/**
 * Smart Contract Vulnerability Scanner Engine
 * Pattern-based + structural analysis for Solidity source code
 * Detects 13 vulnerability classes with line-level precision
 */

// ─── Vulnerability Registry ────────────────────────────────────────────────────

const VULNERABILITY_CATALOG = [
  {
    id: 'SCS-001',
    name: 'Reentrancy',
    category: 'critical',
    description: 'External call made before state variable is updated, enabling reentrancy attacks.',
    owasp: 'SWC-107',
  },
  {
    id: 'SCS-002',
    name: 'Integer Overflow/Underflow',
    category: 'high',
    description: 'Arithmetic operation without SafeMath or Solidity >=0.8.0 overflow protection.',
    owasp: 'SWC-101',
  },
  {
    id: 'SCS-003',
    name: 'Unchecked External Call',
    category: 'high',
    description: 'Return value of external call (.call, .send, .transfer) is not checked.',
    owasp: 'SWC-104',
  },
  {
    id: 'SCS-004',
    name: 'Access Control',
    category: 'critical',
    description: 'Sensitive function lacks access control (onlyOwner, require, modifier).',
    owasp: 'SWC-105',
  },
  {
    id: 'SCS-005',
    name: 'Timestamp Dependence',
    category: 'medium',
    description: 'block.timestamp used for critical logic; miners can manipulate within ~15s.',
    owasp: 'SWC-116',
  },
  {
    id: 'SCS-006',
    name: 'tx.origin Authentication',
    category: 'critical',
    description: 'tx.origin used for authentication instead of msg.sender; vulnerable to phishing.',
    owasp: 'SWC-115',
  },
  {
    id: 'SCS-007',
    name: 'Delegatecall Injection',
    category: 'critical',
    description: 'delegatecall to user-controlled address can overwrite contract storage.',
    owasp: 'SWC-112',
  },
  {
    id: 'SCS-008',
    name: 'Self-destruct',
    category: 'high',
    description: 'selfdestruct/suicide present; contract can be permanently destroyed.',
    owasp: 'SWC-106',
  },
  {
    id: 'SCS-009',
    name: 'Floating Pragma',
    category: 'low',
    description: 'Compiler version is not locked; may compile with unintended version.',
    owasp: 'SWC-103',
  },
  {
    id: 'SCS-010',
    name: 'Gas Limit / Unbounded Loop',
    category: 'medium',
    description: 'Loop iterates over dynamic array; may exceed block gas limit.',
    owasp: 'SWC-128',
  },
  {
    id: 'SCS-011',
    name: 'Front-running',
    category: 'medium',
    description: 'Pattern susceptible to front-running (approve + transferFrom, price-dependent).',
    owasp: 'SWC-114',
  },
  {
    id: 'SCS-012',
    name: 'Missing Events',
    category: 'low',
    description: 'State-changing function does not emit an event for off-chain tracking.',
    owasp: 'N/A',
  },
  {
    id: 'SCS-013',
    name: 'Unused Variables',
    category: 'info',
    description: 'Storage variable declared but never read; wastes gas on deployment.',
    owasp: 'SWC-131',
  },
];

// ─── Helpers ────────────────────────────────────────────────────────────────────

function getLines(code) {
  return code.split('\n');
}

function stripComments(code) {
  // Remove single-line comments
  let result = code.replace(/\/\/.*$/gm, '');
  // Remove multi-line comments
  result = result.replace(/\/\*[\s\S]*?\*\//g, (match) => {
    // Preserve line count
    return match.split('\n').map(() => '').join('\n');
  });
  return result;
}

function getSolidityVersion(code) {
  const match = code.match(/pragma\s+solidity\s+[\^~>=<]*\s*([\d.]+)/);
  if (!match) return null;
  const parts = match[1].split('.').map(Number);
  return { major: parts[0] || 0, minor: parts[1] || 0, patch: parts[2] || 0 };
}

function isVersionGte(version, major, minor) {
  if (!version) return false;
  if (version.major > major) return true;
  if (version.major === major && version.minor >= minor) return true;
  return false;
}

/**
 * Extract function blocks with their line ranges, names, modifiers, and bodies.
 */
function extractFunctions(code) {
  const lines = getLines(code);
  const functions = [];
  const funcStartRegex = /^\s*function\s+(\w+)\s*\(([^)]*)\)\s*(.*)/;

  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(funcStartRegex);
    if (!match) continue;

    const name = match[1];
    const params = match[2];
    // Gather the full signature (may span multiple lines)
    let signatureLines = lines[i];
    let braceCount = 0;
    let bodyStart = -1;
    let foundOpenBrace = false;

    // Find opening brace
    for (let j = i; j < lines.length; j++) {
      for (const ch of lines[j]) {
        if (ch === '{') {
          if (!foundOpenBrace) {
            foundOpenBrace = true;
            bodyStart = j;
          }
          braceCount++;
        }
        if (ch === '}') braceCount--;
      }
      if (j > i) signatureLines += '\n' + lines[j];
      if (foundOpenBrace && braceCount === 0) {
        const body = lines.slice(bodyStart, j + 1).join('\n');
        const modifiers = signatureLines
          .replace(/\{[\s\S]*/, '')
          .replace(/function\s+\w+\s*\([^)]*\)/, '');
        functions.push({
          name,
          params,
          modifiers: modifiers.trim(),
          startLine: i + 1,
          endLine: j + 1,
          body,
          signatureFull: signatureLines.split('{')[0],
        });
        break;
      }
    }
  }
  return functions;
}

/**
 * Extract state variables (contract-level storage).
 */
function extractStateVariables(code) {
  const lines = getLines(code);
  const vars = [];
  const stateVarRegex = /^\s*(mapping\s*\(.*\)|[\w\[\]]+)\s+(public\s+|private\s+|internal\s+)?([\w]+)\s*[;=]/;
  let insideContract = false;
  let braceDepth = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*(contract|library|interface)\s+/.test(line)) {
      insideContract = true;
    }
    for (const ch of line) {
      if (ch === '{') braceDepth++;
      if (ch === '}') braceDepth--;
    }
    // State vars are at brace depth 1 inside contract
    if (insideContract && braceDepth === 1) {
      const match = line.match(stateVarRegex);
      if (match && !line.trim().startsWith('function') && !line.trim().startsWith('event') && !line.trim().startsWith('modifier') && !line.trim().startsWith('//')) {
        vars.push({
          type: match[1],
          visibility: (match[2] || '').trim(),
          name: match[3],
          line: i + 1,
        });
      }
    }
  }
  return vars;
}

// ─── Detectors ──────────────────────────────────────────────────────────────────

function detectReentrancy(code, lines) {
  const findings = [];
  const functions = extractFunctions(code);

  for (const fn of functions) {
    const bodyLines = fn.body.split('\n');
    let externalCallLine = -1;
    let externalCallAbsLine = -1;

    for (let i = 0; i < bodyLines.length; i++) {
      const line = bodyLines[i];
      const absLine = fn.startLine + i;

      // Detect external calls
      if (/\.(call|send|transfer)\s*[\({]/.test(line) || /\.\w+\{.*value/.test(line)) {
        externalCallLine = i;
        externalCallAbsLine = absLine;
      }

      // After an external call, check for state updates
      if (externalCallLine !== -1 && i > externalCallLine) {
        // State update patterns: variable assignment, mapping update, compound assignment
        const isStateUpdate = (
          (/\b\w+\s*(\[.*\])?\s*=\s*/.test(line) && !line.includes('==') && !/^\s*(bool|uint|int|address|bytes|string|mapping)/.test(line) && !/^\s*(\/\/|require|assert|if|else|for|while|return)/.test(line.trim())) ||
          /\b\w+\s*(\[.*\])?\s*[-+*]=\s*/.test(line)
        );
        if (isStateUpdate) {
          findings.push({
            id: 'SCS-001',
            severity: 'critical',
            title: 'Reentrancy Vulnerability',
            description: `Function '${fn.name}': state variable updated at line ${absLine} after external call at line ${externalCallAbsLine}. An attacker can re-enter the function before state is updated.`,
            line: externalCallAbsLine,
            endLine: absLine,
            recommendation: 'Apply the Checks-Effects-Interactions pattern: update state variables BEFORE making external calls. Consider using OpenZeppelin ReentrancyGuard.',
            confidence: 'high',
          });
          break;
        }
      }
    }
  }
  return findings;
}

function detectIntegerOverflow(code, lines) {
  const findings = [];
  const version = getSolidityVersion(code);

  // Solidity >= 0.8.0 has built-in overflow checks
  if (isVersionGte(version, 0, 8)) return findings;

  const usesSafeMath = /using\s+SafeMath\s+for/i.test(code);
  if (usesSafeMath) return findings;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Detect unchecked arithmetic on uint/int types
    if (/\b(uint|int)\d*\b/.test(line)) {
      if (/[+\-*]\s*=/.test(line) || /=\s*.+\s*[+\-*]\s*\w+/.test(line)) {
        findings.push({
          id: 'SCS-002',
          severity: 'high',
          title: 'Integer Overflow/Underflow',
          description: `Unchecked arithmetic at line ${i + 1}. Solidity version < 0.8.0 without SafeMath.`,
          line: i + 1,
          recommendation: 'Upgrade to Solidity >=0.8.0 or use OpenZeppelin SafeMath library for all arithmetic operations.',
          confidence: 'medium',
        });
      }
    }
  }
  return findings;
}

function detectUncheckedCalls(code, lines) {
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // .call{...}("") or .call("") without bool check
    if (/\.call\s*[\({]/.test(line)) {
      // Check if return value is captured
      const hasBoolCapture = /\(\s*bool\s+\w+/.test(line) || /bool\s+\w+.*=.*\.call/.test(line);
      // Check next few lines for require on the bool
      let isChecked = hasBoolCapture;
      if (hasBoolCapture) {
        const nextLines = lines.slice(i, Math.min(i + 3, lines.length)).join(' ');
        if (/require\s*\(/.test(nextLines) || /if\s*\(\s*!?\s*success/.test(nextLines)) {
          isChecked = true;
        } else {
          isChecked = false;
        }
      }
      if (!isChecked) {
        findings.push({
          id: 'SCS-003',
          severity: 'high',
          title: 'Unchecked External Call',
          description: `Low-level .call() at line ${i + 1} — return value not checked. Silent failures can lead to loss of funds.`,
          line: i + 1,
          recommendation: 'Capture the bool return value and require it: (bool success, ) = addr.call{value: amount}(""); require(success, "Call failed");',
          confidence: 'high',
        });
      }
    }

    // .send() without check
    if (/\.send\s*\(/.test(line)) {
      if (!/require\s*\(.*\.send/.test(line) && !/bool\s+\w+\s*=.*\.send/.test(line) && !/if\s*\(.*\.send/.test(line)) {
        findings.push({
          id: 'SCS-003',
          severity: 'high',
          title: 'Unchecked send()',
          description: `.send() at line ${i + 1} — return value not checked. send() returns false on failure instead of reverting.`,
          line: i + 1,
          recommendation: 'Check the return value: require(addr.send(amount), "Send failed"); or use .transfer() which reverts automatically.',
          confidence: 'high',
        });
      }
    }
  }
  return findings;
}

function detectAccessControl(code, lines) {
  const findings = [];
  const functions = extractFunctions(code);
  const sensitivePatterns = [
    /\bselfdestruct\b/,
    /\bsuicide\b/,
    /\.transfer\s*\(/,
    /\.send\s*\(/,
    /\.call\s*[\({]/,
    /\bowner\s*=/,
    /\badmin\s*=/,
    /\bpaused\s*=/,
    /\bmint\b/i,
    /\bburn\b/i,
    /\bwithdraw\b/i,
    /\bsetPrice\b/,
    /\bsetFee\b/,
    /\bupgrade\b/i,
  ];

  const accessModifiers = [
    'onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyMinter', 'onlyGovernance',
    'onlyAuthorized', 'whenNotPaused', 'initializer',
  ];

  for (const fn of functions) {
    // Skip view/pure, constructor, internal/private
    if (/\b(view|pure)\b/.test(fn.modifiers)) continue;
    if (fn.name === 'constructor' || fn.name === 'receive' || fn.name === 'fallback') continue;
    if (/\b(internal|private)\b/.test(fn.modifiers)) continue;

    const hasSensitiveOp = sensitivePatterns.some((p) => p.test(fn.body));
    if (!hasSensitiveOp) continue;

    const hasAccessControl = accessModifiers.some((m) => fn.modifiers.includes(m) || fn.body.includes(m));
    const hasRequireMsg = /require\s*\(\s*msg\.sender\s*==/.test(fn.body) || /require\s*\(\s*_msgSender\(\)\s*==/.test(fn.body);

    if (!hasAccessControl && !hasRequireMsg) {
      findings.push({
        id: 'SCS-004',
        severity: 'critical',
        title: 'Missing Access Control',
        description: `Function '${fn.name}' (line ${fn.startLine}) performs sensitive operations but has no access control modifier or require(msg.sender == owner).`,
        line: fn.startLine,
        recommendation: 'Add an access control modifier (e.g., onlyOwner) or use require(msg.sender == owner) at the start of the function. Consider OpenZeppelin AccessControl or Ownable.',
        confidence: 'high',
      });
    }
  }
  return findings;
}

function detectTimestampDependence(code, lines) {
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\bblock\.timestamp\b/.test(line) || /\bnow\b/.test(line)) {
      // Check if used in comparison or condition
      if (/(<|>|<=|>=|==)\s*(block\.timestamp|now)/.test(line) || /(block\.timestamp|now)\s*(<|>|<=|>=|==)/.test(line) || /if\s*\(.*\b(block\.timestamp|now)\b/.test(line) || /require\s*\(.*\b(block\.timestamp|now)\b/.test(line)) {
        findings.push({
          id: 'SCS-005',
          severity: 'medium',
          title: 'Timestamp Dependence',
          description: `block.timestamp used in condition at line ${i + 1}. Miners can manipulate timestamps by ~15 seconds.`,
          line: i + 1,
          recommendation: 'Avoid using block.timestamp for critical logic. For time-dependent operations, use block.number or an oracle. Allow a tolerance window if timestamps must be used.',
          confidence: 'medium',
        });
      }
    }
  }
  return findings;
}

function detectTxOrigin(code, lines) {
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\btx\.origin\b/.test(line)) {
      if (/require\s*\(.*tx\.origin/.test(line) || /if\s*\(.*tx\.origin/.test(line) || /==\s*tx\.origin/.test(line) || /tx\.origin\s*==/.test(line)) {
        findings.push({
          id: 'SCS-006',
          severity: 'critical',
          title: 'tx.origin Authentication',
          description: `tx.origin used for authentication at line ${i + 1}. A malicious contract can trick the owner into calling it, passing the tx.origin check.`,
          line: i + 1,
          recommendation: 'Replace tx.origin with msg.sender for authentication. tx.origin should only be used for very specific use cases like preventing contracts from calling a function.',
          confidence: 'high',
        });
      }
    }
  }
  return findings;
}

function detectDelegatecall(code, lines) {
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\.delegatecall\s*\(/.test(line)) {
      // Check if the target is user-controlled (parameter-based)
      const functions = extractFunctions(code);
      let isInFunction = false;
      let funcParams = '';
      for (const fn of functions) {
        if (i + 1 >= fn.startLine && i + 1 <= fn.endLine) {
          isInFunction = true;
          funcParams = fn.params;
          break;
        }
      }

      const severity = funcParams.includes('address') ? 'critical' : 'high';
      findings.push({
        id: 'SCS-007',
        severity,
        title: 'Delegatecall Usage',
        description: `delegatecall at line ${i + 1}${funcParams.includes('address') ? ' with address parameter — target may be user-controlled' : ''}. delegatecall executes code in the context of the calling contract, allowing storage manipulation.`,
        line: i + 1,
        recommendation: 'Ensure the delegatecall target is a trusted, immutable address. Never allow user input to determine the delegatecall target. Use OpenZeppelin Proxy patterns for upgradeable contracts.',
        confidence: severity === 'critical' ? 'high' : 'medium',
      });
    }
  }
  return findings;
}

function detectSelfdestruct(code, lines) {
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\b(selfdestruct|suicide)\s*\(/.test(line)) {
      findings.push({
        id: 'SCS-008',
        severity: 'high',
        title: 'Self-destruct Present',
        description: `selfdestruct at line ${i + 1}. This permanently destroys the contract and sends remaining ETH to the specified address. If access control is missing, anyone can destroy the contract.`,
        line: i + 1,
        recommendation: 'Remove selfdestruct if not absolutely necessary. If needed, ensure it is protected by strict access control and a timelock/multisig. Note: selfdestruct is deprecated in newer EVM versions.',
        confidence: 'high',
      });
    }
  }
  return findings;
}

function detectFloatingPragma(code, lines) {
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*pragma\s+solidity\s+/.test(line)) {
      if (/[\^~>]/.test(line) || />=.*</.test(line)) {
        findings.push({
          id: 'SCS-009',
          severity: 'low',
          title: 'Floating Pragma',
          description: `Compiler version not locked at line ${i + 1}. Using "${line.trim()}" may compile with different compiler versions, leading to unexpected behavior.`,
          line: i + 1,
          recommendation: 'Lock the pragma to a specific version: pragma solidity 0.8.20; This ensures consistent compilation behavior.',
          confidence: 'high',
        });
      }
    }
  }
  return findings;
}

function detectGasLimitIssues(code, lines) {
  const findings = [];
  const functions = extractFunctions(code);

  for (const fn of functions) {
    const bodyLines = fn.body.split('\n');
    for (let i = 0; i < bodyLines.length; i++) {
      const line = bodyLines[i];
      const absLine = fn.startLine + i;

      // for loop iterating over storage array .length
      if (/for\s*\(.*;\s*\w+\s*<\s*\w+\.length\s*;/.test(line) || /for\s*\(.*;\s*\w+\s*<\s*\w+\[.*\]\.length\s*;/.test(line)) {
        findings.push({
          id: 'SCS-010',
          severity: 'medium',
          title: 'Unbounded Loop',
          description: `Loop at line ${absLine} in '${fn.name}' iterates over dynamic array length. If the array grows large, the transaction will exceed the block gas limit and revert.`,
          line: absLine,
          recommendation: 'Implement pagination or limit the maximum iterations. Consider using a mapping instead of iterating over arrays, or process items in batches across multiple transactions.',
          confidence: 'medium',
        });
      }

      // while(true) or unbounded while
      if (/while\s*\(\s*true\s*\)/.test(line)) {
        findings.push({
          id: 'SCS-010',
          severity: 'high',
          title: 'Infinite Loop Risk',
          description: `Potentially infinite loop at line ${absLine} in '${fn.name}'.`,
          line: absLine,
          recommendation: 'Add a bounded counter or break condition that is guaranteed to terminate.',
          confidence: 'medium',
        });
      }
    }
  }
  return findings;
}

function detectFrontRunning(code, lines) {
  const findings = [];

  const hasApprove = /function\s+approve\s*\(/.test(code);
  const hasTransferFrom = /function\s+transferFrom\s*\(/.test(code) || /\.transferFrom\s*\(/.test(code);

  if (hasApprove && hasTransferFrom) {
    // Check if increaseAllowance/decreaseAllowance exist (mitigation)
    const hasMitigation = /function\s+(increaseAllowance|decreaseAllowance)\s*\(/.test(code);
    if (!hasMitigation) {
      // Find approve function line
      for (let i = 0; i < lines.length; i++) {
        if (/function\s+approve\s*\(/.test(lines[i])) {
          findings.push({
            id: 'SCS-011',
            severity: 'medium',
            title: 'Front-running: Approve Race Condition',
            description: `approve() at line ${i + 1} is vulnerable to the approve/transferFrom front-running attack. An attacker can front-run an allowance change to spend both old and new allowances.`,
            line: i + 1,
            recommendation: 'Implement increaseAllowance() and decreaseAllowance() functions, or require the current allowance to be 0 before setting a new value. Use OpenZeppelin ERC20 which includes these mitigations.',
            confidence: 'medium',
          });
          break;
        }
      }
    }
  }

  // Detect price-dependent operations without commit-reveal
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\b(price|rate|amount)\s*=\s*/.test(line) && /\bmsg\.value\b/.test(line)) {
      findings.push({
        id: 'SCS-011',
        severity: 'medium',
        title: 'Front-running: Price Manipulation',
        description: `Price-dependent calculation with msg.value at line ${i + 1}. Transactions are visible in the mempool before mining.`,
        line: i + 1,
        recommendation: 'Implement a commit-reveal scheme, use a minimum output amount parameter (slippage protection), or use Flashbots/private transactions.',
        confidence: 'low',
      });
    }
  }
  return findings;
}

function detectMissingEvents(code, lines) {
  const findings = [];
  const functions = extractFunctions(code);

  // Collect all event names
  const eventNames = [];
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/event\s+(\w+)\s*\(/);
    if (match) eventNames.push(match[1]);
  }

  for (const fn of functions) {
    // Skip view/pure/internal/private
    if (/\b(view|pure|internal|private)\b/.test(fn.modifiers)) continue;
    if (fn.name === 'constructor') continue;

    // Check if function modifies state
    const stateChangePatterns = [
      /\b\w+\s*(\[.*\])?\s*=\s*(?!=)/,    // assignment
      /\b\w+\s*(\[.*\])?\s*\+=\s*/,         // compound assignment
      /\b\w+\s*(\[.*\])?\s*-=\s*/,
      /\.push\s*\(/,
      /\.pop\s*\(/,
      /delete\s+/,
    ];

    const modifiesState = stateChangePatterns.some((p) => p.test(fn.body));
    if (!modifiesState) continue;

    // Check if any emit is in the function body
    const hasEmit = /\bemit\s+\w+\s*\(/.test(fn.body);
    if (!hasEmit) {
      findings.push({
        id: 'SCS-012',
        severity: 'low',
        title: 'Missing Event Emission',
        description: `Function '${fn.name}' (line ${fn.startLine}) modifies state but does not emit an event. Off-chain services cannot track this change.`,
        line: fn.startLine,
        recommendation: 'Define and emit an event for every state-changing operation. This enables off-chain indexing (e.g., The Graph, Etherscan) and improves transparency.',
        confidence: 'medium',
      });
    }
  }
  return findings;
}

function detectUnusedVariables(code, lines) {
  const findings = [];
  const stateVars = extractStateVariables(code);
  const strippedCode = stripComments(code);

  for (const v of stateVars) {
    // Count occurrences of the variable name (word boundary)
    const regex = new RegExp(`\\b${v.name}\\b`, 'g');
    const matches = strippedCode.match(regex);
    // If only 1 occurrence (the declaration itself), it's unused
    if (matches && matches.length <= 1) {
      findings.push({
        id: 'SCS-013',
        severity: 'info',
        title: 'Unused State Variable',
        description: `State variable '${v.name}' (${v.type}) declared at line ${v.line} is never used. This wastes storage gas on deployment.`,
        line: v.line,
        recommendation: `Remove the unused variable '${v.name}' to save deployment gas. If it is planned for future use, consider commenting it out.`,
        confidence: 'medium',
      });
    }
  }
  return findings;
}

// ─── Gas Analysis ───────────────────────────────────────────────────────────────

function analyzeGas(code) {
  const lines = getLines(code);
  const suggestions = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Use calldata instead of memory for external function params
    if (/function\s+\w+\s*\(.*\bmemory\b/.test(line) && /\bexternal\b/.test(line)) {
      suggestions.push({
        line: i + 1,
        category: 'gas-optimization',
        title: 'Use calldata instead of memory',
        description: 'External function parameters using memory are copied to memory. Use calldata for read-only parameters to save gas.',
        estimatedSaving: '~200-2000 gas per call',
      });
    }

    // Use uint256 instead of smaller uints (packing exception)
    if (/\b(uint8|uint16|uint32|uint64|uint128)\b/.test(line) && !/struct\b/.test(lines[Math.max(0, i - 5)])) {
      suggestions.push({
        line: i + 1,
        category: 'gas-optimization',
        title: 'Consider uint256 for standalone variables',
        description: 'The EVM operates on 256-bit words. Smaller uint types require extra gas for packing/unpacking unless in a struct.',
        estimatedSaving: '~3-20 gas per operation',
      });
    }

    // Use != 0 instead of > 0 for unsigned integers
    if (/require\s*\(.*>\s*0/.test(line) && /uint/.test(line)) {
      suggestions.push({
        line: i + 1,
        category: 'gas-optimization',
        title: 'Use != 0 instead of > 0',
        description: 'For unsigned integers, != 0 is cheaper than > 0.',
        estimatedSaving: '~6 gas per check',
      });
    }

    // ++i is cheaper than i++
    if (/\bi\+\+/.test(line)) {
      suggestions.push({
        line: i + 1,
        category: 'gas-optimization',
        title: 'Use ++i instead of i++',
        description: 'Pre-increment (++i) is cheaper than post-increment (i++) as it avoids a temporary variable.',
        estimatedSaving: '~5 gas per iteration',
      });
    }

    // Cache array length in loops
    if (/for\s*\(.*;\s*\w+\s*<\s*\w+\.length\s*;/.test(line)) {
      suggestions.push({
        line: i + 1,
        category: 'gas-optimization',
        title: 'Cache array length outside loop',
        description: 'Reading array.length on each iteration costs extra gas. Cache it: uint256 len = arr.length;',
        estimatedSaving: '~100 gas per iteration',
      });
    }

    // Use custom errors instead of require strings (Solidity >= 0.8.4)
    if (/require\s*\(.*,\s*"/.test(line)) {
      suggestions.push({
        line: i + 1,
        category: 'gas-optimization',
        title: 'Use custom errors instead of revert strings',
        description: 'Custom errors (error InsufficientBalance()) are cheaper than require() with string messages since Solidity 0.8.4.',
        estimatedSaving: '~50 gas per revert + deployment gas savings',
      });
    }

    // Pack storage variables
    if (/^\s*(uint\d+|bool|address|bytes\d+)\s+(public\s+|private\s+)?(\w+)\s*;/.test(line)) {
      suggestions.push({
        line: i + 1,
        category: 'gas-optimization',
        title: 'Consider storage variable packing',
        description: 'Group smaller-than-32-byte variables together to share storage slots. Order: address(20) + bool(1) + uint8(1) fit in one slot.',
        estimatedSaving: '~20,000 gas per saved storage slot (SSTORE)',
      });
    }
  }

  // Deduplicate by line + title
  const seen = new Set();
  return suggestions.filter((s) => {
    const key = `${s.line}:${s.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── Main Scanner ───────────────────────────────────────────────────────────────

const CRITICAL_CHECKS = ['SCS-001', 'SCS-004', 'SCS-006', 'SCS-007', 'SCS-003'];

function scan(code, options = {}) {
  const stripped = stripComments(code);
  const lines = getLines(stripped);
  const quickMode = options.quick || false;

  const detectors = [
    detectReentrancy,
    detectIntegerOverflow,
    detectUncheckedCalls,
    detectAccessControl,
    detectTimestampDependence,
    detectTxOrigin,
    detectDelegatecall,
    detectSelfdestruct,
    detectFloatingPragma,
    detectGasLimitIssues,
    detectFrontRunning,
    detectMissingEvents,
    detectUnusedVariables,
  ];

  let allFindings = [];
  for (const detector of detectors) {
    try {
      const results = detector(stripped, lines);
      allFindings.push(...results);
    } catch (err) {
      // Detector failure should not break the scan
      allFindings.push({
        id: 'SCS-ERR',
        severity: 'info',
        title: 'Detector Error',
        description: `Internal error in ${detector.name}: ${err.message}`,
        line: 0,
        recommendation: 'This is an internal scanner issue. Please report it.',
        confidence: 'low',
      });
    }
  }

  if (quickMode) {
    allFindings = allFindings.filter((f) => CRITICAL_CHECKS.includes(f.id));
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

  return {
    findings: allFindings,
    metadata: {
      linesOfCode: lines.length,
      solidityVersion: getSolidityVersion(code),
      functionsAnalyzed: extractFunctions(code).length,
      stateVariables: extractStateVariables(code).length,
      scanMode: quickMode ? 'quick' : 'full',
      detectorCount: quickMode ? CRITICAL_CHECKS.length : detectors.length,
    },
    gasAnalysis: quickMode ? [] : analyzeGas(code),
  };
}

module.exports = {
  scan,
  analyzeGas,
  VULNERABILITY_CATALOG,
  CRITICAL_CHECKS,
};
