/**
 * Smart Contract Scanner — MCP Server (Model Context Protocol)
 * Exposes scanner capabilities as MCP tools for AI assistants
 */

const { scan, analyzeGas, VULNERABILITY_CATALOG } = require('./scanner');
const { generateReport } = require('./report');

// ─── MCP Protocol Implementation ───────────────────────────────────────────────

class MCPServer {
  constructor() {
    this.name = 'smart-contract-scanner';
    this.version = '1.0.0';
    this.tools = this._defineTools();
  }

  _defineTools() {
    return [
      {
        name: 'scan_contract',
        description: 'Perform a full security audit on Solidity smart contract source code. Detects 13 vulnerability classes including reentrancy, access control, integer overflow, and more. Returns a detailed report with risk score, findings by severity, and recommendations.',
        inputSchema: {
          type: 'object',
          properties: {
            code: {
              type: 'string',
              description: 'Solidity smart contract source code to analyze',
            },
          },
          required: ['code'],
        },
      },
      {
        name: 'quick_scan_contract',
        description: 'Quick security scan checking only the top 5 critical vulnerability patterns: reentrancy, access control, tx.origin, delegatecall, and unchecked calls.',
        inputSchema: {
          type: 'object',
          properties: {
            code: {
              type: 'string',
              description: 'Solidity smart contract source code to analyze',
            },
          },
          required: ['code'],
        },
      },
      {
        name: 'analyze_gas',
        description: 'Analyze Solidity code for gas optimization opportunities. Returns specific suggestions with estimated gas savings.',
        inputSchema: {
          type: 'object',
          properties: {
            code: {
              type: 'string',
              description: 'Solidity smart contract source code to analyze',
            },
          },
          required: ['code'],
        },
      },
      {
        name: 'list_vulnerabilities',
        description: 'List all vulnerability types that the scanner can detect, with descriptions and severity levels.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async handleRequest(request) {
    const { method, params } = request;

    switch (method) {
      case 'initialize':
        return this._handleInitialize();
      case 'tools/list':
        return this._handleToolsList();
      case 'tools/call':
        return this._handleToolCall(params);
      default:
        return { error: { code: -32601, message: `Method not found: ${method}` } };
    }
  }

  _handleInitialize() {
    return {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: {
        name: this.name,
        version: this.version,
      },
    };
  }

  _handleToolsList() {
    return { tools: this.tools };
  }

  _handleToolCall(params) {
    const { name, arguments: args } = params;

    try {
      switch (name) {
        case 'scan_contract': {
          if (!args.code) {
            return this._errorResult('Missing required parameter: code');
          }
          const scanResult = scan(args.code, { quick: false });
          const report = generateReport(scanResult);
          return this._successResult(report);
        }

        case 'quick_scan_contract': {
          if (!args.code) {
            return this._errorResult('Missing required parameter: code');
          }
          const scanResult = scan(args.code, { quick: true });
          const report = generateReport(scanResult);
          return this._successResult(report);
        }

        case 'analyze_gas': {
          if (!args.code) {
            return this._errorResult('Missing required parameter: code');
          }
          const suggestions = analyzeGas(args.code);
          return this._successResult({
            gasOptimization: { suggestions, totalSuggestions: suggestions.length },
          });
        }

        case 'list_vulnerabilities': {
          return this._successResult({
            vulnerabilities: VULNERABILITY_CATALOG,
            totalDetectors: VULNERABILITY_CATALOG.length,
          });
        }

        default:
          return this._errorResult(`Unknown tool: ${name}`);
      }
    } catch (err) {
      return this._errorResult(`Tool execution failed: ${err.message}`);
    }
  }

  _successResult(data) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(data, null, 2),
        },
      ],
    };
  }

  _errorResult(message) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ error: message }),
        },
      ],
      isError: true,
    };
  }
}

// ─── Stdio Transport ────────────────────────────────────────────────────────────

function startStdioServer() {
  const server = new MCPServer();
  let buffer = '';

  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    buffer += chunk;
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const request = JSON.parse(line);
        const response = server.handleRequest(request);
        Promise.resolve(response).then((result) => {
          const output = JSON.stringify({
            jsonrpc: '2.0',
            id: request.id,
            result,
          });
          process.stdout.write(output + '\n');
        });
      } catch (err) {
        const errorResponse = JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error' },
        });
        process.stdout.write(errorResponse + '\n');
      }
    }
  });

  process.stderr.write('Smart Contract Scanner MCP Server started (stdio)\n');
}

// ─── Entry Point ────────────────────────────────────────────────────────────────

if (require.main === module) {
  startStdioServer();
}

module.exports = { MCPServer };
