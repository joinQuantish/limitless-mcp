/**
 * MCP HTTP Handler for Limitless MCP
 * Handles authentication, request validation, and tool execution
 *
 * Implements the MCP JSON-RPC 2.0 protocol:
 * - initialize: Returns server capabilities
 * - tools/list: Returns available tools
 * - tools/call: Executes a tool with authentication
 */

import { Request, Response } from 'express';
import { getApiKeyService } from '../services/apikey.service.js';
import { limitlessTools, executeTool, unauthenticatedTools, ToolContext } from './tools.js';

interface MCPRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
  };
}

/**
 * MCP HTTP Handler class
 * Singleton pattern for consistent request handling
 */
export class MCPHttpHandler {
  /**
   * Handle MCP requests
   * Main entry point for POST /mcp
   */
  async handleRequest(req: Request, res: Response): Promise<void> {
    const body: MCPRequest = req.body;

    // Validate JSON-RPC format
    if (!body || body.jsonrpc !== '2.0' || !body.method) {
      res.status(400).json({
        jsonrpc: '2.0',
        id: body?.id || null,
        error: {
          code: -32600,
          message: 'Invalid JSON-RPC request',
        },
      });
      return;
    }

    try {
      // Handle different MCP methods
      switch (body.method) {
        case 'initialize':
          res.json({
            jsonrpc: '2.0',
            id: body.id,
            result: {
              protocolVersion: '2024-11-05',
              serverInfo: {
                name: 'quantish-limitless-mcp',
                version: '1.0.0',
              },
              capabilities: {
                tools: {},
              },
            },
          });
          return;

        case 'tools/list':
          res.json({
            jsonrpc: '2.0',
            id: body.id,
            result: {
              tools: limitlessTools,
            },
          });
          return;

        case 'tools/call':
          await this.handleToolCall(req, res, body);
          return;

        default:
          res.json({
            jsonrpc: '2.0',
            id: body.id,
            error: {
              code: -32601,
              message: `Method not found: ${body.method}`,
            },
          });
          return;
      }
    } catch (error: unknown) {
      console.error('MCP Error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Internal error';
      res.json({
        jsonrpc: '2.0',
        id: body.id,
        error: {
          code: -32603,
          message: errorMessage,
        },
      });
    }
  }

  /**
   * Handle tool calls with authentication
   * Validates API key for protected tools, then executes the tool
   */
  private async handleToolCall(req: Request, res: Response, body: MCPRequest): Promise<void> {
    const { name, arguments: args } = body.params || {};

    if (!name) {
      res.json({
        jsonrpc: '2.0',
        id: body.id,
        error: {
          code: -32602,
          message: 'Tool name required',
        },
      });
      return;
    }

    // Check if tool exists
    const tool = limitlessTools.find((t) => t.name === name);
    if (!tool) {
      res.json({
        jsonrpc: '2.0',
        id: body.id,
        error: {
          code: -32602,
          message: `Unknown tool: ${name}`,
        },
      });
      return;
    }

    // Build context
    const context: ToolContext = {};

    // Check if this tool requires authentication
    const requiresAuth = !unauthenticatedTools.includes(name);

    console.log(`[MCP] Tool call: ${name}, requires auth: ${requiresAuth}`);

    if (requiresAuth) {
      // Require authentication
      const apiKey = req.headers['x-api-key'] as string;

      if (!apiKey) {
        res.json({
          jsonrpc: '2.0',
          id: body.id,
          error: {
            code: -32000,
            message: 'API key required. Provide x-api-key header.',
          },
        });
        return;
      }

      const apiKeyService = getApiKeyService();
      const validation = await apiKeyService.validateApiKey(apiKey);

      if (!validation.isValid) {
        res.json({
          jsonrpc: '2.0',
          id: body.id,
          error: {
            code: -32000,
            message: validation.message || 'Invalid API key',
          },
        });
        return;
      }

      context.userId = validation.userId;

      // Optional HMAC validation for extra security
      const hmacSignature = req.headers['x-hmac-signature'] as string;
      const hmacTimestamp = req.headers['x-hmac-timestamp'] as string;

      if (hmacSignature && hmacTimestamp && validation.keyRecord) {
        const apiSecret = await apiKeyService.getApiSecret(validation.keyRecord.id);
        if (apiSecret) {
          const bodyString = JSON.stringify(req.body);
          const signatureData = `${hmacTimestamp}:${req.method}:${req.originalUrl}:${bodyString}`;
          const isValidHmac = apiKeyService.validateHmacSignature(
            apiSecret,
            signatureData,
            hmacSignature
          );

          if (!isValidHmac) {
            res.json({
              jsonrpc: '2.0',
              id: body.id,
              error: {
                code: -32000,
                message: 'Invalid HMAC signature',
              },
            });
            return;
          }
        }
      }
    }

    try {
      const result = await executeTool(name, args || {}, context);

      res.json({
        jsonrpc: '2.0',
        id: body.id,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        },
      });
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Tool execution failed';
      console.error(`Tool ${name} error:`, error);
      res.json({
        jsonrpc: '2.0',
        id: body.id,
        error: {
          code: -32603,
          message: errorMessage,
        },
      });
    }
  }
}

// Singleton
let handlerInstance: MCPHttpHandler | null = null;

export function getMCPHttpHandler(): MCPHttpHandler {
  if (!handlerInstance) {
    handlerInstance = new MCPHttpHandler();
  }
  return handlerInstance;
}
