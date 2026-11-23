package tools

import "encoding/json"

// Input schemas are written explicitly (rather than inferred from Go structs)
// so that the published schema carries defaults and numeric bounds without
// importing the SDK's JSON Schema implementation as a direct dependency.

const listWorkspacesSchema = `{
  "type": "object",
  "properties": {},
  "additionalProperties": false
}`

const getFileTreeSchema = `{
  "type": "object",
  "properties": {
    "workspace": { "type": "string", "description": "Workspace name (optional if only one workspace is authorized)." },
    "path": { "type": "string", "default": "", "description": "Relative directory path inside the workspace." },
    "depth": { "type": "integer", "default": 3, "minimum": 1, "maximum": 10, "description": "Max traversal depth." },
    "cursor": { "type": "string", "default": "", "description": "Pagination cursor returned by a previous truncated response." }
  },
  "additionalProperties": false
}`

const searchCodeSchema = `{
  "type": "object",
  "properties": {
    "workspace": { "type": "string", "description": "Workspace name (optional if only one workspace is authorized)." },
    "query": { "type": "string", "minLength": 1, "description": "Search pattern (regex or plain text)." },
    "path": { "type": "string", "default": "", "description": "Optional subdirectory or file filter." },
    "regex": { "type": "boolean", "default": false, "description": "Interpret query as regular expression when true." },
    "ignore_case": { "type": "boolean", "default": true, "description": "Case-insensitive matching." },
    "max_results": { "type": "integer", "default": 100, "minimum": 1, "maximum": 500 }
  },
  "required": ["query"],
  "additionalProperties": false
}`

const readFileSchema = `{
  "type": "object",
  "properties": {
    "workspace": { "type": "string", "description": "Workspace name (optional if only one workspace is authorized)." },
    "path": { "type": "string", "minLength": 1 },
    "ranges": {
      "type": "array",
      "description": "Optional list of 1-based inclusive line ranges. Reads from line 1 up to limits if omitted.",
      "items": {
        "type": "object",
        "properties": {
          "start_line": { "type": "integer", "minimum": 1 },
          "end_line": { "type": "integer", "minimum": 1 }
        },
        "required": ["start_line", "end_line"],
        "additionalProperties": false
      }
    }
  },
  "required": ["path"],
  "additionalProperties": false
}`

const editFileSchema = `{
  "type": "object",
  "properties": {
    "workspace": { "type": "string", "description": "Workspace name (optional if only one workspace is authorized)." },
    "path": { "type": "string", "minLength": 1 },
    "expected_sha256": { "type": "string", "description": "Optional optimistic concurrency check against last read sha256." },
    "edits": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "properties": {
          "old_text": { "type": "string", "minLength": 1 },
          "new_text": { "type": "string" },
          "replace_all": { "type": "boolean", "default": false }
        },
        "required": ["old_text", "new_text"],
        "additionalProperties": false
      }
    }
  },
  "required": ["path", "edits"],
  "additionalProperties": false
}`

const writeFileSchema = `{
  "type": "object",
  "properties": {
    "workspace": { "type": "string", "description": "Workspace name (optional if only one workspace is authorized)." },
    "path": { "type": "string", "minLength": 1 },
    "content": { "type": "string" },
    "expected_sha256": { "type": "string", "description": "Required when overwriting an existing file; must be omitted or empty when creating a new file." }
  },
  "required": ["path", "content"],
  "additionalProperties": false
}`

const runCheckSchema = `{
  "type": "object",
  "properties": {
    "workspace": { "type": "string", "description": "Workspace name (optional if only one workspace is authorized)." },
    "name": { "type": "string", "minLength": 1, "description": "Built-in check identifier (e.g., git_status, git_diff, go_test, npm_test, pytest, uv_pytest, uv_ruff, uv_pip_list, pip_list, cargo_test). Call list_workspaces for the full list." }
  },
  "required": ["name"],
  "additionalProperties": false
}`

func rawSchema(s string) json.RawMessage { return json.RawMessage(s) }
