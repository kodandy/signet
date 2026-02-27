export interface CredentialRule {
  source?: string;            // "env:VAR_NAME" or "file:path"
  allowed_actions?: string[];
  max_uses?: number;
  expires?: string;
  require_approval?: boolean;
}

export interface Scope {
  filesystem?: {
    writable?: string[];     // glob patterns
    readable?: string[];
    blocked?: string[];      // always deny
  };
  network?: {
    allow?: string[];        // domain whitelist
    deny?: string[];         // default: ["*"]
  };
  credentials?: {
    [name: string]: CredentialRule;
  };
  shell?: {
    allow?: string[];        // command patterns
    deny?: string[];
    ask?: string[];          // human-in-the-loop
  };
}

export interface SignetConfig {
  version: number;
  defaults?: {
    expires?: string;        // e.g. "4h"
  };
  scope: Scope;
}
