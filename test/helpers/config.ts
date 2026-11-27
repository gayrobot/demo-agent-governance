// Configurations the tests use. HELPDESK is the helpdesk's constants at dc26b4e, so
// the ported tests show its switch-over changes no behaviour. LIFECYCLE is shaped like
// the lifecycle demo: one audience per system, and a grant for a run and a finding.

import type { IssuerConfig } from "../../src/identity.ts";

export const HELPDESK: IssuerConfig = {
  issuer: "urn:savory-air:dev-issuer",
  agentAudience: "helpdesk-agent",
  agentClientId: "helpdesk-agent",
  resources: {
    "savory-air-directory": [
      "directory:read",
      "devices:read",
      "directory:mfa.reset",
      "directory:group.add",
    ],
    "savory-air-runbooks": ["runbooks:read"],
    "savory-air-tickets": ["tickets:escalate"],
  },
  subjectPattern: /^[a-z0-9._-]+@example\.test$/,
  refPattern: /^[A-Za-z0-9_-]{1,64}$/,
};

export const LIFECYCLE: IssuerConfig = {
  issuer: "urn:savory-air:lifecycle-lab",
  agentAudience: "lifecycle-agent",
  agentClientId: "lifecycle-agent",
  resources: {
    "savory-air-saas": ["accounts:deactivate"],
    "savory-air-ads": ["accounts:deactivate", "assets:transfer"],
  },
  subjectPattern: /^[a-z0-9._-]+@example\.test$/,
  refPattern: /^run-[0-9]{4}\/[a-z]+\/[A-Za-z0-9-]+\/[a-z_]+$/,
};

export const JAMIE = "jamie@example.test";
