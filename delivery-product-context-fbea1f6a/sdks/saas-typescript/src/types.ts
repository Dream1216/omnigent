export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type ProjectStatus = "active" | "suspended" | "archived";
export type RunStatus =
  | "created"
  | "queued"
  | "leased"
  | "starting"
  | "running"
  | "waiting_input"
  | "waiting_approval"
  | "cancelling"
  | "cancelled"
  | "succeeded"
  | "failed"
  | "timed_out"
  | "orphaned";

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface Project {
  id: string;
  space_id: string;
  name: string;
  visibility: "private" | "space" | "restricted";
  status: ProjectStatus;
  authorization_version: number;
  created_at: string;
  updated_at: string;
  etag: string;
}

export interface Run {
  id: string;
  project_id: string;
  task_id: string;
  session_id: string | null;
  parent_run_id: string | null;
  status: RunStatus;
  version: number;
  event_sequence: number;
  queue_class: string;
  priority: number;
  metadata: Record<string, JsonValue>;
  created_at: string;
  updated_at: string;
  terminal_at: string | null;
  etag: string;
}

export interface RunContent {
  run_id: string;
  input: Record<string, JsonValue>;
  product_revision: string;
  upstream_revision: string;
  schema_revision: string;
  adapter_contract_version: string;
  etag: string;
}

export interface RunEvent {
  id: string;
  run_id: string;
  sequence: number;
  type: string;
  data: Record<string, JsonValue>;
  trace_id: string;
  created_at: string;
}

export interface RunCreate {
  title: string;
  input: Record<string, JsonValue>;
  session_id?: string | null;
  queue_class?: string;
  priority?: number;
  quota_resource?: string;
  quota_units?: number;
  metadata?: Record<string, JsonValue>;
}

export interface RunRetry {
  input_override?: Record<string, JsonValue> | null;
  queue_class?: string | null;
  priority?: number | null;
  metadata?: Record<string, JsonValue>;
}

export interface ListProjectsOptions {
  limit?: number;
  cursor?: string;
  status?: ProjectStatus;
}

export interface ListRunsOptions {
  limit?: number;
  cursor?: string;
  status?: RunStatus[];
  createdAfter?: string;
  createdBefore?: string;
}

export interface ListRunEventsOptions {
  limit?: number;
  cursor?: string;
  afterSequence?: number;
}

export interface MutationOptions {
  idempotencyKey: string;
}

export interface VersionedMutationOptions extends MutationOptions {
  ifMatch: string;
}
