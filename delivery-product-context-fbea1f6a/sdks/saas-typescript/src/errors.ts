export class OmnigentSaasError extends Error {
  override readonly name: string = "OmnigentSaasError";
}

export class TransportError extends OmnigentSaasError {
  override readonly name: string = "TransportError";
}

export class ApiTimeoutError extends TransportError {
  override readonly name: string = "ApiTimeoutError";
}

export class ProtocolError extends OmnigentSaasError {
  override readonly name: string = "ProtocolError";
}

export interface ApiErrorOptions {
  statusCode: number;
  code: string;
  message: string;
  requestId: string | null;
  details?: Record<string, unknown>;
  retryAfter?: string | null;
}

export class ApiError extends OmnigentSaasError {
  override readonly name: string = "ApiError";
  readonly statusCode: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly details: Record<string, unknown>;
  readonly retryAfter: string | null;

  constructor(options: ApiErrorOptions) {
    super(options.message);
    this.statusCode = options.statusCode;
    this.code = options.code;
    this.requestId = options.requestId;
    this.details = options.details ?? {};
    this.retryAfter = options.retryAfter ?? null;
  }
}

export class AuthenticationError extends ApiError {
  override readonly name: string = "AuthenticationError";
}
export class AuthorizationError extends ApiError {
  override readonly name: string = "AuthorizationError";
}
export class NotFoundError extends ApiError {
  override readonly name: string = "NotFoundError";
}
export class ConflictError extends ApiError {
  override readonly name: string = "ConflictError";
}
export class PreconditionFailedError extends ApiError {
  override readonly name: string = "PreconditionFailedError";
}
export class ValidationError extends ApiError {
  override readonly name: string = "ValidationError";
}
export class RateLimitError extends ApiError {
  override readonly name: string = "RateLimitError";
}
