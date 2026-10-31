/**
 * The backend's error envelope: {"error": {"code": "...", "message": "..."}}
 *
 * Lives in its own module so the fixture backend can throw the same error type
 * the real client does, without a circular import. A mock that fails
 * differently from the real thing is a mock that hides bugs.
 */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}
