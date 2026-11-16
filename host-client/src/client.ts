import rawManifest from './manifest.json' with { type: 'json' };
import { schemaRevision, type Operation, type InputByOperation, type OutputByOperation, type ExecutionError, type FileResultWire, type ApprovalRequiredWire, type ApprovalSessionWire } from './generated.js';
export type { Operation, InputByOperation, OutputByOperation, ExecutionError } from './generated.js';

/** Full values stay in the host until the caller explicitly reads them. */
export class HostValue<T> {
  #value: T;
  constructor(value: T) { this.#value = value; }
  read(): T { return this.#value; }
  toString(): string { return '[HostValue: redacted]'; }
  toJSON(): string { return this.toString(); }
  [Symbol.for('nodejs.util.inspect.custom')](): string { return this.toString(); }
}

/** Supply an already-authenticated MCP SDK connection; this client owns no credentials. */
export interface Transport {
  callTool(request: { name: string; arguments: Record<string, unknown> }): Promise<unknown>;
}
/** A host-owned JSON Schema 2020-12 validator. Do not log either argument. */
export type Validate = (schema: unknown, value: unknown) => boolean;
export type FileResult<O extends Operation> = FileResultWire & { operation: O };
export type ApprovalSession = NonNullable<ApprovalRequiredWire['approval']['session']>;
export interface ApprovalOffer {
  reason: string;
  url?: string;
  token?: HostValue<string>;
  session?: HostValue<ApprovalSession>;
}
export type Outcome<T> =
  | { kind: 'success'; value: HostValue<T> }
  | { kind: 'error'; error: HostValue<ExecutionError> }
  | { kind: 'approvalRequired'; error: HostValue<ExecutionError>; approval: ApprovalOffer };

/** Composition helpers stop with reusable, redacted approval guidance. */
export class ApprovalRequiredError extends Error {
  readonly approval: ApprovalOffer;
  readonly error: HostValue<ExecutionError>;
  constructor(approval: ApprovalOffer, error: HostValue<ExecutionError>) {
    super('Human approval is required; present the approval URL and explicitly retry after approval');
    this.name = 'ApprovalRequiredError'; this.approval = approval; this.error = error;
  }
}
interface OperationMetadata { executor: string; inputSchema: unknown; outputSchema: unknown; profiles: string[] }
interface Manifest { schemaRevision: string; executionErrorSchema: unknown; fileResultSchema: unknown; approvalRequiredSchema: unknown; approvalSessionSchema: unknown; operations: Record<string, OperationMetadata> }
const manifest: Manifest = rawManifest;
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function validate(validator: Validate, schema: unknown, value: unknown): boolean {
  try { return validator(schema, value) === true; }
  catch { throw new Error('Host schema validation failed; inspect host configuration without logging payloads'); }
}
function payload(result: unknown): { error: boolean; value: Record<string, unknown> } {
  if (!object(result) || !object(result.structuredContent) ||
      (result.isError !== undefined && typeof result.isError !== 'boolean')) {
    throw new Error('The MCP response has no valid structured result; reconcile effects before retrying');
  }
  return { error: result.isError === true, value: result.structuredContent };
}

function approvalOffer(value: unknown): ApprovalOffer {
  const invalid = () => new Error('The approval guidance contract is invalid; request fresh approval');
  if (!object(value) || typeof value.reason !== 'string') throw invalid();
  const offer: ApprovalOffer = { reason: value.reason };
  if (value.approvalToken !== undefined) {
    if (typeof value.approvalToken !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.approvalToken)) throw invalid();
    offer.token = new HostValue(value.approvalToken);
  }
  if (value.approvalUrl !== undefined) {
    if (typeof value.approvalUrl !== 'string') throw invalid();
    try {
      const url = new URL(value.approvalUrl);
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password ||
          typeof value.approvalToken === 'string' && value.approvalUrl.includes(value.approvalToken)) throw invalid();
    } catch { throw invalid(); }
    offer.url = value.approvalUrl;
  }
  if (object(value.session)) offer.session = new HostValue(value.session as ApprovalSession);
  return offer;
}
async function call(transport: Transport, request: { name: string; arguments: Record<string, unknown> }): Promise<unknown> {
  try { return await transport.callTool(request); }
  catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new DOMException('MCP transport was cancelled; reconcile effects before retrying', 'AbortError');
    }
    throw new Error('MCP transport failed; the operation may have run. Reconcile before retrying');
  }
}

/** Typed composition runs in the host process. This client never retries an operation. */
export class HostClient {
  #transport: Transport;
  #validate: Validate;
  #profile: string;
  #fileDelivery: boolean;
  #requiresApproval: boolean;
  #approvalToken: HostValue<string> | undefined;
  private constructor(transport: Transport, validator: Validate, profile: string, fileDelivery: boolean, requiresApproval: boolean, token?: HostValue<string>) {
    this.#transport = transport; this.#validate = validator;
    this.#profile = profile; this.#fileDelivery = fileDelivery;
    this.#requiresApproval = requiresApproval; this.#approvalToken = token;
  }
  static async connect(transport: Transport, validator: Validate): Promise<HostClient> {
    const result = payload(await call(transport, { name: 'server.capabilities', arguments: {} }));
    const data = result.value;
    if (result.error || data.schemaRevision !== schemaRevision || !object(data.runtime) ||
        typeof data.runtime.operationProfile !== 'string' ||
        !['metadata', 'secrets', 'pkiSsh', 'full'].includes(data.runtime.operationProfile) ||
        !object(data.runtime.delivery) || !Array.isArray(data.runtime.delivery.resultModes)) {
      throw new Error('Server capability contract differs from this client; regenerate bindings or select a compatible server');
    }
    return new HostClient(transport, validator, data.runtime.operationProfile,
      data.runtime.delivery.resultModes.includes('file'), data.runtime.humanApproval === true);
  }
  get requiresApproval(): boolean { return this.#requiresApproval; }
  /** Bind an opaque approval credential for future explicit invocations; this sends no work. */
  withApproval(token: HostValue<string>): HostClient {
    const value = token.read();
    if (!this.#requiresApproval || typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
      throw new Error('A valid approval credential and an approval-enabled server are required');
    }
    return new HostClient(this.#transport, this.#validate, this.#profile, this.#fileDelivery, true, token);
  }
  /** Read permission and remaining time without extending the session. */
  approvalStatus(): Promise<HostValue<ApprovalSessionWire>> { return this.#session('status'); }
  /** Explicitly close this session; transport failure does not trigger a replay. */
  closeApproval(): Promise<HostValue<ApprovalSessionWire>> { return this.#session('close'); }
  async #session(action: 'status' | 'close'): Promise<HostValue<ApprovalSessionWire>> {
    if (!this.#approvalToken) throw new Error('Bind an approval credential before managing its session');
    const response = payload(await call(this.#transport, { name: 'approval.session', arguments: { action, approvalToken: this.#approvalToken.read() } }));
    if (response.error || !validate(this.#validate, manifest.approvalSessionSchema, response.value) ||
        action === 'close' && (!object(response.value.session) || response.value.session.state !== 'closed')) {
      throw new Error('Approval session state could not be confirmed; inspect it before proceeding');
    }
    if (action === 'close') this.#approvalToken = undefined;
    return new HostValue(response.value as unknown as ApprovalSessionWire);
  }
  async invoke<O extends Operation>(operation: O, args: InputByOperation[O]): Promise<Outcome<OutputByOperation[O]>> {
    return this.#invoke(operation, args, false) as Promise<Outcome<OutputByOperation[O]>>;
  }
  async invokeFile<O extends Operation>(operation: O, args: InputByOperation[O]): Promise<Outcome<FileResult<O>>> {
    return this.#invoke(operation, args, true) as Promise<Outcome<FileResult<O>>>;
  }
  async #invoke(operation: Operation, args: unknown, file: boolean): Promise<Outcome<unknown>> {
    if (!Object.hasOwn(manifest.operations, operation)) throw new Error('Unknown operation');
    const metadata = manifest.operations[operation]!;
    if (!metadata.profiles.includes(this.#profile)) throw new Error('Operation is unavailable in this server profile');
    if (file && !this.#fileDelivery) throw new Error('This server does not support whole-result file delivery');
    if (!validate(this.#validate, metadata.inputSchema, args)) throw new Error('Arguments do not satisfy the operation schema');
    const response = payload(await call(this.#transport, { name: metadata.executor,
      arguments: { operation, arguments: args, resultDelivery: file ? 'file' : 'inline',
        ...(this.#approvalToken ? { approvalToken: this.#approvalToken.read() } : {}) } }));
    if (response.error) {
      if (!validate(this.#validate, manifest.executionErrorSchema, response.value.error) ||
          !object(response.value.error) || response.value.error.operation !== operation) {
        throw new Error('The execution error contract is invalid; reconcile effects before retrying');
      }
      if (response.value.error.category === 'approvalRequired') {
        if (!validate(this.#validate, manifest.approvalRequiredSchema, response.value)) {
          throw new Error('The approval guidance contract is invalid; request fresh approval');
        }
        return { kind: 'approvalRequired', error: new HostValue(response.value.error as ExecutionError),
          approval: approvalOffer(response.value.approval) };
      }
      return { kind: 'error', error: new HostValue(response.value.error as ExecutionError) };
    }
    if (file) {
      const ref = response.value.resultFile;
      if (!validate(this.#validate, manifest.fileResultSchema, response.value) ||
          response.value.operation !== operation || !object(ref) || typeof ref.uri !== 'string' ||
          !ref.uri.startsWith('mcp-file://infisical/') || typeof ref.name !== 'string' || ref.mimeType !== 'application/json') {
        throw new Error('The result file contract is invalid; reconcile effects before retrying');
      }
    } else if (!validate(this.#validate, metadata.outputSchema, response.value)) {
      throw new Error('The output does not satisfy the operation schema; reconcile effects before retrying');
    }
    return { kind: 'success', value: new HostValue(response.value) };
  }
}
