export { createVigilo, DEFAULT_ENDPOINT, type VigiloClient, type VigiloOptions } from './client.js';
export {
  buildBatch,
  EVENT_BATCH_SCHEMA,
  EVENT_SCHEMA,
  EVENT_SCHEMA_VERSION,
  LIMITS,
  SDK_NAME,
  SDK_VERSION,
  THREAT_LAYERS,
  THREAT_TYPES,
  type EventBatch,
} from './contract.js';
export { detect, highestSeverity } from './detectors/index.js';
export { VALUE_SIGNATURES, type Signature } from './detectors/signatures.js';
export { resolveClientIp, normalizeIp, type TrustProxy } from './ip.js';
export { buildPayload, maskHeaders, maskObject, maskString, REDACTED, type MaskingOptions } from './masking.js';
export { collectValues, decodeValue, headerValue, normalizeRoutePath } from './normalize.js';
export { IpTracker, type TrackerOptions } from './tracker.js';
export { EventTransport, type SendFn, type TransportOptions, type TransportStats } from './transport.js';
export { uuidv7 } from './uuid.js';
export type * from './types.js';
