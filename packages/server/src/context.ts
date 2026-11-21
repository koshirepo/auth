/** What a service needs to know about the HTTP request it is serving. */
export interface RequestContext {
  /** The client IP as determined by your trusted proxy configuration. Used for risk scoring and throttling. */
  ip?: string;
  userAgent?: string;
  /** The DPoP proof header and the request it must match. */
  dpop?: {
    proof: string;
    /** HTTP method of the request, for example `POST`. */
    method: string;
    /** The URL the browser used, without query string or fragment. */
    url: string;
  };
}
