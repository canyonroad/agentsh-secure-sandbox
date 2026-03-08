/**
 * Read W3C traceparent from the active OpenTelemetry span, if available.
 *
 * Uses dynamic import so @opentelemetry/api is an optional peer dependency.
 * Returns undefined when OTEL is not installed, no span is active, or the
 * trace context is invalid (all-zero trace ID).
 */
export async function getTraceparent(): Promise<string | undefined> {
  try {
    const { trace } = await import('@opentelemetry/api');
    const span = trace.getActiveSpan();
    const ctx = span?.spanContext();
    if (!ctx?.traceId || ctx.traceId === '00000000000000000000000000000000') {
      return undefined;
    }
    const flags = (ctx.traceFlags ?? 0).toString(16).padStart(2, '0');
    return `00-${ctx.traceId}-${ctx.spanId}-${flags}`;
  } catch {
    return undefined;
  }
}
