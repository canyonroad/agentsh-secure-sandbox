import { describe, it, expect, vi, afterEach } from 'vitest';
import { getTraceparent } from './traceparent.js';

describe('getTraceparent', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns undefined when @opentelemetry/api is not installed', async () => {
    // Default environment has no OTEL, dynamic import will throw
    const result = await getTraceparent();
    expect(result).toBeUndefined();
  });

  it('returns undefined when no active span', async () => {
    vi.doMock('@opentelemetry/api', () => ({
      trace: {
        getActiveSpan: () => undefined,
      },
    }));
    const { getTraceparent: fn } = await import('./traceparent.js');
    expect(await fn()).toBeUndefined();
  });

  it('returns undefined for all-zero trace ID', async () => {
    vi.doMock('@opentelemetry/api', () => ({
      trace: {
        getActiveSpan: () => ({
          spanContext: () => ({
            traceId: '00000000000000000000000000000000',
            spanId: 'abcdef1234567890',
            traceFlags: 1,
          }),
        }),
      },
    }));
    const { getTraceparent: fn } = await import('./traceparent.js');
    expect(await fn()).toBeUndefined();
  });

  it('returns W3C traceparent when span is active', async () => {
    vi.doMock('@opentelemetry/api', () => ({
      trace: {
        getActiveSpan: () => ({
          spanContext: () => ({
            traceId: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
            spanId: '1234567890abcdef',
            traceFlags: 1,
          }),
        }),
      },
    }));
    const { getTraceparent: fn } = await import('./traceparent.js');
    expect(await fn()).toBe(
      '00-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6-1234567890abcdef-01',
    );
  });

  it('pads traceFlags to two hex digits', async () => {
    vi.doMock('@opentelemetry/api', () => ({
      trace: {
        getActiveSpan: () => ({
          spanContext: () => ({
            traceId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1',
            spanId: 'bbbbbbbbbbbbbb01',
            traceFlags: 0,
          }),
        }),
      },
    }));
    const { getTraceparent: fn } = await import('./traceparent.js');
    const result = await fn();
    expect(result).toMatch(/-00$/);
  });
});
