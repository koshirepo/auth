/**
 * Helpers for testing code that uses this library, and for testing adapters you write yourself.
 * Importing this entry point requires Vitest.
 */
export { createFakeClock, type FakeClock } from './clock.js';
export { runAdapterContractTests, type AdapterHarness } from './contract.js';
