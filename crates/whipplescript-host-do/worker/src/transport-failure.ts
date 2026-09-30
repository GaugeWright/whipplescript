/** Preserve the shell's three-call limit while delivering its final observation. */
export function transportFailureObservation(attempts: number, message: string): string {
  return JSON.stringify({
    error: message,
    ...(attempts >= 3 ? { transport_retry_budget_exhausted: true } : {}),
  });
}
