// U-05 R2-2 D3 harness: with RLIMIT_FSIZE set, SIGXFSZ would TERMINATE the process before any cleanup (that is the
// kill case, D3k). Ignoring it here makes the over-limit write return EFBIG, so the catchable-error path is what runs.
process.on('SIGXFSZ', () => {});
