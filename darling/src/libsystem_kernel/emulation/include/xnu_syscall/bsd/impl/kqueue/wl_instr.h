#ifndef _DARLING_EMULATION_WL_INSTR_H
#define _DARLING_EMULATION_WL_INSTR_H

#include <stdbool.h>
#include <stdint.h>

// Measurement-only logging of slow workloop and workqueue waits (m2v, firehose-mach-path.md section 6). Records go to
// WLI_DIR/<pid>.log, opened, appended and closed per record, so no descriptor stays in the process. Nothing is
// logged, and the waits are unchanged, unless that directory exists: a measuring run creates it.
#define WLI_DIR "/var/log/darling-wlinstr"

bool wli_enabled(void);
uint64_t wli_mono_us(void);
void wli_log(const char* format, ...) __attribute__((format(printf, 1, 2)));

#endif
