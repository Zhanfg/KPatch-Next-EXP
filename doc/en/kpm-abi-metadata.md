# Optional KPM ABI metadata (display-only)

The existing KPM metadata contains `name`, `version`, `license`,
`author`, and `description`. These are not ABI version numbers.

This fork adds an **optional** NUL-separated `abi=<decimal number>` string
in the existing `.kpm.info` ELF section. For newly authored KPMs:

```c
#include <kpmodule.h>

KPM_NAME("my-module");
KPM_VERSION("1.2.3");
KPM_ABI("1");  // Declared module ABI, not its release version.
```

The macro only writes metadata; it does not enforce compatibility, change
calling conventions, or supply a new kernel API. Authors must choose the
ABI number matching the ABI contract their KPM was actually built for.

Legacy modules with no `abi` key remain valid and appear as `legacy`
in the KPN manager. An invalid or unrecognized value appears as
`unknown`, not as a guessed number. Display values are never inferred
from KPM release versions or the host's KernelPatch version.

The field is surfaced through both existing read paths:
- File-based KPM inspection: `kptools -l -M /path/to.kpm`
- Runtime / embedded KPMs: `kpatch kpm info NAME`

Both still provide the original fields in their original format and only
append `abi=` if present. Existing KPMs, including Nohello, do not
require recompilation. Newly declared ABI metadata on running/embedded
modules requires a KPIMG containing this reader, whereas reading an
installed `.kpm` file requires only a newer `kptools`.

**Important:** This is a descriptive badge, not runtime ABI negotiation or
binary-compatibility attestation. This fork continues to support and load
existing legacy KPMs without changing privilege or load semantics.
