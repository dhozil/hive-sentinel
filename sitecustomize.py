"""Runtime patch untuk bug known GLSim (genlayer-test 0.29.x).

Dalam proses glsim yang berumur panjang, modul SDK GenLayer di-evict
antara transaksi (VMContext cleanup), sehingga class kontrak yang
di-cache dan di-reuse untuk deploy berikutnya bisa gagal alokasi storage
terhadap internal SDK yang baru di-import ulang:

    class is not marked for usage within storage, please, annotate it
    with @allow_storage

Patch ini memaksa setiap deploy memuat ulang class dari source —
deterministik dan mencerminkan perilaku produksi, di mana tiap deployment
meng-compile code sendiri.

Aktif otomatis saat menjalankan glsim dengan PYTHONPATH menunjuk ke
folder ini (lihat scripts/glsim-dev.ps1).

Referensi: buildersclaw/apps/genlayer/sitecustomize.py
"""

from __future__ import annotations

import hashlib
from pathlib import Path


try:
    import glsim.engine as _glsim_engine
except Exception:
    _glsim_engine = None


if _glsim_engine is not None and not getattr(
    _glsim_engine, "_honeypot_proxy_fix", False
):
    _original_simengine_deploy = _glsim_engine.SimEngine.deploy

    def _patched_simengine_deploy(self, code_path, args=None, kwargs=None, sender=None):
        # Always drop cached classes before deploy. In a long-lived glsim
        # process the GenLayer SDK modules are evicted between transactions
        # (VMContext cleanup), so ANY reused class — even the real one — can
        # fail storage allocation against freshly re-imported SDK internals
        # ('class is not marked for usage within storage'). A fresh load per
        # deploy is deterministic and matches production behavior, where each
        # deployment compiles its own code.
        try:
            path = Path(str(code_path))
            code_hash = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
            self._class_cache.pop(path_key := str(path), None)
            self._code_hash_cache.pop(code_hash, None)
        except OSError:
            pass

        return _original_simengine_deploy(
            self, code_path, args, kwargs, sender
        )

    _glsim_engine.SimEngine.deploy = _patched_simengine_deploy
    _glsim_engine._honeypot_proxy_fix = True
