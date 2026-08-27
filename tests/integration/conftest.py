"""
Conftest untuk integration tests.

GLSim's `gen_getContractSchemaForCode` RPC can return an empty method list
(server-side schema extraction bug), which breaks ContractFactory method
binding. This conftest monkeypatches `_get_schema_with_fallback` to compute
the schema locally from the contract source using the same direct-mode
loader, so method binding always works.
"""

import inspect
import os
import tempfile
from pathlib import Path

from gltest.contracts.contract_factory import ContractFactory
from gltest.direct import VMContext
from gltest.direct.loader import load_contract_class


def _extract_schema(cls: type) -> dict:
    ctor_params = []
    ctor_kwparams = {}
    methods = {}

    init = getattr(cls, "__init__", None)
    if init:
        try:
            sig = inspect.signature(init)
            for pname, param in sig.parameters.items():
                if pname == "self":
                    continue
                ptype = getattr(param.annotation, "__name__", str(param.annotation))
                if param.default != inspect.Parameter.empty:
                    ctor_kwparams[pname] = ptype
                else:
                    ctor_params.append(ptype)
        except (ValueError, TypeError):
            pass

    for name in dir(cls):
        if name.startswith("_"):
            continue
        obj = getattr(cls, name, None)
        if obj is None or not callable(obj):
            continue
        if not getattr(obj, "__gl_public__", False):
            continue
        try:
            sig = inspect.signature(obj)
        except (ValueError, TypeError):
            continue

        params = []
        kwparams = {}
        for pname, param in sig.parameters.items():
            if pname == "self":
                continue
            ptype = getattr(param.annotation, "__name__", str(param.annotation))
            if param.default != inspect.Parameter.empty:
                kwparams[pname] = ptype
            else:
                params.append(ptype)

        ret_type = getattr(sig.return_annotation, "__name__", "any")
        readonly = getattr(obj, "__gl_readonly__", False)
        methods[name] = {
            "params": params,
            "kwparams": kwparams,
            "ret": ret_type,
            "readonly": readonly,
        }

    return {
        "ctor": {"params": ctor_params, "kwparams": ctor_kwparams},
        "methods": methods,
    }


def _local_schema(self):
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    )
    try:
        tmp.write(self.contract_code)
        tmp.close()
        vm = VMContext()
        with vm.activate():
            cls = load_contract_class(Path(tmp.name).resolve(), vm)
            return _extract_schema(cls)
    finally:
        os.unlink(tmp.name)


ContractFactory._get_schema_with_fallback = _local_schema
