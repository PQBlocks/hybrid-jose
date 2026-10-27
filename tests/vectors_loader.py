"""Official test vector loader for pqblocks-jose."""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_DIR = os.path.join(HERE, "vectors")
CACHE = os.path.expanduser(os.environ.get("PQC_VECTORS", "~/.cache/pqblocks-vectors"))


def sets(filt=""):
    out = []
    # 1. Local vendored vectors
    acvp_local = os.path.join(VECTORS_DIR, "acvp")
    if os.path.isdir(acvp_local):
        for name in sorted(os.listdir(acvp_local)):
            path = os.path.join(acvp_local, name, "internalProjection.json")
            if os.path.isfile(path) and filt.lower() in name.lower():
                out.append(("acvp", name, path))

    wyche_local = os.path.join(VECTORS_DIR, "wycheproof")
    if os.path.isdir(wyche_local):
        for name in sorted(os.listdir(wyche_local)):
            path = os.path.join(wyche_local, name)
            clean_name = name.replace("_test.json", "").replace(".json", "")
            if filt.lower() in clean_name.lower() or filt.lower() in name.lower():
                out.append(("wycheproof", clean_name, path))

    # 2. Fallback to cache if local not found
    if not out:
        acvp_cache = os.path.join(CACHE, "ACVP-Server", "gen-val", "json-files")
        if os.path.isdir(acvp_cache):
            for name in sorted(os.listdir(acvp_cache)):
                path = os.path.join(acvp_cache, name, "internalProjection.json")
                if os.path.isfile(path) and filt.lower() in name.lower():
                    out.append(("acvp", name, path))

        wyche_cache = os.path.join(CACHE, "wycheproof", "testvectors_v1")
        if os.path.isdir(wyche_cache):
            for name in sorted(os.listdir(wyche_cache)):
                path = os.path.join(wyche_cache, name)
                clean_name = name.replace("_test.json", "").replace(".json", "")
                if filt.lower() in clean_name.lower() or filt.lower() in name.lower():
                    out.append(("wycheproof", clean_name, path))

    return out


def load(name):
    found = sets(name)
    if not found:
        raise FileNotFoundError(f"No official vector set matches {name!r} under {VECTORS_DIR}")
    groups = []
    for kind, set_name, path in found:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for g in doc.get("testGroups", []):
            g = dict(g)
            g["_source"] = f"{kind}:{set_name}"
            groups.append(g)
    return groups
