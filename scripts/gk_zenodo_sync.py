#!/usr/bin/env python3
"""gk_zenodo_sync.py — 每个 GitHub Release 自动归档为一个新的 Zenodo 版本。

动机（2026-11-04，owner 裁定「能不能不每次都重新上传附件」）
==========================================================
Concept DOI 只指向 **Zenodo 上的最新版本**，不会随 GitHub Release 自动前进；
每版手动上传 5 个附件不可持续，而 Zenodo–GitHub 集成只能抓 tag tarball，
不含 CI 产出的 `PROVENANCE.json` / `SBOM.cdx.json` / 确定性 zip。

流程（Zenodo legacy deposit API，纯标准库，无第三方依赖）
--------------------------------------------------------
1. 由 Concept DOI 的 recid 解析**最新已发布版本**的 record id；
2. `POST /deposit/depositions/<id>/actions/newversion` 建新草稿；
3. 删掉草稿继承的旧文件，上传本版 `dist/` 的 5 个附件；
4. `PUT` 元数据（version / publication_date）；
5. `POST /deposit/depositions/<draft>/actions/publish` —— Concept DOI 自动指向本版。

无 `ZENODO_TOKEN` 时**跳过**（exit 0 / status=skipped）：存档失败不应让发版变红。

用法：
  python3 scripts/gk_zenodo_sync.py --concept 23934594 --version v0.9.6.3 --dist dist
  python3 scripts/gk_zenodo_sync.py ... --dry-run      # 只打印计划，不发任何写请求
退出码：0 = 已发布 / 已跳过；1 = 存档失败；2 = 参数或附件缺失。
"""
import argparse
import datetime
import json
import os
import sys
import urllib.error
import urllib.request
import uuid

API = "https://zenodo.org/api"
BASE_FILES = ("SHA256SUMS", "PROVENANCE.json", "SBOM.cdx.json", "release-manifest.json")


def _req(method, url, token=None, body=None, headers=None, timeout=120):
    """单点 HTTP：返回 (status, 解析后的 JSON 或原文)。非 2xx 不抛，交给调用方判定。"""
    h = {"Accept": "application/json"}
    h.update(headers or {})
    if token:
        h["Authorization"] = "Bearer %s" % token
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw)
            except ValueError:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


def _multipart(name, data):
    """构造 `name` + `file` 两字段的 multipart 体（Zenodo legacy 上传要求）。"""
    b = uuid.uuid4().hex
    head = ('--%s\r\nContent-Disposition: form-data; name="name"\r\n\r\n%s\r\n'
            '--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n' % (b, name, b, name))
    tail = "\r\n--%s--\r\n" % b
    return (head.encode("utf-8") + data + tail.encode("utf-8"),
            "multipart/form-data; boundary=%s" % b)


def latest_record_id(concept, token):
    """Concept recid → 最新已发布版本 record id（找不到返回 None）。"""
    url = "%s/records?q=conceptrecid:%s&sort=mostrecent&size=1&all_versions=true" % (API, concept)
    st, obj = _req("GET", url, token)
    if st != 200 or not isinstance(obj, dict):
        return None
    hits = (obj.get("hits") or {}).get("hits") or []
    if not hits:
        return None
    return hits[0].get("id")


def plan_files(dist, version):
    """本版要归档的 5 个附件（缺任何一个都算失败，不静默少传）。"""
    from pathlib import Path
    d = Path(dist)
    names = ["zthl-aegis-%s.zip" % version] + list(BASE_FILES)
    return [(n, d / n) for n in names]


def _clean_meta(meta):
    """去掉只读/由服务端生成的键，并清掉会让 Zenodo 校验 400 的空值项。

    2026-11-04 实测：旧记录携带 `dates: [{"type": "issued", "date": ""}]`，
    整体回写时 Zenodo 报 `metadata.dates: Invalid date provided.`（v0.9.6.4 归档失败根因）。
    故 dates 逐项过滤：`date` 为空的条目直接丢弃，全空则删掉该键。
    """
    drop = {"doi", "prereserve_doi", "relations", "_deposit", "owners", "created",
            "modified", "recid", "conceptrecid", "resource_type", "id", "conceptdoi"}
    out = {k: v for k, v in (meta or {}).items() if k not in drop and v not in (None, "", [], {})}
    dates = out.get("dates")
    if isinstance(dates, list):
        kept = [d for d in dates
                if isinstance(d, dict) and str(d.get("date") or "").strip()]
        if kept:
            out["dates"] = kept
        else:
            out.pop("dates", None)
    return out


def find_draft(rec, token):
    """复用**已存在的草稿**（上次失败留下的），避免 `newversion` 因草稿占用而报错。"""
    st, obj = _req("GET", "%s/deposit/depositions/%s" % (API, rec), token)
    if st != 200 or not isinstance(obj, dict):
        return None
    ld = ((obj.get("links") or {}).get("latest_draft") or "").rstrip("/")
    did = ld.rsplit("/", 1)[-1]
    return did if did.isdigit() and did != str(rec) else None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="gk_zenodo_sync.py")
    ap.add_argument("--concept", required=True, help="Concept recid（如 23934594）")
    ap.add_argument("--version", required=True, help="发布版本号，如 v0.9.6.3")
    ap.add_argument("--dist", default="dist", help="发布产物目录")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    token = os.environ.get("ZENODO_TOKEN", "").strip()
    files = plan_files(a.dist, a.version)
    missing = [str(p) for _, p in files if not p.is_file()]
    if missing:
        print(json.dumps({"ok": False, "error": "附件缺失", "missing": missing},
                         ensure_ascii=False))
        return 2
    if not token:
        print(json.dumps({"ok": True, "status": "skipped",
                          "reason": "ZENODO_TOKEN 未配置（跳过存档，不影响发版）",
                          "files": [n for n, _ in files]}, ensure_ascii=False))
        return 0

    rec = latest_record_id(a.concept, token)
    if not rec:
        print(json.dumps({"ok": False, "error": "无法解析最新版本记录",
                          "concept": a.concept}, ensure_ascii=False))
        return 1
    if a.dry_run:
        print(json.dumps({"ok": True, "status": "dry-run", "latest_record": rec,
                          "version": a.version, "files": [n for n, _ in files]},
                         ensure_ascii=False))
        return 0

    # 复用上次失败留下的草稿；没有才 newversion（否则 Zenodo 会因草稿占用拒绝建新版本）
    draft = find_draft(rec, token)
    if draft:
        # 提示走 stderr：stdout 只留**单条**最终 JSON（调用方按单条解析）
        print("复用已有草稿 %s" % draft, file=sys.stderr)
    else:
        st, obj = _req("POST", "%s/deposit/depositions/%s/actions/newversion" % (API, rec), token,
                       body=b"")
        if st not in (200, 201) or not isinstance(obj, dict):
            print(json.dumps({"ok": False, "error": "newversion 失败", "status": st,
                              "detail": obj}, ensure_ascii=False))
            return 1
        draft_url = ((obj.get("links") or {}).get("latest_draft") or "").rstrip("/")
        draft = draft_url.rsplit("/", 1)[-1]
        if not draft.isdigit():
            print(json.dumps({"ok": False, "error": "newversion 未返回 draft id",
                              "links": obj.get("links")}, ensure_ascii=False))
            return 1

    st, obj = _req("GET", "%s/deposit/depositions/%s" % (API, draft), token)
    if st != 200 or not isinstance(obj, dict):
        print(json.dumps({"ok": False, "error": "读取草稿失败", "status": st}, ensure_ascii=False))
        return 1
    for f in obj.get("files") or []:
        link = ((f.get("links") or {}).get("self") or "").rstrip("/")
        if link:
            _req("DELETE", link, token)

    uploaded = []
    for name, path in files:
        body, ctype = _multipart(name, path.read_bytes())
        st, res = _req("POST", "%s/deposit/depositions/%s/files" % (API, draft), token,
                       body=body, headers={"Content-Type": ctype})
        if st not in (200, 201):
            print(json.dumps({"ok": False, "error": "上传失败", "file": name,
                              "status": st, "detail": res}, ensure_ascii=False))
            return 1
        uploaded.append(name)

    meta = _clean_meta(obj.get("metadata"))
    meta["version"] = a.version
    meta["publication_date"] = datetime.date.today().isoformat()
    body = json.dumps({"metadata": meta}).encode("utf-8")
    st, res = _req("PUT", "%s/deposit/depositions/%s" % (API, draft), token,
                   body=body, headers={"Content-Type": "application/json"})
    if st not in (200, 201):
        print(json.dumps({"ok": False, "error": "元数据更新失败", "status": st,
                          "detail": res}, ensure_ascii=False))
        return 1

    st, res = _req("POST", "%s/deposit/depositions/%s/actions/publish" % (API, draft),
                   token, body=b"")
    if st not in (200, 201, 202):
        print(json.dumps({"ok": False, "error": "发布失败", "status": st,
                          "detail": res}, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, "status": "published", "record": draft,
                      "doi": (res or {}).get("doi") if isinstance(res, dict) else None,
                      "conceptdoi": (res or {}).get("conceptdoi") if isinstance(res, dict) else None,
                      "version": a.version, "files": uploaded}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
