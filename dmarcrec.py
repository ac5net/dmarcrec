#!/usr/bin/env python3
"""
dmarcrec.py - DMARC ポリシーレコードを RFC 9989 / RFC 9990 どおりに読む

使い方:
    ./dmarcrec.py <ドメイン> [--fixtures <txt>] [--json]
    例: ./dmarcrec.py kddi.com

やること:
  1. _dmarc.<ドメイン> の TXT を取る。無ければ DNS Tree Walk（RFC 9989 4.10）で
     組織ドメイン／PSD のレコードを探し、sp / np / p の優先順で適用ポリシーを決める
  2. レコードを 4.7 / 4.8 の定義で解析する。v=DMARC1 が先頭でなければ無効、
     未知タグは無視、RFC 7489 にあって RFC 9989 で削除された pct / ri / rf は「無視される」と指摘
  3. rua / ruf の宛先ホストごとに Tree Walk で組織ドメインを求め、レコードの組織ドメインと
     違えば <ドメイン>._report._dmarc.<宛先ホスト> の TXT を引いて外部宛先の認可を確認する
     （RFC 9990 4 節）。認可が無い URI は受信側に無視される

Python 標準ライブラリだけで動きます。--fixtures を渡すとネットワークに出ません。
"""
import argparse
import json
import re
import sys
import urllib.parse
import urllib.request

DOH = "https://dns.google/resolve"
TYPE_TXT = 16
MAX_LABELS = 8                      # RFC 9989 4.10: Tree Walk の問い合わせ上限
POLICIES = ("none", "quarantine", "reject")
REMOVED_TAGS = {"pct": "A.6（t タグに置換）", "ri": "C.5.2", "rf": "C.5.2"}
KNOWN_TAGS = {"v", "p", "sp", "np", "adkim", "aspf", "fo", "psd", "rua", "ruf", "t"}
_FO = re.compile(r"^(?:[01](?::[ds])*|[ds](?::[01])?(?::[ds])?|(?:[ds]:)*[01])$")


# ---------------------------------------------------------------- DNS 取得
def doh_txt(name):
    """dns.google に TXT を問い合わせ、(status, ad, [txt]) を返す。TXT の引用符は外す"""
    url = DOH + "?" + urllib.parse.urlencode({"name": name, "type": TYPE_TXT})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        j = json.load(r)
    txts = []
    for a in j.get("Answer", []):
        if a.get("type") == TYPE_TXT:
            d = a["data"]
            # dns.google は "..." "..." の形で返すことがある（255 オクテット分割）
            parts = re.findall(r'"((?:[^"\\]|\\.)*)"', d)
            txts.append("".join(parts) if parts else d)
    return j.get("Status", -1), bool(j.get("AD")), txts


class FixtureLookup:
    """'名前 | Status | AD | TXT1 || TXT2' 形式のテキストで応答を再生する"""

    def __init__(self, path):
        self.data = {}
        self.missing = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                name, st, ad, txt = [x.strip() for x in line.split("|", 3)]
                txts = [t.strip() for t in txt.split("||") if t.strip()] if txt else []
                self.data[name.lower()] = (int(st), ad == "1", txts)

    def __call__(self, name):
        key = name.lower().rstrip(".")
        if key not in self.data:
            self.missing.append(key)
            return 3, False, []
        return self.data[key]


# ---------------------------------------------------------------- レコード解析
def is_dmarc(txt):
    """4.7 "v": 先頭のタグが v=DMARC1（大文字小文字を区別）でなければレコードではない"""
    m = re.match(r"^\s*v\s*=\s*DMARC1\s*(;|$)", txt)
    return m is not None


def parse_record(txt):
    """4.7 / 4.8 に沿って tag=value を解析。戻り値: {'tags':{}, 'findings':[(level,msg)], 'valid':bool}"""
    tags, findings = {}, []
    if not is_dmarc(txt):
        return {"tags": {}, "findings": [("ERROR", "v=DMARC1 が先頭に無い。レコード全体を無視（4.7）")], "valid": False}
    seen = set()
    for raw in txt.split(";"):
        if not raw.strip():
            continue
        if "=" not in raw:
            findings.append(("WARN", "'=' の無い要素 %r は無視" % raw.strip()))
            continue
        k, v = raw.split("=", 1)
        k, v = k.strip(), v.strip()          # タグ名は大文字小文字を区別する（RFC 6376 3.2）
        if k in seen:
            findings.append(("WARN", "タグ %s が重複。RFC 6376 3.2 ではレコード全体が無効、RFC 9989 4.8 では構文エラーは既定値で読む。ここでは最初の値を採用するが、実装で結果が分かれる" % k))
            continue
        seen.add(k)
        if k in REMOVED_TAGS:
            findings.append(("INFO", "タグ %s=%s は RFC 9989 で削除済み（%s）。受信側には未知タグとして無視される" % (k, v, REMOVED_TAGS[k])))
            tags[k] = v
            continue
        if k not in KNOWN_TAGS:
            if k.lower() in KNOWN_TAGS | set(REMOVED_TAGS):
                findings.append(("WARN", "タグ名 %s は大文字小文字を区別するので %s とは別物。未知タグとして無視される（RFC 6376 3.2）" % (k, k.lower())))
            else:
                findings.append(("INFO", "未知タグ %s は無視（4.8）" % k))
            continue
        tags[k] = v

    # 値の検証（4.8 Table 2）
    # 値も大文字小文字を区別する（RFC 6376 3.2。RFC 9989 4.7 の値はすべて小文字）
    for k in ("p", "sp", "np"):
        if k in tags and tags[k] not in POLICIES:
            hint = "（大文字小文字が違う。値は区別される）" if tags[k].lower() in POLICIES else ""
            findings.append(("ERROR", "%s=%s は none/quarantine/reject のいずれでもない%s" % (k, tags[k], hint)))
            tags[k + "_invalid"] = tags.pop(k)
    for k in ("adkim", "aspf"):
        if k in tags and tags[k] not in ("r", "s"):
            findings.append(("WARN", "%s=%s は r/s 以外。既定 r で読む" % (k, tags[k])))
            tags.pop(k)
    if "t" in tags and tags["t"] not in ("y", "n"):
        findings.append(("WARN", "t=%s は y/n 以外。既定 n で読む" % tags["t"]))
        tags.pop("t")
    if "psd" in tags and tags["psd"] not in ("y", "n", "u"):
        findings.append(("WARN", "psd=%s は y/n/u 以外。既定 u で読む" % tags["psd"]))
        tags.pop("psd")
    if "fo" in tags:
        if not _FO.match(tags["fo"]):
            findings.append(("WARN", "fo=%s は 4.8 の dmarc-fo 構文に合わない" % tags["fo"]))
        if "ruf" not in tags:
            findings.append(("INFO", "ruf が無いので fo は無視される（4.7）"))
    for k in ("rua", "ruf"):
        if k in tags:
            uris = []
            for u in tags[k].split(","):
                u = u.strip()
                if not u:
                    continue
                if "!" in u:
                    findings.append(("INFO", "%s の %s にレポートサイズ指定（obs-dmarc-uri）。RFC 9989 で廃止、無視される" % (k, u)))
                    u = u.split("!", 1)[0]
                if ":" not in u:
                    findings.append(("WARN", "%s の %r は URI ではない" % (k, u)))
                    continue
                uris.append(u)
            tags[k + "_uris"] = uris
    if "p" not in tags:
        if tags.get("rua_uris"):
            findings.append(("WARN", "p タグが無い（または無効）。rua があるので p=none として扱う（4.10.1）"))
            tags["p"] = "none"
            tags["p_assumed"] = True
        else:
            findings.append(("ERROR", "p タグが無く rua も無い。受信側は DMARC 処理をしない（4.10.1）"))
            return {"tags": tags, "findings": findings, "valid": False}
    return {"tags": tags, "findings": findings, "valid": True}


def valid_records(txts):
    """DMARC レコードとして有効な TXT だけ返す。複数あれば（4.10 手順2）全部捨てる"""
    recs = [t for t in txts if is_dmarc(t)]
    return recs if len(recs) == 1 else []


# ---------------------------------------------------------------- Tree Walk
def walk_targets(domain):
    """4.10 手順3〜8。domain 自身は含めず、次の問い合わせ先の列を返す（最大 7 個）"""
    labels = domain.lower().rstrip(".").split(".")
    x = len(labels)
    cur = labels[1:] if x < MAX_LABELS else labels[x - 7:]
    out = []
    while cur:
        out.append(".".join(cur))
        cur = cur[1:]
    return out


def tree_walk(domain, lookup):
    """domain 自身から始めて、有効なレコードが見つかった名前と psd 値を順に返す。
    psd=n / psd=y を含むレコードで停止（4.10 手順2・6）"""
    found, queries = [], []
    for t in [domain.lower().rstrip(".")] + walk_targets(domain):
        st, ad, txts = lookup("_dmarc." + t)
        queries.append("_dmarc." + t)
        recs = valid_records(txts)
        if recs:
            tags = parse_record(recs[0])["tags"]
            psd = tags.get("psd", "u")
            found.append((t, psd, recs[0], ad))
            if psd in ("n", "y"):
                break
    return found, queries


def org_domain(domain, lookup):
    """4.10.2: 組織ドメインの決定"""
    domain = domain.lower().rstrip(".")
    found, _ = tree_walk(domain, lookup)
    for t, psd, _, _ in found:                       # 長い方から
        if psd == "n":
            return t
    for t, psd, _, _ in found:
        if psd == "y" and t != domain:
            # psd=y の 1 ラベル下
            return domain[: domain.rfind("." + t)].split(".")[-1] + "." + t
    if found:
        return found[-1][0]                           # 最もラベル数が少ないもの
    return domain


# ---------------------------------------------------------------- 外部宛先の認可（RFC 9990 4）
def verify_external(domain, host, lookup):
    name = "%s._report._dmarc.%s" % (domain, host)
    if len(name) > 253:
        return name, False, "名前が DNS の上限を超える（手順4）"
    st, ad, txts = lookup(name)
    if st not in (0, 3):
        return name, False, "DNS エラー status=%d" % st
    recs = [t for t in txts if is_dmarc(t)]
    if not recs:
        return name, False, "v=DMARC1 のレコードが無い（status=%d）" % st
    # 上書き rua があれば同じホストでなければならない
    for r in recs:
        tags = parse_record(r)["tags"]
        for u in tags.get("rua_uris", []):
            m = re.match(r"^mailto:[^@]+@([^\s]+)$", u, re.I)
            if m and m.group(1).lower() != host.lower():
                return name, False, "認可レコードの rua が別ホスト %s を指す。両方とも送信禁止" % m.group(1)
    return name, True, "認可あり"


# ---------------------------------------------------------------- 判定
def check(domain, lookup=doh_txt):
    domain = domain.lower().rstrip(".")
    out = {"domain": domain, "findings": [], "record_at": None, "record": None,
           "policy": None, "effective": None, "external": []}
    st, ad, txts = lookup("_dmarc." + domain)
    if st not in (0, 3):
        raise RuntimeError("DNS 応答が異常: status=%d" % st)
    recs = [t for t in txts if is_dmarc(t)]
    if len(recs) > 1:
        out["findings"].append(("ERROR", "_dmarc.%s に DMARC レコードが %d 本。全部無視される（4.10 手順2）" % (domain, len(recs))))
    if len(recs) == 1:
        out["record_at"] = domain
        out["record"] = recs[0]
        out["dnssec_ad"] = ad
        subdomain = False
    else:
        # Tree Walk（起点は親）
        found, queries = tree_walk(domain, lookup)
        found = [f for f in found if f[0] != domain]
        out["walk"] = queries
        if not found:
            out["findings"].append(("INFO", "DMARC レコード無し。Tree Walk（%d 問い合わせ）でも見つからない。DMARC は適用されない" % len(queries)))
            out["policy"] = "none-published"
            return out
        t, psd, rec, ad = found[0]
        out["record_at"] = t
        out["record"] = rec
        out["dnssec_ad"] = ad
        subdomain = True
        out["findings"].append(("INFO", "%s 自身にレコードは無く、%s のレコードを適用（4.10.1）" % (domain, t)))

    parsed = parse_record(out["record"])
    out["findings"] += parsed["findings"]
    tags = parsed["tags"]
    out["tags"] = {k: v for k, v in tags.items() if not k.endswith("_uris")}
    if not parsed["valid"]:
        out["policy"] = "invalid"
        return out

    p = tags["p"]
    if subdomain:
        # 存在するサブドメインとして sp → p。np は非存在ドメイン用なので適用しない
        eff = tags.get("sp", p)
        out["effective"] = eff
        out["findings"].append(("INFO", "サブドメインなので適用ポリシーは sp=%s（無ければ p）" % eff))
    else:
        out["effective"] = p
    out["policy"] = p
    if tags.get("t", "n") == "y" and p != "none":
        out["findings"].append(("INFO", "t=y: テストモード。受信側は 1 段階緩いポリシーを適用する（4.7）"))
    if "np" in tags:
        out["findings"].append(("INFO", "np=%s: 存在しないサブドメイン向けポリシー（RFC 9989 新設）" % tags["np"]))
    if tags.get("psd", "u") != "u":
        out["findings"].append(("INFO", "psd=%s（RFC 9989 新設）" % tags["psd"]))
    if not tags.get("rua_uris"):
        out["findings"].append(("INFO", "rua 無し。集計レポートは生成されない（4.7）"))

    # 外部宛先の認可
    own_org = org_domain(out["record_at"], lookup)
    out["org_domain"] = own_org
    checked = set()
    for k in ("rua", "ruf"):
        for u in tags.get(k + "_uris", []):
            m = re.match(r"^mailto:[^@]+@([^\s]+)$", u, re.I)
            if not m:
                out["findings"].append(("INFO", "%s の %s は mailto 以外。受信側が対応しなければ無視" % (k, u)))
                continue
            host = m.group(1).lower()
            if host in checked:
                continue
            checked.add(host)
            host_org = org_domain(host, lookup)
            if host_org == own_org:
                out["external"].append({"tag": k, "host": host, "external": False, "host_org": host_org})
                continue
            name, ok, why = verify_external(out["record_at"], host, lookup)
            out["external"].append({"tag": k, "host": host, "external": True, "host_org": host_org,
                                    "query": name, "authorized": ok, "why": why})
            if not ok:
                out["findings"].append(("ERROR", "%s の宛先 %s は外部（組織ドメイン %s ≠ %s）だが認可レコードが無い。受信側はこの URI を無視する（RFC 9990 4）: %s"
                                        % (k, host, host_org, own_org, why)))
    return out


def fmt(r):
    L = ["対象        : %s" % r["domain"]]
    if r["record"] is None:
        L.append("レコード    : なし（Tree Walk %d 回）" % len(r.get("walk", [])))
    else:
        L.append("レコード    : _dmarc.%s%s" % (r["record_at"], "（DNSSEC AD）" if r.get("dnssec_ad") else ""))
        L.append("  " + r["record"])
        L.append("ポリシー    : p=%s → 適用 %s" % (r["policy"], r["effective"]))
        if r.get("org_domain"):
            L.append("組織ドメイン: %s" % r["org_domain"])
    for e in r["external"]:
        if e["external"]:
            L.append("  %s → %s  外部（%s）: %s" % (e["tag"], e["host"], e["host_org"], "認可あり" if e["authorized"] else "認可なし → 無視される"))
        else:
            L.append("  %s → %s  同一組織" % (e["tag"], e["host"]))
    for lv, msg in r["findings"]:
        L.append("  [%s] %s" % (lv, msg))
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domain")
    ap.add_argument("--fixtures", help="テキスト形式の DNS 応答で動く（ネットワークに出ない）")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    lookup = FixtureLookup(a.fixtures) if a.fixtures else doh_txt
    r = check(a.domain, lookup)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else fmt(r))
    return 1 if any(lv == "ERROR" for lv, _ in r["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
