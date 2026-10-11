#!/usr/bin/env python3
"""dmarcrec.py のオフラインテスト。RFC 9989 / 9990 の例と、実データで踏んだ落とし穴を固定する。"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dmarcrec as d  # noqa: E402

N = 0


def ok(cond, msg):
    global N
    N += 1
    if not cond:
        raise AssertionError("#%d %s" % (N, msg))


def static(table):
    """{name: [txt, ...]} → lookup。無い名前は NXDOMAIN"""
    def lookup(name):
        key = name.lower().rstrip(".")
        if key in table:
            return 0, False, list(table[key])
        return 3, False, []
    return lookup


def findings(r, level=None):
    return [m for lv, m in r["findings"] if level is None or lv == level]


# ---- 4.7 "v": 先頭・大文字小文字 ------------------------------------------
ok(d.is_dmarc("v=DMARC1; p=none"), "v=DMARC1 先頭")
ok(d.is_dmarc("v=DMARC1"), "v だけでも形式上は DMARC レコード")
ok(d.is_dmarc("v = DMARC1 ; p=none"), "equals の前後の WSP は許される（4.8）")
ok(not d.is_dmarc("p=none; v=DMARC1"), "v が先頭でなければ無効")
ok(not d.is_dmarc("v=dmarc1; p=none"), "値は大文字小文字を区別する")
ok(not d.is_dmarc("v=DMARC1x; p=none"), "DMARC1 の後に余計な文字")
ok(not d.is_dmarc("v=spf1 -all"), "SPF は DMARC ではない")

# ---- 4.7 / 4.8 タグ解析 ---------------------------------------------------
p = d.parse_record("v=DMARC1; p=reject; sp=quarantine; np=reject; adkim=s; aspf=r; fo=1:d:s; t=y; psd=n; rua=mailto:a@example.com; ruf=mailto:b@example.com")
ok(p["valid"] and p["tags"]["p"] == "reject" and p["tags"]["np"] == "reject" and p["tags"]["t"] == "y" and p["tags"]["psd"] == "n", "RFC 9989 の全タグを読める")
ok(p["tags"]["rua_uris"] == ["mailto:a@example.com"], "rua の URI 列")
p = d.parse_record("v=DMARC1; p=reject; pct=100; ri=3600; rf=afrf; rua=mailto:a@example.com")
ok(p["valid"] and all(any(k in m for m in findings(p, "INFO")) for k in ("pct=100", "ri=3600", "rf=afrf")), "削除された pct / ri / rf を INFO で指摘し、無効にはしない（C.5.2）")
p = d.parse_record("v=DMARC1; p=reject; foo=bar; rua=mailto:a@example.com")
ok(p["valid"] and any("未知タグ foo" in m for m in findings(p)), "未知タグは無視（4.8）")
p = d.parse_record("v=DMARC1; p=bogus; rua=mailto:a@example.com")
ok(p["valid"] and p["tags"]["p"] == "none" and p["tags"].get("p_assumed"), "p が無効でも rua があれば p=none 扱い（4.10.1）")
p = d.parse_record("v=DMARC1; p=bogus")
ok(not p["valid"], "p が無効で rua も無ければ DMARC 処理なし（4.10.1）")
p = d.parse_record("v=DMARC1; rua=mailto:a@example.com")
ok(p["valid"] and p["tags"]["p"] == "none", "p が無くても rua があれば p=none（4.7）")
p = d.parse_record("v=DMARC1; p=none; rua=mailto:a@example.com!10m")
ok(p["tags"]["rua_uris"] == ["mailto:a@example.com"] and any("obs-dmarc-uri" in m for m in findings(p)), "サイズ指定 !10m は捨てて URI だけ残す（4.8 obs-dmarc-uri）")
p = d.parse_record("v=DMARC1; p=none; rua=mailto:a@example.com, mailto:b@example.net")
ok(len(p["tags"]["rua_uris"]) == 2, "カンマの後の空白は許される（dmarc-urilist の *WSP）")
p = d.parse_record("v=DMARC1; p=none; fo=1")
ok(any("ruf が無いので fo は無視" in m for m in findings(p)), "ruf 無しの fo は無視される（4.7）")
p = d.parse_record("v=DMARC1; p=none; ruf=mailto:x@example.com; fo=0:1")
ok(any("dmarc-fo 構文" in m for m in findings(p, "WARN")), "fo=0:1 は 0 と 1 が排他なので構文違反")
for good in ("0", "1", "d", "s", "1:d", "1:d:s", "d:s", "s:d", "d:1", "0:d:s"):
    pp = d.parse_record("v=DMARC1; p=none; ruf=mailto:x@example.com; fo=%s" % good)
    ok(not any("dmarc-fo 構文" in m for m in findings(pp, "WARN")), "fo=%s は構文どおり" % good)
p = d.parse_record("v=DMARC1; p=none; p=reject; rua=mailto:a@example.com")
ok(p["tags"]["p"] == "none" and any("重複" in m for m in findings(p)), "タグ重複は最初の値（落とし穴：後勝ちにしていた）")
p = d.parse_record("v=DMARC1; P=reject; rua=mailto:a@example.com")
ok(p["tags"]["p"] == "none" and p["tags"].get("p_assumed") and any("大文字小文字を区別" in m for m in findings(p, "WARN")),
   "落とし穴：タグ名は大文字小文字を区別する（RFC 6376 3.2）。P= は未知タグ → p 無し → rua があるので p=none")
p = d.parse_record("v=DMARC1; p=Reject; rua=mailto:a@example.com")
ok(p["tags"]["p"] == "none" and any("大文字小文字が違う" in m for m in findings(p, "ERROR")), "値も区別する。p=Reject は無効 → p=none 扱い")
p = d.parse_record("v=DMARC1; p=none;")
ok(p["valid"], "末尾の ';' は許される（dmarc-record の [dmarc-sep]）")
p = d.parse_record("v=DMARC1;p=quarantine;pct=100;rua=mailto:report@dmarc.example.com;ruf=mailto:report@dmarc.example.com")
ok(p["valid"] and p["tags"]["p"] == "quarantine", "空白なしの詰めた記法（amazon.com 形式）")

# ---- 4.10 Tree Walk の問い合わせ列 ------------------------------------------
ok(d.walk_targets("a.mail.example.com") == ["mail.example.com", "example.com", "com"], "x<8: 親から TLD まで")
ok(d.walk_targets("a.b.c.d.e.f.g.h.i.j.mail.example.com") == ["g.h.i.j.mail.example.com", "h.i.j.mail.example.com", "i.j.mail.example.com", "j.mail.example.com", "mail.example.com", "example.com", "com"],
   "x>=8: 7 ラベルに切り詰めてから登る（4.10 の例と同じ 8 問い合わせ）")
ok(d.walk_targets("example.com") == ["com"], "組織ドメイン自身なら TLD を 1 回だけ")

# 4.10.2 の例1: mail.example.com と example.com にレコード → 組織ドメインは example.com
lk = static({"_dmarc.mail.example.com": ["v=DMARC1; p=none"], "_dmarc.example.com": ["v=DMARC1; p=reject"]})
ok(d.org_domain("a.mail.example.com", lk) == "example.com", "4.10.2 例1: ラベル数が最少のもの")
# 例2: mail.example.com に psd=n
lk = static({"_dmarc.mail.example.com": ["v=DMARC1; p=none; psd=n"], "_dmarc.example.com": ["v=DMARC1; p=reject"]})
ok(d.org_domain("a.mail.example.com", lk) == "mail.example.com", "4.10.2 例2: psd=n がそのまま組織ドメイン")
# 例3: com に psd=y だけ
lk = static({"_dmarc.com": ["v=DMARC1; p=none; psd=y"]})
ok(d.org_domain("a.mail.example.com", lk) == "example.com", "4.10.2 例3: psd=y の 1 ラベル下")
# psd=y が起点自身なら対象外
lk = static({"_dmarc.example.com": ["v=DMARC1; p=none; psd=y"]})
ok(d.org_domain("example.com", lk) == "example.com", "起点自身の psd=y は 1 ラベル下の規則を使わない")
# 何も無ければ起点
ok(d.org_domain("nothing.example", static({})) == "nothing.example", "レコードが無ければ起点が組織ドメイン")
# 複数レコードは捨てる（4.10 手順2）
lk = static({"_dmarc.example.com": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]})
r = d.check("example.com", lk)
ok(r["record"] is None and any("2 本" in m for m in findings(r, "ERROR")), "同じ名前に 2 本あれば全部無視")
# SPF の TXT が同居していても DMARC は 1 本
lk = static({"_dmarc.example.com": ["v=spf1 -all", "v=DMARC1; p=reject"]})
ok(d.check("example.com", lk)["policy"] == "reject", "DMARC でない TXT は数えない")

# ---- 4.10.1 サブドメインの適用ポリシー ----------------------------------------
lk = static({"_dmarc.example.com": ["v=DMARC1; p=reject; sp=none"]})
r = d.check("sub.example.com", lk)
ok(r["record_at"] == "example.com" and r["effective"] == "none", "サブドメインは sp が優先")
lk = static({"_dmarc.example.com": ["v=DMARC1; p=reject"]})
ok(d.check("sub.example.com", lk)["effective"] == "reject", "sp が無ければ p")
ok(d.check("example.com", static({"_dmarc.example.com": ["v=DMARC1; p=reject; sp=none"]}))["effective"] == "reject", "組織ドメイン自身には sp を使わない")

# ---- RFC 9990 4: 外部宛先の認可 ----------------------------------------------
# blue.example.com → red.example.net
base = {"_dmarc.blue.example.com": ["v=DMARC1; p=none; rua=mailto:reports@red.example.net"],
        "_dmarc.red.example.net": ["v=DMARC1; p=none"]}
r = d.check("blue.example.com", static(base))
ok(r["external"][0]["external"] and not r["external"][0]["authorized"] and r["external"][0]["query"] == "blue.example.com._report._dmarc.red.example.net", "認可レコードが無ければ未認可")
ok(findings(r, "ERROR"), "未認可は ERROR")
base2 = dict(base); base2["blue.example.com._report._dmarc.red.example.net"] = ["v=DMARC1"]
r = d.check("blue.example.com", static(base2))
ok(r["external"][0]["authorized"] and not findings(r, "ERROR"), "v=DMARC1 の TXT があれば認可（例のとおり）")
base3 = dict(base); base3["blue.example.com._report._dmarc.red.example.net"] = ["v=DMARC1; rua=mailto:other@red.example.net"]
ok(d.check("blue.example.com", static(base3))["external"][0]["authorized"], "上書き rua が同じホストなら許可")
base4 = dict(base); base4["blue.example.com._report._dmarc.red.example.net"] = ["v=DMARC1; rua=mailto:other@green.example.org"]
r = d.check("blue.example.com", static(base4))
ok(not r["external"][0]["authorized"] and "別ホスト" in r["external"][0]["why"], "上書き rua が別ホストなら両方とも送信禁止")
base5 = dict(base); base5["blue.example.com._report._dmarc.red.example.net"] = ["v=spf1 -all"]
ok(not d.check("blue.example.com", static(base5))["external"][0]["authorized"], "v=DMARC1 以外の TXT は認可にならない")
# 同一組織なら認可不要（サブドメイン宛て）
lk = static({"_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:r@reports.example.com"]})
r = d.check("example.com", lk)
ok(not r["external"][0]["external"] and r["external"][0]["host_org"] == "example.com", "宛先が同じ組織ドメインなら外部ではない")

# ---- 実データ（2026-10-12）-----------------------------------------------------
fx = d.FixtureLookup(os.path.join(HERE, "fixtures", "live-2026-10-12.txt"))
r = d.check("kddi.com", fx)
ng = [e for e in r["external"] if e["external"] and not e["authorized"]]
ok(len(ng) == 1 and ng[0]["host"] == "ezweb.ne.jp" and ng[0]["query"] == "kddi.com._report._dmarc.ezweb.ne.jp", "kddi.com → ezweb.ne.jp は認可レコード無し（NXDOMAIN）")
ok([e for e in r["external"] if e["host"] == "dmarc25.jp"][0]["authorized"], "kddi.com → dmarc25.jp は認可あり")
r = d.check("gmail.com", fx)
ok(r["org_domain"] == "gmail.com" and r["external"][0]["host_org"] == "google.com" and r["external"][0]["authorized"], "gmail.com の rua は google.com（別組織）で、認可レコードあり")
r = d.check("rx.rakuten.co.jp", fx)
ok(r["record_at"] == "rakuten.co.jp" and not r["external"][0]["external"], "rx.rakuten.co.jp は Tree Walk で rakuten.co.jp に到達。同一組織")
r = d.check("biglobe.ne.jp", fx)
ok([e for e in r["external"] if e["host"] == "gp.biglobe.co.jp"][0]["host_org"] == "biglobe.co.jp", "gp.biglobe.co.jp の組織ドメインは biglobe.co.jp（ne.jp とは別）")
ok(all(e["authorized"] for e in r["external"] if e["external"]), "biglobe.ne.jp の外部宛先 2 件は認可あり")
r = d.check("outlook.com", fx)
ok(r["external"][0]["host_org"] == "dmarc.microsoft" and r["external"][0]["authorized"], "outlook.com → dmarc.microsoft（ブランド TLD）も認可あり")
r = d.check("smbc.co.jp", fx)
ok(d.org_domain("report.securemx.jp", fx) == "securemx.jp", "securemx.jp は psd=n でそこが組織ドメイン")
ok(any("pct=100" in m for m in findings(r)) and any("ri=86400" in m for m in findings(r)), "smbc.co.jp の pct / ri は削除済みタグとして指摘")
r = d.check("softbank.jp", fx)
ok(r["record"] is None and r["policy"] == "none-published" and r["walk"] == ["_dmarc.softbank.jp", "_dmarc.jp"], "softbank.jp: レコード無し。Tree Walk は _dmarc.jp まで")
r = d.check("ocn.ne.jp", fx)
ok(r["record"] is None and r["walk"] == ["_dmarc.ocn.ne.jp", "_dmarc.ne.jp", "_dmarc.jp"], "ocn.ne.jp: ne.jp → jp と登る")
r = d.check("jal.co.jp", fx)
ok(len(r["tags_uris"] if "tags_uris" in r else d.parse_record(r["record"])["tags"]["rua_uris"]) == 2, "jal.co.jp の ', mailto:' 区切りは 2 URI")
r = d.check("ac-5.net", fx)
ok(r["policy"] == "none" and r["external"][0]["authorized"], "ac-5.net は p=none、Cloudflare 宛て rua は認可あり")

main = ["google.com", "microsoft.com", "apple.com", "amazon.com", "cloudflare.com", "github.com", "salesforce.com", "zoom.us", "slack.com", "okta.com",
        "cybozu.com", "yahoo.co.jp", "softbank.jp", "mufg.jp", "smbc.co.jp", "ana.co.jp", "jal.co.jp", "rakuten.co.jp", "freee.co.jp", "sakura.ad.jp",
        "biglobe.ne.jp", "ocn.ne.jp", "so-net.ne.jp", "line.me", "japanpost.jp", "kddi.com", "mercari.com", "moneyforward.com", "nifty.com", "ntt.com"]
pol = {}
pct = ri = 0
ext_ok = ext_ng = 0
for n in main:
    r = d.check(n, fx)
    pol[r["policy"]] = pol.get(r["policy"], 0) + 1
    pct += "pct" in r.get("tags", {})
    ri += "ri" in r.get("tags", {})
    for e in r["external"]:
        if e["external"]:
            if e["authorized"]:
                ext_ok += 1
            else:
                ext_ng += 1
ok(pol == {"reject": 17, "quarantine": 8, "none": 3, "none-published": 2}, "主要30: reject 17 / quarantine 8 / none 3 / 無し 2: %r" % pol)
ok((pct, ri) == (12, 4), "削除済みタグ: pct 12 件、ri 4 件")
ok((ext_ok, ext_ng) == (27, 1), "外部宛先 28 件中 認可あり 27、無し 1")
ok(fx.missing == [], "フィクスチャに無い名前を引いていない: %r" % fx.missing)

print("OK: %d assertions passed" % N)
