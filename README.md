# dmarcrec

DMARC ポリシーレコードを **RFC 9989（2026年5月、RFC 7489 を廃止）と RFC 9990** のとおりに読み、
外部レポート宛先の認可まで確認するスクリプトです。Python 標準ライブラリだけで動きます。

## 使い方

```
git clone https://github.com/ac5net/dmarcrec.git
cd dmarcrec
python3 dmarcrec.py <ドメイン> [--json]
```

例

```
python3 dmarcrec.py kddi.com
python3 dmarcrec.py rx.rakuten.co.jp
```

DNS は DoH（dns.google）で引きます。`--fixtures <txt>` を渡すとネットワークに出ず、テキストに書いた応答で動きます（テストと再現用）。

## 何をしているか

- `_dmarc.<ドメイン>` の TXT を取る。無ければ **DNS Tree Walk**（RFC 9989 4.10）で組織ドメイン／PSD のレコードを探し、
  サブドメインなら `sp`（無ければ `p`）を適用ポリシーにする（4.10.1）
- レコードを 4.7 / 4.8 の定義で解析する
  - `v=DMARC1` が先頭でなければレコード全体を無視。値は大文字小文字を区別する
  - タグ名・値は大文字小文字を区別する（RFC 6376 3.2）。`P=reject` は未知タグ扱い
  - 未知タグは無視。`p` が無効でも `rua` があれば `p=none` として扱う（4.10.1）
  - RFC 7489 にあって RFC 9989 で削除された **`pct` / `ri` / `rf`** は「受信側に無視される」と指摘（C.5.2、A.6）
  - 新設の `np` / `psd` / `t` を読む
- `rua` / `ruf` の宛先ホストごとに Tree Walk で組織ドメインを求め、レコードの組織ドメインと違えば
  `<ドメイン>._report._dmarc.<宛先ホスト>` の TXT を引いて**外部宛先の認可**を確認する（RFC 9990 4、`ruf` は RFC 9991 5）。
  認可レコードが無い URI は受信側に無視される

## 主要30ドメイン＋参照6ドメインの実測（2026年10月12日）

- 主要30ドメインの `p`: **reject 17 / quarantine 8 / none 3 / レコード無し 2**（softbank.jp, ocn.ne.jp）
- RFC 9989 で削除された `pct` を含むレコード 12 件、`ri` 4 件
- 外部レポート宛先 28 件のうち認可レコードあり 27 件。**認可が無い 1 件**: kddi.com の `rua` の 2 つ目（ezweb.ne.jp）は
  `kddi.com._report._dmarc.ezweb.ne.jp` が NXDOMAIN で、受信側はこの URI を無視する
- 新設タグの実例: securemx.jp（smbc.co.jp のレポート宛先）が `np=reject; psd=n` を公開

`fixtures/live-2026-10-12.txt` はその日に dns.google から取得した 113 件の TXT 応答です（Tree Walk と認可確認で引いた名前をすべて含む）。

## テスト

```
python3 test_dmarcrec.py
```

ネットワークに出ないのでオフラインで実行できます。RFC 9989 4.10.2 の組織ドメインの例 3 つ、RFC 9990 4 の
`blue.example.com` → `red.example.net` の例、タグ解析の境界、実データ 36 ドメインの集計を 70 件のアサーションで確認します。

## 解説記事

RFC 9989 で何が変わったか、36 ドメインの結果、落とし穴の経緯はブログに書いています。

https://ac-5.net/security/dmarc-record-rfc9989-check/

## ライセンス

MIT
