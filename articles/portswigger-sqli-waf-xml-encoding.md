---
title: "PortSwigger: XMLエンコードでWAFを回避するUNIONベースSQLi"
emoji: "🧬"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: ["ctf", "portswigger", "sqli", "waf"]
published: false
---

## はじめに

PortSwigger Web Security Academy の SQL injection ラボ、[SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)（**Practitioner**）を題材にします。

これまでのラボはクエリ文字列（`?category=...`）への注入でしたが、今回は2つの新要素が加わります。

1. **注入点が XML ボディ** — 在庫チェック機能が `productId` / `storeId` を XML で送る
2. **WAF が立ちはだかる** — `UNION` や `SELECT` といった露骨な SQLi キーワードを含むリクエストはブロックされる

ゴールは、UNION ベースの SQLi で `users` テーブルから **admin の認証情報を抜き出し**、その資格情報でログインすること。カギは「WAF に検知されないよう、**XML エンティティエンコードでペイロードを難読化する**」ことです。

## ラボ概要と注入点の特定

商品詳細ページの在庫チェック機能は、`POST /product/stock` で次のような XML ボディを送ります。

```xml
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

まずこのリクエストを Burp Repeater に送り、`storeId` が **SQL として評価されているか** を探ります。数値を直接入れる代わりに、計算式を入れてみます。

```xml
<storeId>1+1</storeId>
```

これで store ID `2` の在庫が返ってくれば、`storeId` の中身がそのままクエリに埋め込まれ **サーバ側で評価されている** ことが分かります。注入点はここです。

## 詰まりポイント: UNION を投げると WAF に弾かれる

元のクエリは、店舗ごとの在庫を引く1カラムの SELECT だと推測できます（後で列数を確認します）。UNION 攻撃の定石どおり、まずは列数を調べるために `UNION SELECT NULL` を付けてみます。

```xml
<storeId>1 UNION SELECT NULL</storeId>
```

すると——**リクエストが「潜在的な攻撃」としてブロック** されます。`UNION SELECT` という露骨なキーワードが WAF のシグネチャに引っかかったのです。

ここが今回の本質的な壁です。ペイロードのロジックは正しいのに、**文字列パターンとして検知されて DB に届かない**。

## WAF 回避: XML エンティティエンコード

注入先が XML であることを逆手に取ります。XML パーサは、サーバ側で SQL インタプリタに渡す **前** に、XML の文字参照（エンティティ）をデコードします。つまり——

- WAF が見るのは **エンコードされた生バイト列**（`UNION` という文字列は現れない）
- SQL インタプリタが受け取るのは **デコード後の `UNION`**

という「時間差」を突けば、WAF のキーワード検知をすり抜けられます。例えば `SELECT` の `S` を16進文字参照 `&#x53;` に置き換えるだけでも、WAF から見れば `SELECT` という連続文字列は存在しなくなります。

```xml
<storeId>1 &#x53;ELECT * FROM information_schema.tables</storeId>
```

実務的には、ペイロード全体を16進エンティティに変換してしまうのが確実です。Burp の **Hackvertor 拡張** を使うと、入力を選択して右クリック → `Extensions > Hackvertor > Encode > hex_entities` で一括変換でき、`<@hex_entities>...<@/hex_entities>` タグで囲めば送信時に自動エンコードされます。

エンコードした `1 UNION SELECT NULL` を送り直して **通常のレスポンス（在庫数）が返れば、WAF 回避に成功** しています。

![XMLエンティティエンコードでUNION SELECTがWAFを通過し、正常レスポンスが返った画面](画像URLをここに)

## 列数の確認と、1カラム制約への対処

WAF を越えたら、UNION 攻撃の基本に戻ります。UNION する SELECT は、元のクエリと **同じ列数** を返す必要があります。

- `1 UNION SELECT NULL` … 正常に返る → **1カラム**
- 2カラム以上（`NULL,NULL`）にすると `0 units` が返る＝エラー → 列数が合っていない証拠

つまり返せるのは **1カラムだけ**。ところが欲しいのは username と password の **2つの値** です。そこで、**文字列連結でひとつのカラムにまとめて** 取り出します。区切り文字（ここでは `~`）を挟んで結合すると、あとで分解しやすくなります。

```sql
1 UNION SELECT username || '~' || password FROM users
```

`||` は標準 SQL（PostgreSQL / Oracle / SQLite など）の文字列連結演算子です。これを **hex_entities でエンコードして** `storeId` に入れます。

```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>
```

## 実証と解法の仕上げ

このリクエストを送ると、レスポンスに **`administrator~<パスワード>` のような形式で認証情報** が返ってきます。`~` で username と password が区切られているので、そこから admin の資格情報を取り出せます。

![UNION SELECTでusers テーブルの username~password が取得できた画面](画像URLをここに)

あとは取得した `administrator` のパスワードでログインすればソルブです。

![取得した認証情報でadministratorとしてログインできた画面](画像URLをここに)

## この検証から得た教訓

- **WAF は「入力の文字列パターン」を見ているだけで、SQL の意味を理解しているわけではない**。パーサ（今回は XML）のデコードとの間に処理の時間差があれば、エンコードで容易にすり抜けられる。防御としてキーワードのブラックリストは脆い。
- **注入コンテキスト（クエリ文字列 / JSON / XML）が変われば、使える難読化手段も変わる**。XML なら文字参照 `&#xNN;`、JSON ならユニコードエスケープ `\uNNNN` といった具合に、「サーバがデコードする層」を1枚挟めるかが回避の起点になる。
- **UNION 攻撃は列数が命**。1カラムしか返せない制約は、`||` などの連結でカラムを1本にまとめて回避する。取り出す値が複数あるときは区切り文字を挟むと後処理が楽。
- 根本対策は前回同様 **パラメータ化クエリ**。WAF はあくまで多層防御の一枚であって、アプリ側の安全なクエリ構築を代替するものではない——「WAF があるから大丈夫」は成り立たない、という良い実例。
