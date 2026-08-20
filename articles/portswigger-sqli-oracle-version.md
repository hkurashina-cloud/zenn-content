---
title: "SQL injection attack, querying the database type and version on Oracle"
emoji: "🔎"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: ["ctf", "portswigger", "sqli", "oracle"]
published: false
---

## はじめに

PortSwigger Web Security Academy の SQL injection ラボ、[SQL injection attack, querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)（**Practitioner**）を題材にします。

これまでは「認証バイパス」や「隠しデータの取得」がゴールでしたが、今回のテーマは **データベースの調査（fingerprinting）**。攻撃の下準備として、DB の種類とバージョンを特定します。ゴールは、商品カテゴリフィルタの UNION ベース SQLi を使って **データベースのバージョン文字列を表示させる** ことです。

そして今回の主役は **Oracle 特有の作法** ——「すべての `SELECT` は `FROM` 句を必須とする」という制約への対処です。

## ラボ概要

商品一覧はカテゴリでフィルタでき、`category` パラメータが UNION 攻撃の注入点になります。元のクエリはおおよそこうです。

```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```

UNION 攻撃で `users` などの別テーブルを狙う前に、まず **列数** と **どの列がテキストを返すか**、そして **DB の種類・バージョン** を確定させます。

## ステップ1: 列数とテキスト列を確認する

UNION する SELECT は、元のクエリと **同じ列数** を返さなければなりません。ここで Oracle の落とし穴が登場します。

:::message
**Oracle では、すべての `SELECT` 文が `FROM` 句を必要とします**。MySQL や PostgreSQL のように `UNION SELECT 'abc'` とは書けません。テーブルを指定しない値だけの SELECT でも、`FROM` に有効なテーブル名が要ります。
:::

Oracle にはこの用途のための **組み込みダミーテーブル `dual`** があります。1行1列を持つだけのテーブルで、「定数を SELECT したいだけ」のときに使います。

列数が2・両方テキストだと当たりを付けて、次を `category` に入れます。

```
'+UNION+SELECT+'abc','def'+FROM+dual--
```

URL デコードすると実体はこうです。

```sql
' UNION SELECT 'abc','def' FROM dual--
```

組み上がるクエリを復元するとこうなります。

```sql
SELECT name, description FROM products WHERE category = '' UNION SELECT 'abc','def' FROM dual-- '
```

- `category = ''` … 空文字列で元の結果を空にする
- `UNION SELECT 'abc','def' FROM dual` … 2列（両方テキスト）を返す追加クエリ
- `--` … アプリが付ける末尾の `'` を無効化

レスポンスに `abc` / `def` が現れれば、**列数は2・両方ともテキストデータを扱える** ことが確定します。もし列数が合わなければエラー、テキスト非対応の列に文字列を入れてもエラーになるので、それを手がかりに調整します。

![UNION SELECT 'abc','def' FROM dual で abc/def が表示され、2列・テキスト列と確認できた画面](画像URLをここに)

## ステップ2: バージョン文字列を表示する

列構成が分かったら、片方の列に **Oracle のバージョン情報** を流し込みます。Oracle ではバージョンは `v$version` ビューの `BANNER` 列から取れます。

```
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
```

URL デコード後:

```sql
' UNION SELECT BANNER, NULL FROM v$version--
```

- `BANNER` … 1列目にバージョン文字列を載せる（テキスト列）
- `NULL` … 2列目は使わないので NULL で埋める（列数合わせ）
- `FROM v$version` … Oracle のバージョン情報ビュー

送信すると、レスポンスに **Oracle のバージョン文字列** が表示されます。

![UNION SELECT BANNER, NULL FROM v$version でOracleのバージョン文字列が表示された画面](画像URLをここに)

これでラボはソルブです。

## なぜ「DB の種類・バージョン特定」が重要なのか

バージョン特定は地味ですが、以降の攻撃の土台になります。

- **方言（dialect）の選択**: 文字列連結（`||` か `+` か `CONCAT`）、コメント記法、バージョン取得関数などは DB ごとに違う。今回のように `SELECT @@version`（SQL Server/MySQL）が効かず `v$version`（Oracle）なら効く、という **効く/効かないの差から DB 種別を逆算** できる。
- **既知の脆弱性の適用**: バージョンが分かれば、そのバージョン固有の CVE や機能（`xp_cmdshell` など）が使えるかを判断できる。
- **次の一手の精度**: `information_schema.tables`（多くのDB）か Oracle 固有のカタログか、といったテーブル列挙の方針も DB 種別で変わる。

「どの DB か」を先に確定させることが、UNION 攻撃を安定して回すための前提になります。

## この検証から得た教訓

- **Oracle では `SELECT` に `FROM` が必須**。値だけを返したいときは組み込みの `dual` テーブルを使う（`SELECT 'abc' FROM dual`）。DB 方言の差を知らないと、正しいロジックでも文法エラーで詰まる。
- **UNION 攻撃はまず「列数」と「テキスト列の位置」の確定から**。`'abc','def'` のような既知の目印を返して、どの列が画面に出るか・文字列を扱えるかを見極める。使わない列は `NULL` で埋めて列数を合わせる。
- **バージョン取得クエリが DB 判定を兼ねる**。`@@version` / `v$version` / `version()` のどれが通るかで DB 種別が分かる。fingerprinting は攻撃の入口。
- 根本対策はこれまで同様 **パラメータ化クエリ**。UNION 注入も、入力を文字列連結でクエリに混ぜている限り成立する。
