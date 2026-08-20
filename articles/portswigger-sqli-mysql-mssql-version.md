---
title: "SQLi: querying the database type and version on MySQL and Microsoft"
emoji: "🔎"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: ["ctf", "portswigger", "sqli", "mysql"]
published: false
---

## はじめに

PortSwigger Web Security Academy の SQL injection ラボ、[SQL injection attack, querying the database type and version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)（**Practitioner**）を題材にします。

前回の [Oracle 版](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle) と **やることは同じ**（UNION 攻撃で DB のバージョン文字列を表示）ですが、対象が **MySQL / Microsoft SQL Server** に変わることで、使う構文が微妙に違ってきます。この記事では、Oracle 版との **差分** に注目しながら解いていきます。

## Oracle 版との違い（先に整理）

同じ「バージョン表示」ラボでも、DB 方言によって次の3点が変わります。

| 項目 | Oracle | MySQL / Microsoft |
| --- | --- | --- |
| `SELECT` の `FROM` 句 | **必須**（`FROM dual` が要る） | **不要**（`SELECT 'abc','def'` だけで OK） |
| コメント記法 | `--` | `#`（MySQL）または `-- `（末尾スペース必須） |
| バージョン取得 | `BANNER FROM v$version` | `@@version` |

とくに `@@version` は **MySQL と Microsoft SQL Server の両方で通る** ため、この2つをまとめて1つのラボで扱えるわけです。「効いたクエリから DB 種別を逆算する」という前回の fingerprinting の考え方はそのまま活きます。

## ラボ概要

商品一覧はカテゴリでフィルタでき、`category` パラメータが UNION 攻撃の注入点です。元のクエリはおおよそこうです。

```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```

手順は Oracle 版と同じで、**列数とテキスト列を確定 → バージョンを表示** の2ステップです。

## ステップ1: 列数とテキスト列を確認する

列数が2・両方テキストだと当たりを付けて、次を `category` に入れます。MySQL では `FROM` が不要なので、そのまま値を SELECT できます。

```
'+UNION+SELECT+'abc','def'#
```

URL デコードすると実体はこうです（`#` は MySQL の行コメント）。

```sql
' UNION SELECT 'abc','def'#
```

組み上がるクエリを復元するとこうなります。

```sql
SELECT name, description FROM products WHERE category = '' UNION SELECT 'abc','def'#'
```

- `category = ''` … 空文字列で元の結果を空にする
- `UNION SELECT 'abc','def'` … 2列（両方テキスト）を返す追加クエリ（`FROM` は不要）
- `#` … アプリが末尾に付ける `'` を含め、以降を **コメントアウト**

レスポンスに `abc` / `def` が現れれば、**列数は2・両方テキスト** と確定します。

![UNION SELECT 'abc','def'# で abc/def が表示され、2列・テキスト列と確認できた画面](画像URLをここに)

:::message
`#` の代わりに `-- `（ハイフン2つ + **末尾スペース**）でも構いません。MySQL では `--` の直後にスペースが必要な点に注意。URL に載せるときは `--+` のように `+`（＝スペース）を明示すると安全です。
:::

## ステップ2: バージョン文字列を表示する

列構成が分かったら、片方の列に `@@version` を流し込みます。

```
'+UNION+SELECT+@@version,+NULL#
```

URL デコード後:

```sql
' UNION SELECT @@version, NULL#
```

- `@@version` … 1列目にバージョン文字列を載せる（MySQL / MS SQL 共通のシステム変数）
- `NULL` … 2列目は使わないので NULL で埋める（列数合わせ）

送信すると、レスポンスに **MySQL（または Microsoft SQL Server）のバージョン文字列** が表示されます。

![UNION SELECT @@version, NULL でバージョン文字列が表示された画面](画像URLをここに)

これでラボはソルブです。

## この検証から得た教訓

- **同じ攻撃でも DB 方言で構文が変わる**。`FROM` の要否・コメント記法・バージョン取得関数の3点は DB ごとに要チェック。Oracle の `FROM dual` / `v$version` に対し、MySQL・MS SQL は `FROM` 不要 / `@@version`。
- **`@@version` は MySQL と Microsoft の両対応**。逆に言えば、`@@version` が通って `v$version` が通らなければ「Oracle ではない」と絞り込める。**通る/通らないの差分そのものが fingerprint** になる。
- **コメントは `#` か `-- `（末尾スペース）**。URL 経由では `#` は素直だが、`--` を使うなら `--+` でスペースを明示しないと後続の `'` を消し損ねて構文エラーになりがち。
- UNION 攻撃の基本（**列数とテキスト列の確定 → 目的の値を該当列に、残りは NULL**）は DB を問わず共通。方言差はここに上乗せされるレイヤーと捉えると整理しやすい。
- 根本対策はこれまで同様 **パラメータ化クエリ**。
