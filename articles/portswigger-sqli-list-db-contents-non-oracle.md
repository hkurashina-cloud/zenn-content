---
title: "SQLi: listing the database contents on non-Oracle databases"
emoji: "🗂️"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: ["ctf", "portswigger", "sqli", "postgresql"]
published: false
---

## はじめに

PortSwigger Web Security Academy の SQL injection ラボ、[SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)（**Practitioner**）を題材にします。

これまでのバージョン確認ラボの応用編で、今回は **`information_schema` を辿ってテーブル → 列 → データと掘り進み、最終的に administrator のパスワードを盗んでログイン** します。DB は PostgreSQL（＝non-Oracle）です。

そして正直に書くと、**手順そのものより「目的のテーブルを見つける」ところで一番つまずきました**。この記事では、きれいな解法だけでなく **実際に自分がハマった点と、どう抜け出したか** を残します。

## 攻撃の全体像

UNION ベース SQLi で、次の4段階を踏みます。

1. **列数とテキスト列を確定**（UNION の土台作り）
2. **`information_schema.tables` でテーブル一覧** → 認証情報テーブルを特定
3. **`information_schema.columns` で列一覧** → ユーザー名・パスワード列を特定
4. **その表からデータ取得** → administrator の資格情報を抜く

注入点は商品カテゴリフィルタ `category` です。

## ステップ1: 列数とテキスト列を確認する

まず UNION の受け皿となる列構成を確定します。

```
'+UNION+SELECT+'abc','def'--
```

`abc` / `def` が画面に出れば **2列・両方テキスト** と分かります。以降は「1列目に見たい値、2列目は `NULL`」で組み立てます。

## ステップ2: テーブル一覧を取得する（← ここで大ハマり）

定石どおり、まずは全テーブルを列挙します。

```
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
```

これで一覧は出るのですが——**PostgreSQL のシステムテーブルが大量に混ざって返ってきます**（`pg_partitioned_table`、`pg_available_extension_versions`、`user_defined_types`、`schemata` …）。しかもラボの商品説明（Pest Control Umbrella などの長文）とも混ざるので、目的の1つを目視で探すのが非常につらい。

### つまずき①: `LIKE 'users%'` で絞ったら空振りした

「users で始まるテーブルだろう」と当たりを付けて、こう絞りました。

```
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables+WHERE+table_name+LIKE+'users%'--
```

ところが **0件**。商品一覧だけが返り、注入行がありません。原因は2つ:

- **PostgreSQL の `LIKE` は大文字小文字を区別する**
- `users%` は「**先頭が** users」しかマッチしない。目的の表は `users_〇〇〇` という **ランダム接尾辞付き** の名前で、頭が `users` でも、システム表の海に紛れて見つけにくかった

### つまずき②: 誤ヒットを「これだ」と勘違い

次に `ILIKE '%user%'`（大文字小文字無視・部分一致）で緩めに探すと、`user_defined_types` がヒットしました。名前に user が入っているので「これか？」と思いましたが——**これは情報スキーマのシステムビュー（ユーザー定義型のメタデータ）で、認証情報は入っていません**。`%user%` はシステム表の名前にも引っかかるので、**「user を含む＝目的の表」ではない** と痛感しました。

### 抜け出し方: スキーマで絞るのが正解だった

決め手は **「名前」ではなく「スキーマ」で絞る** ことでした。アプリが作ったテーブルは `public` スキーマにあり、`pg_〜`（`pg_catalog`）や `information_schema` のシステム表はそれ以外のスキーマにあります。

```
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables+WHERE+table_schema='public'--
```

これで返るのは **アプリ自身のテーブルだけ**——`products` と、目的の `users_viiizs`。数百行のノイズが一気に消えて一発で特定できました。

:::message
**教訓**: `information_schema.tables` を辿るときは、まず `WHERE table_schema='public'` でシステム表を除外する。名前でのフィルタ（`LIKE 'users%'`）は、命名規則が読めない・大文字小文字が絡む・部分一致が誤爆する、と落とし穴が多い。
:::

（ノイズごと全件見たい場合は、フィルタなしで出してブラウザの `Cmd+F` で `user` を検索、というローテクも有効です。）

## ステップ3: 列名を取得する（← 500 でつまずいた）

目的の表 `users_viiizs` が分かったら、その **列名** を取ります。

### つまずき③: `column_name` を `.tables` から取ろうとして 500

うっかりこう書いて **500 Internal Server Error** を出しました。

```sql
-- ❌ 500 になる
' UNION SELECT column_name, NULL FROM information_schema.tables--
```

`information_schema.tables` ビューに `column_name` **列は存在しません**（あるのは `table_name`, `table_schema` など）。列名が欲しいときは **`information_schema.columns`** を使う、と対応づければ間違えません。

```
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_viiizs'--
```

これで、この表の列が返りました。

- `username_mpjzft`
- `password_uesucj`
- `email`

ユーザー名列・パスワード列にも **ランダム接尾辞** が付いている点に注意。ここも決め打ちできないので、必ずこのステップで実名を確認します。

![information_schema.columns で users_viiizs の列名（username_mpjzft / password_uesucj）が取得できた画面](画像URLをここに)

## ステップ4: administrator の資格情報を取得する

役者が揃いました。テーブル `users_viiizs`、ユーザー名列 `username_mpjzft`、パスワード列 `password_uesucj`。1列目に username、2列目に password を載せ、`WHERE` で administrator に絞ります。

```
'+UNION+SELECT+username_mpjzft,+password_uesucj+FROM+users_viiizs+WHERE+username_mpjzft='administrator'--
```

（全ユーザーを一覧して administrator を探すなら `WHERE` を外した `... FROM users_viiizs--` でもよい）

レスポンスに `administrator` とそのパスワードが1行で返ります。

![UNION SELECTでadministratorのusernameとpasswordが取得できた画面](画像URLをここに)

あとは `My account` のログイン画面で **Username: `administrator`** / **Password: 取得した文字列** を入力すればソルブです。

![取得した認証情報でadministratorとしてログインできた画面](画像URLをここに)

## この検証から得た教訓（つまずき総まとめ）

- **目的のテーブルは「名前」でなく「スキーマ」で探す**。`WHERE table_schema='public'` でシステム表を除外するのが最短。`LIKE 'users%'` は大文字小文字・先頭一致・命名規則の不確実性で空振りしやすい。
- **`%user%` の部分一致は誤爆する**。`user_defined_types` のようなシステムビューが引っかかる。「名前に user が入っている＝認証テーブル」ではない。
- **列名は `information_schema.columns` から。`.tables` には `column_name` 列は無い**（投げると 500）。「テーブル名＝tables / 列名＝columns」と対応づける。
- **テーブル名も列名もランダム接尾辞付き**（`users_viiizs` / `username_mpjzft` / `password_uesucj`）。配布ペイロードの `users_abcdef` はプレースホルダで、**各ステップで実名を確定してから次に進む** のが鉄則。決め打ちは事故のもと。
- 500 が返ったら「フィルタで弾かれた」ではなく「**クエリ構造を壊した**」サイン。存在しない列を参照した、などスキーマの取り違えを疑う。
- 根本対策はこれまで同様 **パラメータ化クエリ**。`information_schema` を辿れる時点で、入力がクエリ構造に影響できてしまっている。
