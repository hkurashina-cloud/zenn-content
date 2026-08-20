---
title: "PortSwigger: SQLi Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data"
emoji: "💉"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: ["ctf", "portswigger", "sqli", "security"]
published: false
---


## ラボ概要
(SELECT * FROM products WHERE category = 'Gifts' AND released = 1 の説明、目標)

## 最初の仮説: ' OR 1=1-- で全部出るはず
category パラメータに `' OR 1=1--` を入れれば未公開商品も出る、という前提でスタート。

## 詰まりポイント: --を外したらどうなる？
ふと「--部分って本当に必要なのか、OR 1=1 だけで押し切れないのか」を検証したくなった。

### 検証: --なしのpayload
\`\`\`
' OR 1=1
\`\`\`
→ クエリはこう変形される:
\`\`\`sql
SELECT * FROM products WHERE category = '' OR 1=1 AND released = 1
\`\`\`

### ここで考えるべき脆弱性クラス/知識: SQL演算子の優先順位
AND は OR より優先順位が高いので、実際の評価順は:
\`\`\`sql
category = '' OR (1=1 AND released = 1)
\`\`\`
→ 結局 released=1 の制約が生き残ってしまう

### 実証結果
Burp Repeaterで実際に投げてみたところ、未公開商品は表示されなかった。
(スクショ)

## 正解のpayload: ' OR 1=1--
\`\`\`sql
SELECT * FROM products WHERE category = '' OR 1=1-- ' AND released = 1
\`\`\`
--以降がコメントとして無効化されるため、released=1の縛りごと消える。
(スクショ: 未公開商品が表示された画面)

## この検証から得た教訓
- コメントアウトは「念のため付ける保険」ではなく、AND/ORの優先順位を理解した上での「必須の一手」
- 実務では released=1 のような後続条件がどんな形で存在するか分からないので、優先順位頼みの攻撃は再現性が低い

