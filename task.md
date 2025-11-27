# OSVからSnykへの移行タスク

## プロジェクト目的

**Shai-Hulud型自己増殖型ワームの防除**
- 悪意のあるパッケージがpreinstall/postinstallスクリプトで実行される前に検出
- 直接依存・推移的依存の両方をスキャン
- 開発者のnpm tokenやGitHub Personal Access Tokenの窃取を防ぐ

## 決定事項

### ✅ 使用するAPI
**`POST /rest/orgs/{org_id}/packages/issues` (Snyk REST API)**

**理由:**
- PURL形式で複数パッケージを一括クエリ可能（高パフォーマンス）
- REST APIで将来的に安定
- 課金ユーザー向けと明確に割り切る

### ✅ ターゲットユーザー
**Snyk有料プラン契約者のみ**

**要件:**
- `SNYK_API_TOKEN`: Snyk APIトークン
- `SNYK_ORG_ID`: Snyk組織ID
- どちらか一方でも欠けている場合はエラーでインストールを停止

### ✅ Transitive Vulnerabilitiesの対応

**結論: 問題なし**

Snyk APIドキュメントには「直接の脆弱性のみを返す」と記載されているが、これは「**クエリしたパッケージ自体の脆弱性のみを返す**」という意味。

**Bun Security Scanner APIの動作:**
- Bunは`scan({ packages })`に**全パッケージ（直接依存+推移的依存）**を渡す
- 証拠: 既存のOSVスキャナーで「Scanning 669 unique packages」のようなログが出力される
- これは直接依存だけでは説明できない大量の数

**実装での対応:**
```typescript
// Bunが渡すpackages配列の例
packages = [
  { name: "express", version: "4.17.1" },      // 直接依存
  { name: "body-parser", version: "1.19.0" },  // 推移的依存
  { name: "bytes", version: "3.1.0" },         // 推移的依存
  // ... 全ての依存関係
]

// 各パッケージを個別にSnykでスキャン
for (const pkg of packages) {
  // Snyk APIに "body-parser@1.19.0" をクエリ
  // → body-parser 自体の脆弱性を検出
}
```

**結果:**
- 推移的依存に潜むShai-Hulud型ワームも検出可能
- OSVと同等の検出能力を維持

## API調査結果

### 採用するエンドポイント詳細

**`POST /rest/orgs/{org_id}/packages/issues`**

| 項目 | 詳細 |
|------|------|
| URL | `https://api.snyk.io/rest/orgs/{org_id}/packages/issues?version=2024-10-15` |
| 認証 | `Authorization: token {SNYK_API_TOKEN}` |
| Content-Type | `application/vnd.api+json` |
| リクエスト形式 | PURLs (Package URL) の配列 |
| PURL例 | `pkg:npm/express@4.17.1` |
| スコープ付き | `pkg:npm/%40scope%2Fpackage@1.0.0` (URLエンコード必須) |
| バッチ処理 | 複数パッケージを一括クエリ可能 |
| レート制限 | 180 req/min/user |

### OSV.devとの比較

| 項目 | OSV.dev | Snyk API (REST) |
|------|---------|-----------------|
| 認証 | 不要 | 必須（API Token + ORG_ID） |
| 料金 | 無料 | 有料プラン必須 |
| バッチクエリ | ✅ 対応 | ✅ 対応 |
| リクエスト形式 | JSON (name + version) | PURL |
| レート制限 | 緩い | 180 req/min/user |
| Transitive依存検出 | ✅ (Bunが全パッケージを渡す) | ✅ (Bunが全パッケージを渡す) |

## 実現可能性の評価

### ✅ 技術的実現可能性
- Snyk REST APIは利用可能で、npmパッケージの脆弱性スキャンに対応
- 現在のOSVクライアントと同様の構造で実装可能
- Bunが推移的依存も含む全パッケージを渡すため、Shai-Hulud型ワームの検出が可能

### ✅ セキュリティ要件の充足
- preinstall/postinstallスクリプト実行前にスキャン実行
- 直接依存・推移的依存の両方をカバー
- 悪意のあるコードの実行を事前にブロック可能

## 移行影響範囲チェックリスト

### コアロジック

- [x] `src/client.ts` - OSVClientをSnykClientに書き換え
  - [x] APIエンドポイントの変更（`https://api.snyk.io/rest/orgs/{org_id}/packages/issues`）
  - [x] 認証ヘッダーの追加（`Authorization: token {SNYK_API_TOKEN}`）
  - [x] Content-Typeヘッダーの設定（`application/vnd.api+json`）
  - [x] リクエスト形式の変更（PURL形式への変換）
  - [x] PURL生成ロジックの実装（スコープ付きパッケージのURLエンコード対応） → `src/purl.ts`作成
  - [x] レスポンススキーマの変更
  - [x] エラーハンドリングの調整（429レート制限エラーへの対応）
  - [x] バッチクエリロジックの調整

- [x] `src/schema.ts` - Snyk APIレスポンスのスキーマ定義
  - [x] OSVスキーマの削除
  - [x] Snykスキーマの追加（JSON:API形式）
  - [x] 型定義の更新

- [x] `src/processor.ts` - 脆弱性処理ロジックの調整
  - [x] Snyk脆弱性フォーマットへの対応
  - [x] Severityマッピングの調整
  - [x] Advisory生成ロジックの更新
  - [x] URL参照の調整（Snyk脆弱性ページへのリンク）

- [x] `src/constants.ts` - 定数の更新
  - [x] API_BASE_URLの変更（`https://api.snyk.io/rest`）
  - [x] 環境変数名の変更（`OSV_*` → `SNYK_*`）
  - [x] デフォルト値の調整
  - [x] レート制限の定数追加（180 req/min）
  - [x] APIバージョンの定数追加

- [x] `src/index.ts` - 環境変数のバリデーション追加
  - [x] SNYK_API_TOKENの存在チェック
  - [x] SNYK_ORG_IDの存在チェック
  - [x] どちらか一方でも欠けている場合は明確なエラーメッセージでインストール停止
  - [x] エラーメッセージに環境変数設定方法とドキュメントリンクを含める

- [x] `src/semver.ts` - Snykのバージョン範囲形式への対応確認
  - [x] Snykのバージョン範囲形式の調査
  - [x] 必要に応じて調整
  - [x] （注: Snyk APIはPURLでバージョンを指定するため、範囲マッチングは不要 → 変更なし）

- [x] `src/severity.ts` - Snykのseverity形式への対応
  - [x] SeverityマッピングロジックをSnyk形式に更新
  - [x] Snyk severityレベル（critical, high, medium, low）への対応

### ユーティリティ

- [x] `src/retry.ts` - 再試行ロジックの確認
  - [x] Snyk APIのレート制限（429）への対応追加 → client.tsで対応
  - [x] Retry-Afterヘッダーの考慮 → client.tsで対応
  - [x] 必要に応じて調整 → 既存のロジックで対応可能

- [x] `src/logger.ts` - ログメッセージの更新
  - [x] "OSV" → "Snyk"への置換
  - [x] API関連のログメッセージの調整

- [x] `src/cli.ts` - CLIツールの更新
  - [x] 環境変数チェックの追加 → index.tsで対応
  - [x] ヘルプメッセージの更新
  - [x] エラーメッセージの更新

### テスト

- [ ] `tests/scanner.test.ts` - スキャナーのテスト更新
  - [ ] モックレスポンスをSnyk形式（JSON:API）に変更
  - [ ] 環境変数のモック追加（SNYK_API_TOKEN, SNYK_ORG_ID）
  - [ ] 環境変数欠如時のエラーテスト追加

- [ ] `tests/processor.test.ts` - プロセッサーのテスト更新
  - [ ] Snyk脆弱性フォーマットでのテスト
  - [ ] Severityマッピングのテスト

- [ ] `tests/schema.test.ts` - スキーマのテスト更新
  - [ ] Snykレスポンスのバリデーションテスト
  - [ ] JSON:API形式のテスト

- [ ] `tests/severity.test.ts` - Severityマッピングのテスト更新
  - [ ] Snyk severity形式（critical, high, medium, low）でのテスト

- [ ] その他のテストファイル
  - [ ] `tests/constants.test.ts` - 新しい定数のテスト
  - [ ] `tests/logger.test.ts` - ログメッセージの確認
  - [ ] `tests/retry.test.ts` - 429エラーの再試行テスト
  - [ ] `tests/semver.test.ts` - バージョンマッチングのテスト
  - [ ] `tests/package-verification.test.ts` - パッケージ検証のテスト

- [x] 新規テスト追加
  - [x] `tests/purl.test.ts` - PURL生成のテスト（スコープ付きパッケージのエンコーディング）
  - [ ] `tests/env-validation.test.ts` - 環境変数バリデーションのテスト（モジュールロード時実行のためテスト困難 - スキップ）

### ドキュメント

- [x] `README.md` - 完全な書き換え
  - [x] タイトル: "Bun OSV Scanner" → "Bun Snyk Scanner"
  - [x] 説明: OSV.dev → Snyk API
  - [x] **重要**: 「Snyk有料プラン契約者専用」を明記
  - [x] **重要**: Shai-Hulud型ワーム防除の目的を説明
  - [x] インストール手順
  - [x] 必須要件:
    - [x] Snykアカウント作成手順へのリンク
    - [x] API Tokenの取得方法（詳細な手順）
    - [x] Organization IDの確認方法
  - [x] 環境変数の設定（SNYK_API_TOKEN, SNYK_ORG_ID）
  - [x] bunfig.toml の設定例更新（`scanner = "@bun-security-scanner/snyk"`）
  - [x] 機能説明の更新
  - [x] 使用例の更新
  - [x] トラブルシューティング:
    - [x] 環境変数が設定されていない場合
    - [x] APIトークンが無効な場合
    - [x] レート制限に達した場合
    - [x] 組織IDが見つからない場合

- [ ] `SECURITY.md` - セキュリティポリシーの更新
  - [ ] Snyk関連の内容への更新
  - [ ] API Tokenの安全な管理方法の追記

- [ ] `CONTRIBUTING.md` - 貢献ガイドラインの更新
  - [ ] OSV → Snykへの言及の更新
  - [ ] テスト実行に必要な環境変数の説明追加

### パッケージメタデータ

- [x] `package.json` - パッケージ情報の更新
  - [x] name: `@bun-security-scanner/osv` → `@bun-security-scanner/snyk`
  - [x] description: "OSV vulnerability scanner" → "Snyk vulnerability scanner for Bun projects - Shai-Hulud worm protection"
  - [x] keywords: "osv" → "snyk", "shai-hulud", "supply-chain-security"を追加
  - [x] homepage URLの更新
  - [x] repository URLの更新
  - [x] bugs URLの更新

### その他

- [ ] `.github/workflows/*` - CI/CD設定の確認と更新
  - [ ] 環境変数のシークレット設定（SNYK_API_TOKEN, SNYK_ORG_ID）
  - [ ] テスト実行時のモック設定
  - [ ] リリースワークフローの確認

## 実装時の注意事項

### 1. PURL生成の正確性

**スコープ付きパッケージのエンコーディング:**
```typescript
// 正しい実装例
function toPURL(name: string, version: string): string {
  // @scope/package → %40scope%2Fpackage
  const encodedName = name.replace(/^@/, '%40').replace(/\//, '%2F');
  return `pkg:npm/${encodedName}@${version}`;
}

// テストケース
toPURL("express", "4.17.1")          // → "pkg:npm/express@4.17.1"
toPURL("@types/node", "18.0.0")      // → "pkg:npm/%40types%2Fnode@18.0.0"
```

### 2. レート制限への対応

**180 req/min/user の制限:**
- バッチクエリを最大限活用
- 429エラー時のRetry-Afterヘッダーを尊重
- 指数バックオフの実装

### 3. エラーメッセージの明確化

**環境変数未設定時:**
```
Error: Snyk API credentials not configured

This scanner requires a Snyk account with a paid plan.

Required environment variables:
- SNYK_API_TOKEN: Your Snyk API token
- SNYK_ORG_ID: Your Snyk organization ID

Setup instructions:
1. Create a Snyk account: https://snyk.io/signup
2. Get your API token: https://docs.snyk.io/snyk-api/authentication-for-api
3. Find your organization ID: https://docs.snyk.io/getting-started/...

Set environment variables in your shell or .env file:
export SNYK_API_TOKEN="your-token"
export SNYK_ORG_ID="your-org-id"
```

### 4. デバッグログの追加

**実装初期に確認すべき情報:**
```typescript
logger.debug(`Bun provided ${packages.length} packages for scanning`);
logger.debug(`Sample packages:`, packages.slice(0, 5).map(p => `${p.name}@${p.version}`));
logger.debug(`Contains transitive dependencies:`, packages.length > 10); // 推定
```

### 5. Snyk APIレスポンスの事前検証

**実装前に実施:**
- テストアカウントで実際のAPIを叩く
- レスポンススキーマを確認
- エラーレスポンスのバリエーションを確認
- サンプルレスポンスをテストデータとして保存

## 残る疑問点・実装時に決定すべきこと

### 1. 環境変数のバリデーションタイミング

**オプションA: スキャナー初期化時**
```typescript
export const scanner: Bun.Security.Scanner = {
  version: "1",
  async scan({ packages }) {
    // ここで環境変数チェック → エラーで即座に停止
    validateEnvVars();
    // ...
  }
};
```

**オプションB: モジュールロード時（推奨）**
```typescript
// トップレベルでチェック
validateEnvVars();

export const scanner: Bun.Security.Scanner = {
  // ...
};
```

### 2. バッチサイズの最適化

- Snyk APIのバッチクエリで一度に何個のPURLを送信できるか？
- APIドキュメントに記載がない場合、実験的に確認が必要
- OSVは1000パッケージ/batchだったが、Snykは異なる可能性

### 3. Snyk APIレスポンスの詳細構造

以下を実装前に確認が必要：
- 脆弱性が見つかった場合のレスポンス構造
- 脆弱性が見つからなかった場合のレスポンス
- エラーレスポンスの種類（401, 403, 404, 429, 500など）
- Severityの値の種類（critical, high, medium, low以外もあるか？）

### 4. パッケージ名の変更とnpmパブリッシュ

**決定が必要:**
- 新パッケージとして公開 vs 既存パッケージの新バージョン
- 推奨: 新パッケージ（`@bun-security-scanner/snyk`）として公開
- 既存の`@bun-security-scanner/osv`は非推奨（deprecated）として残す
- READMEに移行ガイドを記載

## 実装の進め方（推奨順序）

### Phase 1: 基礎実装（コアロジック）

1. **環境変数バリデーション** (`src/index.ts`)
   - SNYK_API_TOKEN, SNYK_ORG_IDのチェック
   - 明確なエラーメッセージ

2. **定数の更新** (`src/constants.ts`)
   - 新しい環境変数名
   - API URL
   - レート制限

3. **スキーマ定義** (`src/schema.ts`)
   - Snyk API実行して実際のレスポンスを確認
   - Zodスキーマを定義

4. **PURL変換ロジック**
   - スコープ付きパッケージ対応
   - ユニットテスト作成

5. **Snyk APIクライアント** (`src/client.ts`)
   - 認証ヘッダー
   - バッチクエリ実装
   - レート制限対応
   - エラーハンドリング

6. **脆弱性プロセッサー** (`src/processor.ts`, `src/severity.ts`)
   - Snyk形式への対応
   - Severityマッピング

### Phase 2: テスト実装

7. **ユニットテスト更新**
   - 全テストファイルをSnyk形式に更新
   - モックデータの作成
   - 環境変数テストの追加

8. **統合テスト**
   - 実際のSnyk APIを使ったテスト（CIでスキップ可能に）

### Phase 3: ドキュメント・メタデータ

9. **ドキュメント更新**
   - README.md（最優先）
   - CHANGELOG.md
   - CONTRIBUTING.md
   - SECURITY.md

10. **パッケージメタデータ**
    - package.json
    - CI/CD設定

### Phase 4: 検証・リリース

11. **統合テスト**
    - 実際のBunプロジェクトでテスト
    - 様々なシナリオでの動作確認

12. **リリース準備**
    - バージョン番号決定（メジャーバージョンアップ）
    - CHANGELOGの最終確認
    - npmパブリッシュ

## 成功基準

実装完了の定義:

- [ ] 環境変数が未設定の場合、明確なエラーで停止する
- [ ] Bunが渡す全パッケージ（直接+推移的依存）をSnyk APIでスキャンできる
- [ ] Shai-Hulud型ワームを含む悪意のあるパッケージを検出できる
- [ ] 全テストがパスする
- [ ] ドキュメントが更新され、セットアップ手順が明確
- [ ] 実際のBunプロジェクトで動作する
