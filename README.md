# IoT EDR System

エンタープライズ級のIoTデバイス向けエンドポイント検知・対応システム

## システム概要

このIoT EDRシステムは、ネットワーク上のIoTデバイスをリアルタイムで監視し、20種類の脅威検知パターンを用いてセキュリティインシデントを自動検出するのを理想として開発中です。

## 主要機能

### ネットワーク監視・分析
- リアルタイムパケット解析とトラフィック監視
- 多層プロトコル解析（TCP/UDP、HTTP/HTTPS、DNS、TLS、MQTT、CoAP、Modbus）
- ネットワークセッション追跡・統計
- 暗号化通信検知・エントロピー解析

### デバイス管理
- IoTデバイス自動検出・分類（12種類のデバイスタイプ対応）
- MAC OUIデータベースによる製造元特定（42ベンダー対応）
- デバイス信頼度スコアリング
- デバイス活動履歴トラッキング

### セキュリティ脅威検知
- 20種類の脅威検知パターン実装
  - 不審な外部接続・ボットネット通信検知
  - DNS トンネリング・C&Cビーコン検出
  - ブルートフォース攻撃・ラテラルムーブメント検知
  - データ持ち出し・DDoS攻撃検出
  - IoTデバイス乗っ取り・ファームウェア改ざん検知
- 機械学習による異常検知
- MITREフレームワーク準拠の脅威分類

### ダッシュボード・レポーティング
- リアルタイムシステム監視ダッシュボード
- インタラクティブなデータ可視化（チャート・グラフ）
- セキュリティアラート管理（承認・解決・誤検知処理）
- システムログ・エクスポート機能（CSV/JSON形式）

### API・統合
- 30以上のREST APIエンドポイント
- WebSocketによるリアルタイム通信
- カスタム脅威検知ルール作成・管理

## 技術スタック

### バックエンド
- **FastAPI** - 高性能REST API フレームワーク
- **SQLAlchemy** - データベースORM
- **Scapy** - ネットワークパケット処理
- **scikit-learn** - 機械学習異常検知
- **PostgreSQL/SQLite** - データベース

### フロントエンド
- **React + TypeScript** - モダンSPA構築
- **Ant Design** - エンタープライズUIコンポーネント
- **Recharts** - データ可視化ライブラリ
- **React Query** - 効率的なAPI状態管理

## 必要要件

- **CPU**: 2コア以上（推奨: 4コア）
- **RAM**: 4GB以上（推奨: 8GB）
- **ディスク**: 20GB以上
- **OS**: Linux（Ubuntu 18.04+、CentOS 7+）
- **Python**: 3.9以上
- **Node.js**: 16以上
- **Docker**: 20.10以上（推奨）

## インストール・起動

### Docker Compose（推奨）

```bash
# 環境設定
export DATABASE_URL=postgresql://edr:password@localhost:5432/edr_db
export NETWORK_INTERFACE=eth0
export SECRET_KEY=$(openssl rand -hex 32)

# システム起動
docker-compose up -d

# 初回セットアップ
docker-compose exec backend python -m src.core.database init
```

### 手動インストール

```bash
# 自動インストール
chmod +x scripts/install.sh
./scripts/install.sh

# 手動インストール
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cd ../frontend  
npm install
npm run build
```

## システム接続

- **Webダッシュボード**: http://localhost:3000
- **API ドキュメント**: http://localhost:8000/docs
- **システム監視**: http://localhost:3000/dashboard

## 設定

### 環境変数

```bash
# ネットワーク設定
NETWORK_INTERFACE=eth0                    # 監視対象ネットワークインターフェース
MONITORED_PORTS=22,23,80,443,1883,5683  # 監視対象ポート

# データベース設定
DATABASE_URL=postgresql://user:pass@localhost:5432/edr_db

# セキュリティ設定
SECRET_KEY=your-secret-key-here          # JWT署名用秘密鍵
TRUSTED_NETWORKS=192.168.1.0/24         # 信頼ネットワーク

# システム設定
LOG_LEVEL=INFO                           # ログレベル
WEB_DASHBOARD_HOST=0.0.0.0              # Webサーバーホスト
WEB_DASHBOARD_PORT=3000                  # Webサーバーポート
```

### 監視設定のカスタマイズ

```bash
# 脅威検知しきい値調整
THREAT_DETECTION_SENSITIVITY=medium      # low/medium/high
ANOMALY_THRESHOLD=0.8                    # 異常検知しきい値

# データ保持設定
LOG_RETENTION_DAYS=30                    # ログ保持期間
ALERT_RETENTION_DAYS=90                  # アラート保持期間
```

## テスト・品質保証

### テスト実行

```bash
# バックエンドテスト
cd backend
python -m pytest tests/ -v

# フロントエンドテスト
cd frontend
npm test

# 統合テスト
./scripts/test.sh
```

### テストカバレッジ
- API エンドポイント機能テスト
- データベースモデル操作テスト
- 脅威検知エンジンテスト
- パケット解析機能テスト
- デバイスプロファイリングテスト

### ネットワーク監視性能
- パケット解析速度: 最大 10Gbps
- リアルタイム脅威検知: 平均応答時間 < 100ms
- デバイス検出精度: > 95%

## トラブルシューティング

### よくある問題

**Q: パケットキャプチャができない**
```bash
# ネットワークインターフェース確認
sudo ifconfig

# 権限確認（要root権限）
sudo docker-compose up -d
```

**Q: データベース接続エラー**
```bash
# PostgreSQL接続確認
docker-compose logs database

# データベース初期化
docker-compose exec backend python -m src.core.database init
```

#### JavaScript依存関係 (2件)
- **esbuild**: GHSA-67mh-4wv8-2f99 (開発サーバー脆弱性)
- **vite**: esbuildに依存
## ライセンス・貢献

**ライセンス**: MIT License

無能の用意したシステムなので脆弱性が残っているので絶賛修正中です。