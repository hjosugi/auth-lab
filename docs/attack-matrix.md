# 攻撃と防御

このページは [09_attack_matrix.md](09_attack_matrix.md) に移動しました（CWE / OWASP
マッピング付きの完全な攻撃対応表）。

実演:

```bash
PYTHONPATH=. python attacks/catalog.py       # 素朴実装が破れる → authlab が防ぐ
python attacks/run_regressions.py            # 全防御をアサーションで回帰チェック
```
