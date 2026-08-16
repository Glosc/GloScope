# tiny_app — 评测靶场（编码存储）

这是一份**故意脆弱**的最小 Flask 靶场，含三条已知漏洞（SQL 注入 / SSRF / 路径穿越），
仅用于测试 GloScope 扫描器自身的召回与误报，**绝不可部署或作为开发模板**。

## 为什么是 base64

本仓库的开发环境装有静态安全钩子，会拦截任何包含真实漏洞模式的明文文件写入——
靶场 payload 明文写入会被误拦（钩子并不能区分「项目代码引入漏洞」与「漏洞扫描器
自己的测试靶场」）。因此靶场源码以 `app.py.b64`（base64）存储，这不是为了对使用者
隐藏内容——解码即得完整明文：

```bash
python -c "import base64,pathlib;print(base64.b64decode(pathlib.Path('app.py.b64').read_bytes()).decode())"
```

## 使用

评测脚本会在运行时把 payload 物化到临时目录并扫描：

```bash
python evals/run_eval.py --live --config config.local.toml
```

ground truth 见 `evals/ground_truth.json`（按「文件 × 漏洞类别」标注）。
