# toJohn

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=plastic)](https://github.com/aristorechina/toJohn/blob/main/LICENSE)
[![Crates.io](https://img.shields.io/crates/v/tojohn?logo=rust&logoColor=white&style=plastic&color=orange)](https://crates.io/crates/tojohn)
[![GitHub](https://img.shields.io/badge/Github-toJohn-181716?style=plastic&logo=github&logoColor=white)](https://github.com/aristorechina/toJohn)
[![Latest Release](https://img.shields.io/github/v/release/aristorechina/toJohn?sort=semver&style=plastic&color=brightgreen)](https://github.com/aristorechina/toJohn/releases/latest)

[English](https://github.com/aristorechina/toJohn/blob/main/README.md) | 简体中文

**toJohn** 是一个一体化的密码哈希提取工具：从 100+ 种文件格式中提取可破解的密码哈希，统一输出为哈希行格式，可直接交给 John the Ripper、hashcat 等密码破解工具加载。

## 特性

- **100+ 种格式**：加密卷、归档、数据库、钱包、办公文档、证书密钥、网络捕获
- **统一 CLI**：自动格式识别（best-effort 内容嗅探）、递归目录扫描、批量处理、输出重定向
- **输出精确**：所有格式的输出由 golden 测试逐字节固化，保证与该格式的标准哈希行完全一致
- **纯 Rust**：ASN.1/DER、OLE2/CFB、ZIP、XML、pcap 等底层解析均为内置实现，运行时无任何外部脚本依赖

## 构建

需要 Rust 1.87+（2021 edition；使用了 `is_multiple_of` 等较新 API）。`rusqlite` 使用 bundled 特性，构建需要本地 C 编译器。

```sh
cargo build --release
# 产物：target/release/tojohn(.exe)
```

或直接安装到 PATH：

```sh
cargo install --path crates/tojohn-cli
```

## 使用

```text
tojohn [选项] <文件...>
```

常用示例：

```sh
# 自动识别格式并提取
tojohn backup.7z

# 指定格式（对自动识别有歧义的输入）
tojohn -f zip encrypted.zip

# 递归扫描目录，输出到文件，单个文件出错时继续
tojohn -r dumps/ -o hashes.txt --keep-going

# 列出全部支持格式 / 各格式详情
tojohn --list-formats
tojohn --list-details

# 内联文本输入（文本类格式，如 ansible-vault）
tojohn --text -f ansible '$ANSIBLE_VAULT;1.1;AES256;...'
```

### 选项

| 选项 | 说明 |
| --- | --- |
| `-f, --format <名称>` | 强制指定格式（名称见 `--list-formats`） |
| `-r, --recursive` | 递归扫描目录 |
| `-k, --keyfile <路径>` | 附加密钥文件 |
| `-o, --output <路径>` | 写入文件而非 stdout |
| `--text <文本>` | 内联文本输入（需配合 `-f`） |
| `--keep-going` | 批量模式下单文件出错时继续处理 |
| `-q, --quiet` | 关闭 stderr 上的逐文件摘要 |
| `--list-formats` | 列出全部支持格式后退出 |
| `--list-details` | 列出格式详情（识别能力、描述）后退出 |

自动识别按固定优先级依次用各格式的内容嗅探器尝试匹配；对歧义输入可用 `-f` 强制指定。

## 测试

```sh
cargo test
```

测试体系为 15 个单元测试 + 142 个 golden 测试。golden 用例位于 [`fixtures/`](https://github.com/aristorechina/toJohn/tree/main/fixtures)：每个用例 = 输入样本 + 期望输出（`expected.txt`），逐字节比对提取结果。这是本项目行为正确性的验收标准——修改任何代码后跑一遍，即可确认全部格式的输出未被改变。风格与命名规范见 [CONVENTIONS.md](https://github.com/aristorechina/toJohn/blob/main/CONVENTIONS.md)。

## 项目结构

```text
crates/
  tojohn/        核心库：100+ 个格式模块 + 通用解析器（ASN.1、OLE2、ZIP、XML、pcap）
  tojohn-cli/    命令行前端
fixtures/        golden 测试数据
CONVENTIONS.md   代码风格与命名规范
```

## 许可证

[Apache-2.0](https://github.com/aristorechina/toJohn/blob/main/LICENSE) © [Aristore](https://github.com/aristorechina)

## 致谢

- [openwall/john](https://github.com/openwall/john) —— 本工具输出的哈希行格式由 John the Ripper 项目定义
- [ivanmrsulja/keepass2john](https://github.com/ivanmrsulja/keepass2john) —— KDBX4 哈希提取的参考实现
