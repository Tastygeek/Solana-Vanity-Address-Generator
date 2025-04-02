# Solana Vanity Address Generator

一个高性能的 Solana 靓号地址生成器，支持多进程并行搜索，使用标准 BIP39 助记词生成。

## 功能特性

- 🚀 多进程并行搜索，充分利用 CPU 性能
- 🔒 使用标准 BIP39 助记词生成，完全兼容 Phantom 等钱包
- 🎯 支持自定义地址前缀
- 📊 实时显示搜索进度和速度统计
- ✅ 自动验证生成的地址和助记词
- 💾 自动保存结果到文件
- 🔍 支持地址验证测试

## 安装

1. 克隆仓库：
```bash
git clone https://github.com/Tastygeek/solana-vanity-address.git
cd solana-vanity-address
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

## 使用方法

基本用法：
```bash
python generate_sol_address.py -p Sol
```

### 命令行参数

- `-p, --prefix`: 要匹配的地址前缀 (默认: "Sol")
- `-b, --batch-size`: 每批生成的地址数量 (默认: 5000)
- `-c, --cpu-cores`: 使用的 CPU 核心数量, 0 表示自动 (默认: 0)
- `-d, --details`: 显示每个进程的详细信息
- `-i, --interval`: 统计信息更新间隔(秒) (默认: 5)
- `-t, --test`: 启动前测试助记词推导

### 示例

1. 使用 4 个 CPU 核心搜索以 "Sol" 开头的地址：
```bash
python generate_sol_address.py -p Sol -c 4
```

2. 显示详细进度信息：
```bash
python generate_sol_address.py -p Sol -d
```

3. 自定义批处理大小和更新间隔：
```bash
python generate_sol_address.py -p Sol -b 10000 -i 10
```

## 输出说明

程序运行时会显示：
- 实时搜索速度
- 已检查的地址数量
- 运行时间
- 找到匹配地址时的详细信息

结果文件包含：
- 生成的地址
- 对应的助记词
- 验证状态
- 生成时间
- 尝试次数
- 总耗时

## 注意事项

- 生成的助记词使用标准 BIP39 标准，可以导入 Phantom 等 Solana 钱包
- 程序会自动验证生成的地址和助记词的关联性
- 建议在运行前先使用 `-t` 参数测试助记词推导功能

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 贡献

欢迎提交 Issue 和 Pull Request！

## 免责声明

本工具仅供学习和研究使用。请勿用于任何非法用途。 
