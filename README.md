# 消费湖整数列页的自适应压缩与选择性解码

plain.py 定义位图加定宽 int64 的 INTP1 叶页（保持兼容），adaptive.py 实现
INTP2 自适应页：块目录前置、块自带 null 位图与 CRC，块级在 CONST/PLAIN/
BITPACK/DELTA/DELTA_EXC 间按真实字节竞标；差分用模 2**64 运算避免溢出，
离群大数进例外表。rangeio.py 提供可计量的字节范围读，column.py 持久化页
目录、按原行号做块级稀疏投影，并提供整页 verify 与混合 codec 兼容。

运行环境为 Python 3.11，仅使用标准库。文件职责与数据约定见 contracts.md。

```sh
python3 -m packedcolumns
python3 -m unittest discover -s tests -v
python3 -m compileall -q packedcolumns tests
```

data/sample.json 保存项目演练资料。测试使用临时目录，不改变项目内正文。
