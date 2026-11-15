# 消费湖整数列页的自适应压缩与选择性解码

plain.py 定义当前位图加定宽 int64 的叶页，rangeio.py 提供可计量的字节范围读，column.py 持久化页目录并按原行号投影。当前没有压缩页或块级稀疏解码。

运行环境为 Python 3.11，仅使用标准库。文件职责与数据约定见 contracts.md。

```sh
python3 -m packedcolumns
python3 -m unittest discover -s tests -v
python3 -m compileall -q packedcolumns tests
```

data/sample.json 保存项目演练资料。测试使用临时目录，不改变项目内正文。
