# v2node (修改版)

基于 [wyx2685/v2node](https://github.com/wyx2685/v2node) 的自用修改版本。

一个基于修改版xray内核的V2board节点服务端。

## 感谢

- [wyx2685/v2node](https://github.com/wyx2685/v2node) - 原版项目

**注意： 本项目搭配自用的 Xboard 路由插件使用**

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/missish/v2node/main/script/install.sh && bash install.sh
```

## 构建

```bash
GOEXPERIMENT=jsonv2 go build -v -o build_assets/v2node -trimpath -ldflags "-X 'github.com/wyx2685/v2node/cmd.version=$version' -s -w -buildid="
```

## Stars 增长记录

[![Stargazers over time](https://starchart.cc/missish/v2node.svg?variant=adaptive)](https://starchart.cc/missish/v2node)
