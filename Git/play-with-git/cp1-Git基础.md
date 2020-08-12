<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [1. 综述](#1-综述)
    - [1> 版本控制系统 VCS 分类](#1-版本控制系统-vcs-分类)
    - [2> Git 的特点](#2-git-的特点)
    - [工具](#工具)
- [2 安装-Git](#2-安装-git)
  - [Linux](#linux)
  - [Windows](#windows)
    - [社区命令行工具](#社区命令行工具)
    - [第三方图形化工具](#第三方图形化工具)
  - [验证](#验证)
- [3 Git 最小配置](#3-git-最小配置)
- [4 创建 git 仓库](#4-创建-git-仓库)
    - [add 添加文件](#add-添加文件)
    - [status 查看当前仓库状态](#status-查看当前仓库状态)
    - [commit 提交](#commit-提交)
    - [log 查看变更日志](#log-查看变更日志)

<!-- /code_chunk_output -->

[TOC]


# 1. 综述

### 1> 版本控制系统 VCS 分类
![集中式版本控制系统](https://gitee.com/chuanshen/development_notes/raw/master/Git/play-with-git/img/cp1-%E9%9B%86%E4%B8%AD%E5%BC%8F%E7%89%88%E6%9C%AC%E6%8E%A7%E5%88%B6%E7%B3%BB%E7%BB%9F.png)
![分布式版本控制系统](https://gitee.com/chuanshen/development_notes/raw/master/Git/play-with-git/img/cp1-%E5%88%86%E5%B8%83%E5%BC%8F%E7%89%88%E6%9C%AC%E6%8E%A7%E5%88%B6%E7%B3%BB%E7%BB%9F.png)

- 集中式版本控制系统 (集中式 VCS)
    - 由集中的版本管理服务器(文件, 文件夹的版本演进历史)
    - 具备文件版本管理(获取, 比较, 提交)和分支管理能力
    - 集成效率由明显的提高
    - 客户端必须时刻和服务器相连(客户端不具备完整的版本历史)
- 分布式版本管理系统 (分布式 VCS)
  - 服务端和客户端都有完整的版本库
  - 脱离服务端, 客户端照样可以管理版本
  - 查看历史和版本比较等多数操作, 都不需要访问服务器, 比集中式 VCS 更能提高版本管理效率

### 2> Git 的特点

- 最优的存储能力
- 非凡的性能
- 开源
- 很容易做备份
- 支持离线操作
- 很容易定制工作流程

### 工具

- git
- GitHub 全球最大的开源社区
- GitLab 社区版免费 CI (自己的GitLab 二次开发)

# 2 安装-Git

官网: https://git-scm.com
文档: https://git-scm.com/book/zh/v2/
安装说明: https://git-scm.com/book/zh/v2/起步-安装-Git

## Linux

RHEL CentOS 等基于 RPM 的发行版本:

```shell script
$ sudo def install git-all
```

基于 Debian 的发型版本 如 Ubuntu 等使用 apt 命令

```shell script
$ sudo apt install git-all
```

更多下载地址: https://git-scm.com/download/linux

## Windows

### 社区命令行工具
下载地址(msysGit): https://git-scm.com/download/win
项目地址: http://msysgit.github.io

### 第三方图形化工具

1 安装GitHub Desktop

文档: https://docs.github.com/cn/desktop/getting-started-with-github-desktop/installing-and-authenticating-to-github-desktop
下载: https://desktop.github.com/

2 安装 TortoiseGit

下载: https://tortoisegit.org/download/

> 下载页面有汉化包的下载

## 验证

在命令行中执行命令
```shell script
C:\Users\chuan>git --version
git version 2.19.1.windows.1
```

# 3 Git 最小配置

配置 global

user.name
user.email

信息体现在变更信息中, 即变更信息中记录【谁】什么时间做了变更. 邮箱也用于 review 时发送反馈邮件.

```shell script
git config --global user.name 'your_name'
git config --global user.email 'your_email@domain.com'
```

config 的三个作用域

- local (缺省)只对当前仓库有效, 在git 仓库目录中有效
- global 对当前用户所有仓库有效
- system 对系统所有登录的用户有效

```shell script
git config --local
git config --global
git config --system

# 显示 config 的配置, 使用 --list 指令
git config --list --local
git config --list --global
git config --list --system

# 清除设置
$ git config --unset --local user.name
$ git config --unset --global user.name
$ git config --unset --system user.name
```

> local > global > system
> git config --list 显示整合 system global local 的混合版本

# 4 创建 git 仓库

两种 场景:

1.把已有的项目代码纳入 Git 管理

```shell script
cd 项目代码所在的文件夹
git init
```

2.新建的项目直接使用 Git 管理

```shell script
cd 某个文件夹
git init your_project #会在当前路径下创建和项目名称同名的文件夹
cd your_project
```

创建成功后, 在目标目录中生成一个 .git 的隐藏目录, 这是 git 仓库的核心目录, 删除后, 目录中将不在存在版本信息.

### add 添加文件

对文件的修改可以直接提交, 但如果是新建的文件, 需要先添加 add 将文件纳入到版本控制的管控之中, 放入暂存区, 再进行提交.

```shell script
git add 文件名
```

### status 查看当前仓库状态

```shell script
git status 
```

### commit 提交

将 暂存区的变更, 正式的提交
```shell script 
git commit -m '说明' 
```

> 默认配置必须填写说明, vanderful.

### log 查看变更日志

查看仓库当前分支的变更日志

```shell script 
git log 
```