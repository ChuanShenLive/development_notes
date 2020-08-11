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