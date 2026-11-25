#!/usr/bin/env node
'use strict';

/*
 * V0.7 站长之家 DNS 投票查询助手
 * 仅使用 Node.js 22+ 内置的 fetch / WebSocket，不需要 npm 包。
 *
 * 用法:
 *   node chinaz-vote.js --input domains.json --output votes.json
 *                       [--concurrency 5] [--timeout 45] [--retries 2]
 *                       [--cert-top 5] [--cert-timeout 4000]
 *
 * 输入:
 *   { "domains": [ { "domain": "github.com", "category": "github" } ] }
 *
 * 输出:
 *   { "source": "chinaz", "generatedAt": "...", "totalDomains": 121,
 *     "results": [ { domain, category, status, total, messages, errors,
 *                    votes: [ {ip,count,share,avgTtl,firstSeen,cert,certName} ],
 *                    topIp, topCount, elapsedMs, error } ] }
 *
 *   V0.7 证书校验：cert 取值为 match（证书匹配域名）/ mismatch（证书属于
 *   其他域名，应淘汰）/ unknown（握手失败或超时，无法判定，保留但降级）。
 *   --cert-top 0 可关闭证书校验。
 */

const fs = require('fs');
const tls = require('tls');

function getArg(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index >= 0 && index + 1 < process.argv.length) {
    return process.argv[index + 1];
  }
  return fallback;
}

const inputPath = getArg('--input', '');
const outputPath = getArg('--output', '');
const concurrency = Math.max(1, Math.min(10, parseInt(getArg('--concurrency', '5'), 10) || 5));
const timeoutSec = Math.max(10, Math.min(180, parseInt(getArg('--timeout', '45'), 10) || 45));
const retries = Math.max(0, Math.min(4, parseInt(getArg('--retries', '2'), 10) || 0));
const certTop = Math.max(0, Math.min(12, parseInt(getArg('--cert-top', '5'), 10) || 0));
const certTimeoutMs = Math.max(1000, Math.min(15000, parseInt(getArg('--cert-timeout', '4000'), 10) || 4000));

function fatal(message, code) {
  const body = {
    source: 'chinaz',
    generatedAt: new Date().toISOString(),
    totalDomains: 0,
    fatal: String(message),
    results: []
  };
  try {
    if (outputPath) {
      fs.writeFileSync(outputPath, JSON.stringify(body, null, 2), 'utf8');
    }
  } catch (_) {
    // 输出文件不可写时只打印错误。
  }
  console.error('[FATAL] ' + message);
  process.exit(code || 2);
}

if (!inputPath || !outputPath) {
  fatal('缺少 --input 或 --output 参数。', 2);
}

const nodeMajor = parseInt(String(process.versions.node || '0').split('.')[0], 10);
if (nodeMajor < 22 || typeof fetch !== 'function' || typeof WebSocket !== 'function') {
  fatal('需要 Node.js 22 或更高版本（当前 ' + process.versions.node + '），并且内置 fetch/WebSocket 可用。', 3);
}

let input;
try {
  input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
} catch (error) {
  fatal('无法读取输入 JSON: ' + error.message, 2);
}

const sourceDomains = Array.isArray(input.domains) ? input.domains : [];
if (sourceDomains.length === 0) {
  fatal('输入中没有 domains。', 2);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isValidIPv4(text) {
  const parts = String(text).split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function normalizeDomain(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

function isValidDomain(value) {
  if (!value || value.length < 4 || value.length > 253) return false;
  if (value.includes('..') || value.includes('/') || value.includes('\\') || /\s/.test(value)) return false;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value);
}

// ============ TLS 证书域名校验（V0.7 新增） ============
// 通过 SNI 用目标域名连接候选 IP，检查服务器证书是否真的属于该域名。
// 只有"证书明确属于别的域名"才判 mismatch；握手失败/超时归为 unknown，
// 避免误伤不接受该 SNI 或直接重置连接的正常 CDN 节点。
function certNames(cert) {
  const names = [];
  if (cert && cert.subject && cert.subject.CN) {
    names.push(String(cert.subject.CN).toLowerCase());
  }
  if (cert && cert.subjectaltname) {
    for (const part of String(cert.subjectaltname).split(',')) {
      const m = part.trim().match(/^DNS:(.+)$/i);
      if (m) names.push(m[1].toLowerCase());
    }
  }
  return names;
}

function certDomainMatches(names, domain) {
  const d = String(domain).toLowerCase().replace(/\.$/, '');
  for (const n of names) {
    if (n === d) return true;
    if (n.startsWith('*.') && d.split('.').length === n.split('.').length && d.endsWith(n.slice(1))) {
      return true;
    }
  }
  return false;
}

function checkCert(domain, ip, timeoutMs) {
  return new Promise((resolve) => {
    let socket;
    try {
      socket = tls.connect({
        host: ip,
        port: 443,
        servername: domain,
        rejectUnauthorized: false
      });
    } catch (_) {
      resolve({ status: 'unknown', name: '' });
      return;
    }
    let done = false;
    function finish(status, name) {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch (_) {}
      resolve({ status, name: String(name || '') });
    }
    socket.setTimeout(timeoutMs);
    socket.on('secureConnect', () => {
      try {
        const cert = socket.getPeerCertificate();
        const names = certNames(cert);
        if (names.length === 0) {
          finish('unknown', '');
          return;
        }
        if (certDomainMatches(names, domain)) {
          finish('match', names[0]);
        } else {
          finish('mismatch', names[0]);
        }
      } catch (_) {
        finish('unknown', '');
      }
    });
    socket.on('timeout', () => finish('unknown', ''));
    socket.on('error', () => finish('unknown', ''));
  });
}

function extractLet(html, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const doubleQuoted = new RegExp('let\\s+' + escaped + '\\s*=\\s*"([^"]+)"');
  let match = html.match(doubleQuoted);
  if (match) return match[1];

  const singleQuoted = new RegExp("let\\s+" + escaped + "\\s*=\\s*'([^']+)'");
  match = html.match(singleQuoted);
  if (match) return match[1];

  return '';
}

function extractTotal(html) {
  let match = html.match(/let\s+total\s*=\s*parseInt\(\s*["'](\d+)["']\s*\)/);
  if (match) return parseInt(match[1], 10);

  match = html.match(/let\s+total\s*=\s*(\d+)/);
  if (match) return parseInt(match[1], 10);

  return 0;
}

async function fetchTask(domain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  let response;
  try {
    response = await fetch('https://tool.chinaz.com/dns/' + encodeURIComponent(domain), {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8'
      }
    });
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    throw new Error('查询页 HTTP ' + response.status);
  }

  const html = await response.text();
  const taskId = extractLet(html, 'taskId');
  const taskToken = extractLet(html, 'taskToken');
  const wssUrl = extractLet(html, 'wssUrl');
  const total = extractTotal(html);

  if (!taskId || !taskToken || !wssUrl || total <= 0) {
    throw new Error('查询页没有生成任务（可能被限流、域名无结果或页面结构变化）');
  }
  if (!/^wss:\/\/tool\.chinaz\.com\//i.test(wssUrl)) {
    throw new Error('查询页返回了非预期的 WebSocket 地址');
  }

  return { taskId, taskToken, wssUrl, total };
}

function collectVotes(task, timeoutSec) {
  return new Promise((resolve, reject) => {
    const votes = new Map();
    let messages = 0;
    let errors = 0;
    let nextOrder = 0;
    let finished = false;
    let ws;
    let hardTimer = null;
    let idleTimer = null;

    function clearTimers() {
      if (hardTimer) clearTimeout(hardTimer);
      if (idleTimer) clearTimeout(idleTimer);
      hardTimer = null;
      idleTimer = null;
    }

    function finish(error) {
      if (finished) return;
      finished = true;
      clearTimers();
      try {
        if (ws && ws.readyState === 1) ws.close();
      } catch (_) {
        // 忽略关闭异常。
      }

      const items = Array.from(votes.entries()).map(([ip, value]) => ({
        ip,
        count: value.count,
        share: task.total > 0 ? value.count / task.total : 0,
        avgTtl: value.ttlCount > 0 ? Math.round(value.ttlSum / value.ttlCount) : 0,
        firstSeen: value.firstSeen
      }));

      items.sort((a, b) => {
        if (b.count !== a.count) return b.count - a.count;
        if (a.avgTtl !== b.avgTtl) return a.avgTtl - b.avgTtl;
        return a.firstSeen - b.firstSeen;
      });

      const result = {
        total: task.total,
        messages,
        errors,
        votes: items,
        topIp: items.length > 0 ? items[0].ip : '',
        topCount: items.length > 0 ? items[0].count : 0,
        partial: messages < task.total
      };

      if (error && items.length === 0) {
        reject(new Error(error));
        return;
      }
      if (items.length === 0) {
        reject(new Error('查询在 ' + messages + '/' + task.total + ' 条消息内没有返回有效 IPv4'));
        return;
      }
      resolve(result);
    }

    function resetIdle() {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        finish('等待后续节点超时');
      }, 8000);
    }

    try {
      ws = new WebSocket(task.wssUrl);
    } catch (error) {
      reject(new Error('无法创建 WebSocket: ' + error.message));
      return;
    }

    hardTimer = setTimeout(() => {
      finish('WebSocket 总超时');
    }, Math.max(10, timeoutSec) * 1000);

    ws.onopen = () => {
      try {
        ws.send(JSON.stringify({ task_id: task.taskId, task_token: task.taskToken }));
        resetIdle();
      } catch (error) {
        finish('发送查询任务失败: ' + error.message);
      }
    };

    ws.onmessage = (event) => {
      messages++;
      resetIdle();
      let payload;
      try {
        payload = JSON.parse(String(event.data));
      } catch (_) {
        errors++;
        return;
      }

      if (!payload || payload.code !== 1) {
        errors++;
        return;
      }

      const rows = Array.isArray(payload.aData) ? payload.aData : [];
      let found = false;
      for (const row of rows) {
        const rawName = String(row && row.name ? row.name : '');
        const ip = rawName.split(',')[0].trim();
        if (!isValidIPv4(ip)) continue;
        found = true;

        let value = votes.get(ip);
        if (!value) {
          value = { count: 0, ttlSum: 0, ttlCount: 0, firstSeen: ++nextOrder };
          votes.set(ip, value);
        }
        value.count++;

        const ttl = parseInt(String(row && row.tTL ? row.tTL : ''), 10);
        if (Number.isFinite(ttl) && ttl > 0) {
          value.ttlSum += ttl;
          value.ttlCount++;
        }
      }

      if (!found) {
        errors++;
      }
      if (messages >= task.total) {
        finish('');
      }
    };

    ws.onerror = () => {
      errors++;
      setTimeout(() => finish('WebSocket 连接错误'), 1000);
    };

    ws.onclose = () => {
      if (!finished) finish('');
    };
  });
}

async function queryOne(item) {
  const domain = normalizeDomain(item && item.domain);
  const category = String(item && item.category ? item.category : '未分类');
  const start = Date.now();

  if (!isValidDomain(domain)) {
    return {
      domain,
      category,
      status: 'error',
      total: 0,
      messages: 0,
      errors: 0,
      votes: [],
      topIp: '',
      topCount: 0,
      elapsedMs: 0,
      error: '域名格式不合法'
    };
  }

  let lastError = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const task = await fetchTask(domain);
      const voted = await collectVotes(task, timeoutSec);

      // V0.7：对票数靠前的候选 IP 做 TLS 证书域名校验。
      // 结果写回每个 vote 的 cert 字段，供 PowerShell 淘汰错误 IP。
      if (certTop > 0 && Array.isArray(voted.votes)) {
        const targets = voted.votes.slice(0, certTop);
        await Promise.all(targets.map(async (vote) => {
          const result = await checkCert(domain, vote.ip, certTimeoutMs);
          vote.cert = result.status;
          vote.certName = result.name;
        }));
        for (let i = certTop; i < voted.votes.length; i++) {
          voted.votes[i].cert = 'unknown';
          voted.votes[i].certName = '';
        }
      }

      return {
        domain,
        category,
        status: 'ok',
        total: voted.total,
        messages: voted.messages,
        errors: voted.errors,
        votes: voted.votes,
        topIp: voted.topIp,
        topCount: voted.topCount,
        elapsedMs: Date.now() - start,
        error: voted.partial ? ('只收到 ' + voted.messages + '/' + voted.total + ' 条节点结果') : ''
      };
    } catch (error) {
      lastError = error;
      if (attempt < retries) {
        await sleep(1000 * (attempt + 1));
      }
    }
  }

  return {
    domain,
    category,
    status: 'error',
    total: 0,
    messages: 0,
    errors: 0,
    votes: [],
    topIp: '',
    topCount: 0,
    elapsedMs: Date.now() - start,
    error: lastError ? String(lastError.message || lastError) : '未知错误'
  };
}

async function main() {
  const domains = sourceDomains
    .map((item) => ({ domain: normalizeDomain(item && item.domain), category: String(item && item.category ? item.category : '未分类') }))
    .filter((item) => item.domain);

  const results = new Array(domains.length);
  let nextIndex = 0;
  let completed = 0;

  async function worker() {
    while (true) {
      const index = nextIndex++;
      if (index >= domains.length) return;
      const item = domains[index];
      const result = await queryOne(item);
      results[index] = result;
      completed++;
      if (result.status === 'ok') {
        console.error('[' + completed + '/' + domains.length + '] ' + item.domain + ' -> ' + result.topIp + ' (' + result.topCount + '/' + result.total + ')');
      } else {
        console.error('[' + completed + '/' + domains.length + '] ' + item.domain + ' [失败] ' + result.error);
      }
    }
  }

  const workers = [];
  for (let i = 0; i < Math.min(concurrency, domains.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  const output = {
    source: 'chinaz',
    generatedAt: new Date().toISOString(),
    totalDomains: domains.length,
    results
  };

  try {
    fs.writeFileSync(outputPath, JSON.stringify(output, null, 2), 'utf8');
  } catch (error) {
    fatal('无法写入输出 JSON: ' + error.message, 2);
  }

  const ok = results.filter((item) => item && item.status === 'ok').length;
  console.error('完成: ' + ok + '/' + domains.length + ' 个域名取得有效投票，结果已写入 ' + outputPath);
}

main().catch((error) => {
  fatal('未处理的异常: ' + (error && error.stack ? error.stack : error), 2);
});
