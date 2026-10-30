// 0.1.5 static checks: the runtime mirror of the recon tool's constants (operator ruling R5 2026-10-21: mirror recon's tree when handed
// over). static-checks-1.4 came from the hand-off 2c57daef (recon tree de8f33b); static-checks-1.5 (operator rulings R7, R9, R9a, R9b
// 2026-10-22) from d78fa156 (recon v6.13 7b4eda4): every 1.4 marker, limit, gate, class, role and notice unchanged, plus S7's named
// condition and recon's 16 test vectors for it. The constants below are copied from the hand-off and compared with the module's exports
// by regex source and flags, so a marker that drifts on either side fails here. Failing first: written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';

const SC = () => import('../../proxy/static-checks.js');
const R14 = {
 "version": "static-checks-1.5",
 "checks": [
  {
   "id": "S0",
   "gate": "static:S0-shell-fetch-in-hook",
   "cls": "shell-fetch-in-hook",
   "roles": null,
   "notice": "an install script downloads code to run or sends data to an outside host"
  },
  {
   "id": "S1",
   "gate": "static:S1-loader-in-hook-target",
   "cls": "loader-in-hook-target",
   "roles": [
    "hook"
   ],
   "notice": "an install script runs a small loader that fetches and executes"
  },
  {
   "id": "S2",
   "gate": "static:S2-obfuscated-entry",
   "cls": "obfuscated-entry",
   "roles": [
    "main",
    "bin"
   ],
   "notice": "its entry file is obfuscated code"
  },
  {
   "id": "S3",
   "gate": "static:S3-secret-harvest-with-sink",
   "cls": "secret-harvest-with-sink",
   "roles": [
    "main",
    "bin",
    "hook"
   ],
   "notice": "its code reads credentials and sends them to an outside host"
  },
  {
   "id": "S4",
   "gate": "static:S4-wallet-swap-hook",
   "cls": "wallet-swap-hook",
   "roles": [
    "main",
    "bin"
   ],
   "notice": "its code rewrites wallet addresses in web traffic"
  },
  {
   "id": "S5",
   "gate": "static:S5-oversized-hook-target",
   "cls": "oversized-hook-target",
   "roles": [
    "hook"
   ],
   "notice": "an install script runs a file too large to read"
  },
  {
   "id": "S6",
   "gate": "static:S6-network-beacon-in-hook-target",
   "cls": "network-beacon-in-hook-target",
   "roles": [
    "hook"
   ],
   "notice": "an install script sends details about this machine to the network"
  },
  {
   "id": "S7",
   "gate": "static:S7-entry-capability-gain",
   "cls": "entry-capability-gain",
   "roles": [
    "main",
    "bin"
   ],
   "notice": "its entry file gained a capability its previous version did not have"
  }
 ],
 "shells": [
  "sh",
  "bash",
  "dash",
  "zsh"
 ],
 "shell_c": {
  "regex": "(?:^|[;&|(\\x60]|\\$\\()\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:env\\s+(?:\\w+=\\S*\\s+)*)?(?:(?:\\/[^\\s/;&|()'\"\\x60]+)*\\/)?(?:sh|bash|dash|zsh)\\s+(?:-[a-zA-Z]+\\s+)*-[a-zA-Z]*c[a-zA-Z]*\\s+(?:'([^']*)'|\"((?:[^\"\\\\]|\\\\.)*)\")",
  "flags": "g"
 },
 "net_tools": [
  {
   "name": "curl",
   "regex": "(?:^|[;&|(\\x60]|\\$\\()\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:env\\s+(?:\\w+=\\S*\\s+)*)?(?:(?:\\/[^\\s/;&|()'\"\\x60]+)*\\/)?(?:curl)(?:\\.exe)?(?=\\s|$|[;&|)])",
   "flags": "i"
  },
  {
   "name": "wget",
   "regex": "(?:^|[;&|(\\x60]|\\$\\()\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:env\\s+(?:\\w+=\\S*\\s+)*)?(?:(?:\\/[^\\s/;&|()'\"\\x60]+)*\\/)?(?:wget)(?:\\.exe)?(?=\\s|$|[;&|)])",
   "flags": "i"
  },
  {
   "name": "nc",
   "regex": "(?:^|[;&|(\\x60]|\\$\\()\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:env\\s+(?:\\w+=\\S*\\s+)*)?(?:(?:\\/[^\\s/;&|()'\"\\x60]+)*\\/)?(?:nc|ncat|netcat)(?:\\.exe)?(?=\\s|$|[;&|)])",
   "flags": "i"
  },
  {
   "name": "nslookup",
   "regex": "(?:^|[;&|(\\x60]|\\$\\()\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:env\\s+(?:\\w+=\\S*\\s+)*)?(?:(?:\\/[^\\s/;&|()'\"\\x60]+)*\\/)?(?:nslookup)(?:\\.exe)?(?=\\s|$|[;&|)])",
   "flags": "i"
  },
  {
   "name": "dig",
   "regex": "(?:^|[;&|(\\x60]|\\$\\()\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:env\\s+(?:\\w+=\\S*\\s+)*)?(?:(?:\\/[^\\s/;&|()'\"\\x60]+)*\\/)?(?:dig)(?:\\.exe)?(?=\\s|$|[;&|)])",
   "flags": "i"
  },
  {
   "name": "host",
   "regex": "(?:^|[;&|(\\x60]|\\$\\()\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:env\\s+(?:\\w+=\\S*\\s+)*)?(?:(?:\\/[^\\s/;&|()'\"\\x60]+)*\\/)?(?:host)(?:\\.exe)?(?=\\s|$|[;&|)])",
   "flags": "i"
  },
  {
   "name": "ping",
   "regex": "(?:^|[;&|(\\x60]|\\$\\()\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:env\\s+(?:\\w+=\\S*\\s+)*)?(?:(?:\\/[^\\s/;&|()'\"\\x60]+)*\\/)?(?:ping)(?:\\.exe)?(?=\\s|$|[;&|)])",
   "flags": "i"
  }
 ],
 "dns_tools": [
  "nslookup",
  "dig",
  "host",
  "ping"
 ],
 "send_markers": [
  {
   "name": "command-substitution",
   "regex": "\\$\\(|`"
  },
  {
   "name": "data-flag",
   "regex": "(?:^|\\s)(?:--data(?:-[a-z]+)?|--form(?:-string)?|--upload-file|--post-data|--post-file)(?=[\\s=]|$)|(?:^|\\s)-[dFT](?=\\s|[^\\s-])"
  },
  {
   "name": "raw-ip-url",
   "regex": "\\bhttps?:\\/\\/(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d+)?\\b"
  },
  {
   "name": "exfil-host-url",
   "regex": null
  }
 ],
 "api_net_sinks": [
  {
   "name": "http-request",
   "regex": "\\b(?:https?|http2)\\.(?:request|get)\\s*\\(",
   "flags": ""
  },
  {
   "name": "fetch",
   "regex": "\\bfetch\\s*\\(",
   "flags": ""
  },
  {
   "name": "net-connect",
   "regex": "\\bnet\\.(?:connect|createConnection)\\s*\\(|\\btls\\.connect\\s*\\(|\\bdgram\\.createSocket\\s*\\(",
   "flags": ""
  },
  {
   "name": "websocket",
   "regex": "\\bnew\\s+WebSocket\\s*\\(",
   "flags": ""
  },
  {
   "name": "xhr",
   "regex": "\\bnew\\s+XMLHttpRequest\\s*\\(",
   "flags": ""
  },
  {
   "name": "axios",
   "regex": "\\baxios(?:\\.\\w+)?\\s*\\(",
   "flags": ""
  }
 ],
 "host_identity": [
  {
   "name": "os.hostname",
   "regex": "(?:\\bos|\\brequire\\(\\s*['\"\\x60](?:node:)?os['\"\\x60]\\s*\\))\\s*\\.\\s*hostname\\s*\\(",
   "flags": ""
  },
  {
   "name": "os.userInfo",
   "regex": "(?:\\bos|\\brequire\\(\\s*['\"\\x60](?:node:)?os['\"\\x60]\\s*\\))\\s*\\.\\s*userInfo\\s*\\(",
   "flags": ""
  },
  {
   "name": "os.networkInterfaces",
   "regex": "(?:\\bos|\\brequire\\(\\s*['\"\\x60](?:node:)?os['\"\\x60]\\s*\\))\\s*\\.\\s*networkInterfaces\\s*\\(",
   "flags": ""
  },
  {
   "name": "env-dump",
   "regex": "JSON\\.stringify\\(\\s*process\\.env\\s*\\)|Object\\.(?:keys|entries|values)\\(\\s*process\\.env\\s*\\)|\\.\\.\\.process\\.env\\b",
   "flags": ""
  },
  {
   "name": "identity-env",
   "regex": "\\bprocess\\.env(?:\\.(?:USER|USERNAME|LOGNAME|HOSTNAME|COMPUTERNAME)\\b|\\[\\s*(['\"\\x60])(?:USER|USERNAME|LOGNAME|HOSTNAME|COMPUTERNAME)\\1\\s*\\])",
   "flags": ""
  }
 ],
 "identity_env": [
  "USER",
  "USERNAME",
  "LOGNAME",
  "HOSTNAME",
  "COMPUTERNAME"
 ],
 "exec_sinks": [
  {
   "name": "child_process",
   "regex": "child_process|\\b(?:execSync|spawnSync|execFileSync|execFile|spawn|fork)\\s*\\(",
   "flags": ""
  },
  {
   "name": "eval",
   "regex": "\\beval\\s*\\(",
   "flags": ""
  },
  {
   "name": "Function",
   "regex": "(?:^|[^\\w$.])(?:new\\s+)?Function\\s*\\(",
   "flags": ""
  },
  {
   "name": "vm",
   "regex": "\\bvm\\.(?:runIn(?:New|This)?Context|Script)\\s*\\(",
   "flags": ""
  }
 ],
 "capability_classes": [
  "net",
  "exec",
  "decode",
  "obf",
  "cred"
 ],
 "decode_markers": [
  {
   "name": "eval",
   "regex": "\\beval\\s*\\(",
   "flags": ""
  },
  {
   "name": "Function",
   "regex": "(?:^|[^\\w$.])(?:new\\s+)?Function\\s*\\(",
   "flags": ""
  },
  {
   "name": "atob",
   "regex": "\\batob\\s*\\(",
   "flags": ""
  }
 ],
 "cred_sources": [
  {
   "name": "npmrc",
   "regex": "\\.npmrc\\b",
   "flags": ""
  },
  {
   "name": "ssh-key",
   "regex": "\\.ssh\\/|\\bid_rsa\\b|\\bid_ed25519\\b|\\bid_ecdsa\\b",
   "flags": ""
  },
  {
   "name": "aws-credentials",
   "regex": "\\.aws\\/credentials|\\bAWS_SECRET_ACCESS_KEY\\b|\\bAWS_ACCESS_KEY_ID\\b",
   "flags": ""
  },
  {
   "name": "git-credentials",
   "regex": "\\.git-credentials\\b",
   "flags": ""
  },
  {
   "name": "token-env",
   "regex": "\\b(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN)\\b",
   "flags": ""
  },
  {
   "name": "env-dump",
   "regex": "JSON\\.stringify\\(\\s*process\\.env\\s*\\)|Object\\.(?:keys|entries|values)\\(\\s*process\\.env\\s*\\)|\\.\\.\\.process\\.env\\b",
   "flags": ""
  },
  {
   "name": "wallet-file",
   "regex": "wallet\\.dat|Local Storage\\/leveldb|\\.config\\/gcloud|\\.kube\\/config",
   "flags": ""
  }
 ],
 "limits": {
  "keepFiles": 6,
  "keepBytes": 1048576,
  "maxBin": 4,
  "maxHookTargets": 3,
  "s1MaxBytes": 8192,
  "s2MinIdents": 20,
  "s2MinCharCodes": 50,
  "s2HexDensity": 0.15,
  "s2MinNumericHex": 1000,
  "s4MinAddressFamilies": 2,
  "headBytes": 8000,
  "pathChars": 200
 },
 "s7_named": {
  "arms": [
   "decode-obf",
   "net+exec"
  ],
  "decode_obf_excluded": [
   "decode:Function"
  ],
  "exec_excluded": [
   "exec:Function"
  ],
  "test_vectors": [
   {
    "gains": [
     "decode:eval",
     "exec:eval",
     "net:xhr"
    ],
    "arms": [
     "decode-obf",
     "net+exec"
    ],
    "named": [
     "decode:eval",
     "exec:eval",
     "net:xhr"
    ]
   },
   {
    "gains": [
     "decode:atob"
    ],
    "arms": [
     "decode-obf"
    ],
    "named": [
     "decode:atob"
    ]
   },
   {
    "gains": [
     "decode:numeric-hex",
     "obf:_0x-idents"
    ],
    "arms": [
     "decode-obf"
    ],
    "named": [
     "decode:numeric-hex",
     "obf:_0x-idents"
    ]
   },
   {
    "gains": [
     "exec:child_process",
     "net:http-request"
    ],
    "arms": [
     "net+exec"
    ],
    "named": [
     "exec:child_process",
     "net:http-request"
    ]
   },
   {
    "gains": [
     "decode:later-class"
    ],
    "arms": [
     "decode-obf"
    ],
    "named": [
     "decode:later-class"
    ]
   },
   {
    "gains": [
     "decode:Function",
     "exec:Function"
    ],
    "arms": [],
    "named": []
   },
   {
    "gains": [
     "decode:Function",
     "exec:Function",
     "net:websocket"
    ],
    "arms": [],
    "named": []
   },
   {
    "gains": [
     "exec:Function",
     "net:fetch"
    ],
    "arms": [],
    "named": []
   },
   {
    "gains": [
     "net:fetch"
    ],
    "arms": [],
    "named": []
   },
   {
    "gains": [
     "exec:child_process"
    ],
    "arms": [],
    "named": []
   },
   {
    "gains": [
     "net:url-literal",
     "exec:child_process"
    ],
    "arms": [],
    "named": []
   },
   {
    "gains": [
     "cred:npmrc",
     "cred:env-dump"
    ],
    "arms": [],
    "named": []
   },
   {
    "gains": [
     "cred:npmrc",
     "exec:child_process",
     "net:fetch"
    ],
    "arms": [
     "net+exec"
    ],
    "named": [
     "exec:child_process",
     "net:fetch"
    ]
   },
   {
    "gains": [
     "net:fetch",
     "exec:Function",
     "exec:eval"
    ],
    "arms": [
     "net+exec"
    ],
    "named": [
     "exec:eval",
     "net:fetch"
    ]
   },
   {
    "gains": [
     "decode:Function",
     "decode:eval"
    ],
    "arms": [
     "decode-obf"
    ],
    "named": [
     "decode:eval"
    ]
   },
   {
    "gains": [],
    "arms": [],
    "named": []
   }
  ]
 }
};

// 1.7: the two bound-form sinks keep their 1.5 regex as `literal` (cft015-static-checks-1.7)
const pairs = (list) => list.map(([name, re]) => ({ name, regex: (re.literal ?? re).source, flags: (re.literal ?? re).flags }));
const want = (list) => list.map((x) => ({ name: x.name, regex: x.regex, flags: x.flags ?? '' }));

test('P14-1 the version string and the eight checks (id, gate, class, roles, notice) are recon\'s (static-checks-1.5; 1.6 adds facts only)', async () => {
  const S = await SC();
  // static-checks-1.6 (R11, recon v6.14) is a facts-only bump: every 1.5 constant here is unchanged (cft015-static-checks-1.6, C2)
  assert.equal(R14.version, 'static-checks-1.5'); assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.9');   // 1.9: S0 and S6 (cft016-static-checks-1.9); then 1.7: the bound-module sinks; 1.8: S8 and S9 appended
  assert.deepEqual(S.CHECKS.slice(0, 8).map(({ id, gate, cls, roles, notice }) => ({ id, gate, cls, roles, notice })), R14.checks);   // S0-S7; 1.8 appends S8, S9 (declared)
});

test('P14-2 S0 1.4: the shells, the sh -c pattern, the network tools (absolute path prefix), the DNS tools and the sends markers', async () => {
  const S = await SC();
  assert.deepEqual([...S.SHELLS], R14.shells);
  assert.deepEqual({ regex: S.SHELL_C.source, flags: S.SHELL_C.flags }, R14.shell_c);
  assert.deepEqual(pairs(S.NET_TOOLS), want(R14.net_tools));
  assert.deepEqual([...S.DNS_TOOLS], R14.dns_tools);
  assert.deepEqual(S.SEND_MARKERS.map(([name, re]) => ({ name, regex: re instanceof RegExp ? re.source : null })), R14.send_markers);
});

test('P14-3 S6 and S7 vocabularies: API network sinks, host identity, identity variables, execution sinks, capability classes, decode markers, credential sources', async () => {
  const S = await SC();
  assert.deepEqual(pairs(S.API_NET_SINKS), want(R14.api_net_sinks));
  assert.deepEqual(pairs(S.HOST_IDENTITY), want(R14.host_identity));
  assert.deepEqual([...S.IDENTITY_ENV], R14.identity_env);
  assert.deepEqual(pairs(S.EXEC_SINKS), want(R14.exec_sinks));
  assert.deepEqual([...S.CAPABILITY_CLASSES], R14.capability_classes);
  assert.deepEqual(pairs(S.DECODE_MARKERS), want(R14.decode_markers));
  assert.deepEqual(pairs(S.CRED_SOURCES), want(R14.cred_sources));
});

test('P14-4 the limits are recon\'s (keep 6 x 1 MiB, 4 bin, 3 hook targets, the S1/S2/S4 thresholds, the 8000-byte head)', async () => {
  const S = await SC(); const L = R14.limits;
  assert.deepEqual([S.LIMITS.maxKeep, S.LIMITS.maxKeepBytes, S.LIMITS.maxBin, S.LIMITS.maxHookTargets, S.LIMITS.s1MaxBytes, S.LIMITS.s2MinIdents, S.LIMITS.s2MinCharCodes,
    S.LIMITS.s2HexDensity, S.LIMITS.s2MinNumericHex, S.LIMITS.s4MinAddressFamilies, S.LIMITS.headBytes],
  [L.keepFiles, L.keepBytes, L.maxBin, L.maxHookTargets, L.s1MaxBytes, L.s2MinIdents, L.s2MinCharCodes, L.s2HexDensity, L.s2MinNumericHex, L.s4MinAddressFamilies, L.headBytes]);
});

test('P15-1 S7 named condition (R9, R9a, R9b): the arms, decode:Function out of the decode-obf arm, exec:Function out of the net+exec arm', async () => {
  const S = await SC();
  assert.deepEqual([...S.S7_NAMED_ARMS], R14.s7_named.arms);
  assert.deepEqual([...S.S7_DECODE_OBF_EXCLUDED], R14.s7_named.decode_obf_excluded);
  assert.deepEqual([...S.S7_EXEC_EXCLUDED], R14.s7_named.exec_excluded);
});

test('P15-2 s7Named gives recon\'s arms and named gains on all 16 of recon\'s test vectors', async () => {
  const S = await SC();
  assert.equal(R14.s7_named.test_vectors.length, 16);
  for (const v of R14.s7_named.test_vectors) assert.deepEqual(S.s7Named(v.gains), { arms: v.arms, named: v.named }, JSON.stringify(v.gains));
});
