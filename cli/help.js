// The per-command `--help` text, printed by `chaingate <command> --help` (cli/index.js). One exported table so a test can check that
// every flag a command parses is named here (0.1.5 #8).
export const COMMAND_HELP = Object.freeze({
  init: 'chaingate init [--no-seed] [--seed <path>] [--unsigned-development] [--scope user|project] [--force] [--dry-run]',
  status: 'chaingate status [--json] [--scope user|project]',
  allow: 'chaingate allow <package>@<version> --reason "..." [--scope user|project]',
  stop: 'chaingate stop [--scope user|project]',
  'update-seed': 'chaingate update-seed [--force] [--scope user|project]\n'
    + '  chaingate update-seed --seed <path> [--unsigned-development] [--scope user|project]\n'
    + '  chaingate update-seed --rollback [--scope user|project]',
  'update-advisories': 'chaingate update-advisories [--json] [--scope user|project]\n'
    + '  chaingate update-advisories --file <dir> [--json] [--scope user|project]\n'
    + '  chaingate update-advisories --accept-cut <sha256> [--file <dir>] [--scope user|project]\n'
    + '  Exit codes: 0=current, 2=a cut is held (see --accept-cut), 1=refused or unreadable',
  why: 'chaingate why <package>@<version> --packument <file> [--json] [--scope user|project]\n'
    + '  chaingate why --from <check.json> [--json]\n'
    + '  chaingate why <package>@<version> --cached [--json]   (legacy row, UNBOUND, exit 4)\n'
    + '  chaingate why <package>@<version>                     (no mode: the same as --cached)',
  history: 'chaingate history <package> [--limit N] [--json] [--scope user|project]',
  doctor: 'chaingate doctor [--json] [--scope user|project]',
  check: 'chaingate check <package>@<version> --packument <file> [--tarball <file>] [--json] [--scope user|project]\n  Exit codes (follow the effective action): 0=ALLOW, 2=WARN, 3=BLOCK, 4=tool error',
  overrides: 'chaingate overrides [list|revoke <package>@<version>] [--json] [--scope user|project]',
  accept: 'chaingate accept <package>@<version> | --revoke <package>@<version> | --list [--scope user|project]',
  pin: 'chaingate pin <package>@<version> | --list [--scope user|project]',
  unpin: 'chaingate unpin <package> [<major> | 0.<minor>] [--scope user|project]',
  report: 'chaingate report [--all | --since <dur>] [--json] [--scope user|project]\n'
    + '  Exit codes: 0=nothing named, refused or tag-moved, 2=named warnings, 3=a refusal or a moved dist-tag, 4=tool error or incomplete record',
});
