#!/usr/bin/env python3
"""Pin GitHub Actions to SHA and enforce persist-credentials: false.

Scans .github/workflows/*.yml, resolves version tags to commit SHAs
via git ls-remote, and reports what would change (dry-run by default).
Pass --apply to write changes to files.
"""
import argparse
import os
import re
import subprocess
import sys
import glob as globmod

USES_RE = re.compile(r'^(?P<indent>\s*)uses:\s*(?P<ref>(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)@(?P<tag>v[0-9][^\s#]*))(\s*#.*)?$')
ALREADY_SHA_RE = re.compile(r'^[0-9a-f]{40}$')
CHECKOUT_STEP_RE = re.compile(r'^(\s*-?\s*uses:\s*\S*actions/checkout\S*)')
PERSIST_CRED_RE = re.compile(r'persist-credentials:\s*false')
INDENT_RE = re.compile(r'^(\s*)')
STEP_USES_RE = re.compile(r'^\s*-?\s*uses:\s')


def find_workflow_files():
    patterns = ['.github/workflows/*.yml', '.github/workflows/*.yaml']
    files = []
    for pat in patterns:
        files.extend(globmod.glob(pat))
    return sorted(set(files))


def git_ls_remote(owner, repo, tag, timeout=15):
    url = f'https://github.com/{owner}/{repo}.git'
    try:
        result = subprocess.run(
            ['git', 'ls-remote', url, f'refs/tags/{tag}'],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.strip().splitlines():
            sha, ref = line.split('\t', 1)
            if ref == f'refs/tags/{tag}':
                return sha
            deref = 'refs/tags/' + tag + '^{}'
            if ref == deref:
                return sha
        lines = result.stdout.strip().splitlines()
        if lines:
            return lines[0].split('\t')[0]
        return None
    except subprocess.TimeoutExpired:
        print(f'  [WARN] timeout fetching {owner}/{repo}@{tag}', file=sys.stderr)
        return None
    except Exception as e:
        print(f'  [WARN] error fetching {owner}/{repo}@{tag}: {e}', file=sys.stderr)
        return None


def process_file(filepath, dry_run=True):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    changes = []
    new_lines = []
    checkout_fixes = []

    i = 0
    while i < len(lines):
        line = lines[i]

        m_uses = USES_RE.match(line)
        if m_uses:
            tag = m_uses.group('tag')
            sha_part = m_uses.group('ref').split('@')[1]
            if not ALREADY_SHA_RE.match(sha_part):
                owner = m_uses.group('owner')
                repo = m_uses.group('repo')
                indent = m_uses.group('indent')
                print(f'  resolving {owner}/{repo}@{tag} ...', end=' ', flush=True)
                sha = git_ls_remote(owner, repo, tag)
                if sha:
                    new_line = f'{indent}uses: {owner}/{repo}@{sha}\n'
                    new_lines.append(new_line)
                    changes.append(('pin', f'{owner}/{repo}@{tag}', sha[:12]))
                    print(f'→ {sha[:12]}')
                    i += 1
                    continue
                else:
                    print('FAILED (kept original)')

        new_lines.append(line)

        if CHECKOUT_STEP_RE.match(line) and not PERSIST_CRED_RE.search(line):
            base_indent_match = INDENT_RE.match(line)
            base_indent = base_indent_match.group(1) if base_indent_match else ''
            next_block_indent = base_indent + '  '
            credential_line = f'{next_block_indent}persist-credentials: false\n'
            j = i + 1
            insert_pos = i + 1
            while j < len(lines):
                next_line = lines[j]
                if next_line.strip() == '' or INDENT_RE.match(next_line).group(1) > base_indent:
                    insert_pos = j
                    j += 1
                else:
                    break
            else:
                insert_pos = len(lines)
            new_lines.insert(insert_pos, credential_line)
            checkout_fixes.append((insert_pos, filepath))
            changes.append(('persist-credentials', filepath, f'line {insert_pos + 1}'))
            i = insert_pos + 1
            continue

        i += 1

    return new_lines, changes, checkout_fixes


def main():
    parser = argparse.ArgumentParser(
        description='Pin GitHub Actions to SHA and enforce persist-credentials: false.',
    )
    parser.add_argument(
        '--apply', action='store_true', default=False,
        help='Write changes to workflow files (default: dry-run, no writes)',
    )
    args = parser.parse_args()
    dry_run = not args.apply

    if not os.path.isdir('.github/workflows'):
        print('ERROR: .github/workflows/ not found. Run from repo root.', file=sys.stderr)
        sys.exit(1)

    files = find_workflow_files()
    if not files:
        print('No workflow files found.')
        return

    if dry_run:
        print('DRY RUN — no files will be modified. Use --apply to write changes.\n')

    all_changes = []
    total_pins = 0
    total_creds = 0

    for filepath in files:
        print(f'\n[{filepath}]')
        new_lines, changes, _ = process_file(filepath, dry_run=dry_run)

        if changes and not dry_run:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)

        for kind, *rest in changes:
            all_changes.append((kind, filepath, *rest))
            if kind == 'pin':
                total_pins += 1
            elif kind == 'persist-credentials':
                total_creds += 1

    print('\n' + '=' * 60)
    print('SUMMARY' + (' (dry-run)' if dry_run else ' (applied)'))
    print('=' * 60)

    if not all_changes:
        print('No changes needed. All actions SHA-pinned, all checkouts have persist-credentials: false.')
        return

    print(f'{"Type":<22} {"Location":<28} {"Detail"}')
    print('-' * 60)
    for entry in all_changes:
        kind = entry[0]
        loc = entry[1]
        detail = ' '.join(str(x) for x in entry[2:])
        print(f'{kind:<22} {loc:<28} {detail}')

    print('-' * 60)
    print(f'SHAs pinned: {total_pins}  |  persist-credentials added: {total_creds}')
    if dry_run:
        print('\nDry run complete — nothing written. Run with --apply to commit changes.')
    else:
        print('\nChanges written to files. Review and commit manually.')


if __name__ == '__main__':
    main()
