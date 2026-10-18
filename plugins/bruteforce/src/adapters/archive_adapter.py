"""Bounded, per-member 7z/RAR extraction into generated output names."""
from pathlib import Path
import uuid

from .base import PasswordAdapter
from ..bounded_io import extracted
from ..security import member_safe
from ..subprocess_runner import run

LIST_LIMIT = 4 * 1024 * 1024
MEMBER_LIMIT = 10_000


class ArchiveAdapter(PasswordAdapter):
    name = 'archive_adapter'
    supported_formats = ['7z', 'rar', 'tar', 'gzip']
    supported_protections = ['7z', 'rar', 'password']

    def can_handle(self, artifact, context):
        return self.path(artifact).suffix.lower() in {'.7z', '.rar'}

    def _tool(self, artifact):
        return 'unrar' if self.path(artifact).suffix.lower() == '.rar' else '7z'

    def verify_password(self, artifact, password, context):
        tool = self._tool(artifact)
        args = ['t', f'-p{password}', str(self.path(artifact))]
        result = run(tool, args, context['limits'].timeout_seconds, secret_indexes=(1,))
        return {'valid': result['exit_code'] == 0,
                'reason': 'verified_structure' if result['exit_code'] == 0 else result['status'],
                'audit': result}

    def _members(self, artifact, password, context, tool):
        archive = str(self.path(artifact))
        if tool == '7z':
            args = ['l', '-slt', '-sccUTF-8', f'-p{password}', archive]
            secret_index = 3
        else:
            args = ['lb', f'-p{password}', archive]
            secret_index = 1
        result = run(tool, args, context['limits'].timeout_seconds,
                     secret_indexes=(secret_index,), max_stdout=LIST_LIMIT)
        if result['exit_code'] != 0 or result.get('output_truncated'):
            raise ValueError('archive_listing_incomplete')
        names = []
        if tool == '7z':
            # `-slt` emits a key/value block per member. The first block is archive metadata.
            blocks = result['stdout'].replace('\r\n', '\n').split('\n\n')
            for block in blocks:
                fields = {}
                for line in block.splitlines():
                    if ' = ' in line:
                        key, value = line.split(' = ', 1)
                        fields[key] = value
                name = fields.get('Path')
                if not name or 'Type' in fields or 'Size' not in fields or fields.get('Folder') == '+':
                    continue
                if fields.get('Symbolic Link') or fields.get('Hard Link'):
                    raise ValueError('archive_link_member_rejected')
                if not member_safe(name) or name.startswith('-'):
                    raise ValueError('archive_unsafe_member')
                try:
                    size = int(fields['Size'])
                except ValueError as error:
                    raise ValueError('archive_member_size_invalid') from error
                if size < 0:
                    raise ValueError('archive_member_size_invalid')
                names.append((name, size))
        else:
            for name in result['stdout'].splitlines():
                name = name.rstrip('\r')
                if not name:
                    continue
                if not member_safe(name) or name.startswith('-'):
                    raise ValueError('archive_unsafe_member')
                names.append((name, None))
        if len(names) > MEMBER_LIMIT:
            raise ValueError('archive_member_count_limit')
        return names

    def extract(self, artifact, password, context):
        tool = self._tool(artifact)
        members = self._members(artifact, password, context, tool)
        limit = max(0, int(context['limits'].max_output))
        root = Path(context['output_dir']) / 'unlocked' / uuid.uuid4().hex
        root.mkdir(parents=True, exist_ok=False)
        total = 0
        output = []
        try:
            for index, (name, declared_size) in enumerate(members):
                if declared_size is not None and declared_size > limit - total:
                    raise ValueError('archive_expansion_limit')
                remaining = limit - total
                target = root / f'member-{index:05d}.bin'
                archive = str(self.path(artifact))
                if tool == '7z':
                    args = ['x', '-so', '-bd', f'-p{password}', archive, name]
                    secret_index = 3
                else:
                    args = ['p', '-inul', '-idq', f'-p{password}', archive, name]
                    secret_index = 3
                result = run(tool, args, context['limits'].timeout_seconds,
                             secret_indexes=(secret_index,), output_path=target,
                             max_stdout=remaining)
                if result.get('output_truncated'):
                    target.unlink(missing_ok=True)
                    raise ValueError('archive_expansion_limit')
                if result['exit_code'] != 0:
                    target.unlink(missing_ok=True)
                    raise ValueError(result['status'])
                info = extracted(target, remaining)
                if declared_size is not None and info['size'] != declared_size:
                    target.unlink(missing_ok=True)
                    raise ValueError('archive_member_size_mismatch')
                info['name'] = Path(name).name
                total += info['size']
                output.append(info)
        except Exception:
            import shutil
            shutil.rmtree(root, ignore_errors=True)
            raise
        return output
