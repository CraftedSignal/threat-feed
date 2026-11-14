"""Static-site workflow contracts migrated from internal/workflowconfig Go tests.

Tests read the actual repository workflow files; no tooling-repository fixtures.
"""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow(name):
    return yaml.safe_load((ROOT / '.github' / 'workflows' / name).read_text())


def triggers(value):
    # PyYAML's YAML 1.1 resolver treats the Actions key `on` as boolean true.
    return value.get('on', value.get(True, {}))


def steps(job):
    return job['steps']


def action(job, name):
    return next(s for s in steps(job) if name in s.get('uses', ''))


class SiteWorkflowContracts(unittest.TestCase):
    def setUp(self):
        self.site = workflow('site.yml')
        self.jobs = self.site['jobs']

    def test_batches_production_and_keeps_manual_pr_gates(self):
        event = triggers(self.site)
        self.assertEqual(event['push']['branches'], ['main'])
        self.assertEqual(event['push']['paths'], ['site/static/stix.json'])
        self.assertEqual(event['schedule'], [{'cron': '7,22,37,52 * * * *'}])
        self.assertIn('workflow_dispatch', event)
        self.assertEqual(self.site['concurrency']['cancel-in-progress'], "${{ github.event_name == 'pull_request' }}")
        group = self.site['concurrency']['group']
        for term in ['pull_request', 'production']:
            self.assertIn(term, group)
        # A required check cannot live behind a workflow path filter: GitHub
        # otherwise leaves documentation-only PRs waiting for an absent check.
        self.assertNotIn('paths', event['pull_request'])
        self.assertIn('pull_request', self.jobs['validate']['if'])
        for name in ['build', 'deploy', 'notify-subscribers']:
            self.assertIn('refs/heads/main', self.jobs[name]['if'])

    def test_pages_wait_artifact_and_permissions_are_bounded(self):
        self.assertEqual(self.site['permissions'], {'contents': 'read'})
        build, deploy = self.jobs['build'], self.jobs['deploy']
        self.assertEqual(build['permissions'], {'contents': 'read', 'pages': 'read'})
        self.assertEqual(deploy['timeout-minutes'], 25)
        for name in ['pages', 'id-token', 'actions']:
            self.assertEqual(deploy['permissions'][name], 'write')
        self.assertEqual(action(deploy, 'actions/deploy-pages')['with']['timeout'], 1200000)
        self.assertEqual(action(build, 'actions/upload-pages-artifact')['with']['retention-days'], 1)
        deploy_index = steps(deploy).index(action(deploy, 'actions/deploy-pages'))
        cleanup_index, cleanup = next((i, s) for i, s in enumerate(steps(deploy))
                                      if 'actions/runs/${GITHUB_RUN_ID}/artifacts' in s.get('run', '')
                                      and '--method DELETE' in s.get('run', ''))
        self.assertGreater(cleanup_index, deploy_index)
        self.assertEqual(cleanup['if'], 'always()')
        self.assertEqual(cleanup['working-directory'], '.')

    def test_stages_only_current_stix_before_pages_upload(self):
        build = self.jobs['build']
        stage = next(i for i, s in enumerate(steps(build)) if 'npm run stage-stix' in s.get('run', ''))
        upload = steps(build).index(action(build, 'actions/upload-pages-artifact'))
        self.assertLess(stage, upload)

    def test_skips_noop_schedules_and_bounds_notification_history(self):
        changes = self.jobs['changes']
        for name in ['site_changed', 'previous_sha', 'previous_comparable']:
            self.assertIn(name, changes['outputs'])
        for name, paths in [('changes', ['.github/workflows/site.yml']),
                            ('notify-subscribers', ['.github/scripts/build-dispatch-payload.py', 'site/content/briefs'])]:
            checkout = action(self.jobs[name], 'actions/checkout')['with']
            self.assertEqual(checkout['fetch-depth'], 1)
            for path in paths:
                self.assertIn(path, checkout['sparse-checkout'])
        self.assertEqual(self.jobs['build']['needs'], 'changes')
        self.assertIn("needs.changes.outputs.site_changed == 'true'", self.jobs['build']['if'])
        self.assertEqual(self.jobs['notify-subscribers']['needs'], ['changes', 'deploy'])

    def test_avoids_ineffective_hugo_resource_cache(self):
        for name in ['validate', 'build']:
            self.assertFalse(any('actions/cache' in s.get('uses', '') for s in steps(self.jobs[name])))

    def test_strict_history_rename_manifest_and_sitemap_gates(self):
        for name, base in [('validate', 'github.event.pull_request.base.sha'),
                           ('build', 'needs.changes.outputs.previous_sha')]:
            with self.subTest(job=name):
                job = self.jobs[name]
                # Only the feed checkout needs ancestry; tooling checkout is bounded.
                feed_checkout = next(s for s in steps(job) if 'actions/checkout' in s.get('uses', '')
                                     and s.get('with', {}).get('repository') != 'CraftedSignal/ti-bot')['with']
                self.assertEqual(feed_checkout['fetch-depth'], 0)
                self.assertEqual(feed_checkout['filter'], 'blob:none')
                named = {s['name']: (i, s) for i, s in enumerate(steps(job)) if 'name' in s}
                validation_index, validation = named['Validate changed public artifacts']
                self.assertIn(base, validation['env']['BASE_SHA'])
                self.assertEqual(validation['working-directory'], '.')
                for required in ['git diff --find-renames --name-status -z --diff-filter=AMRD',
                                 "read -r -d ''", 'if [[ "$status" == D* ]]; then',
                                 'stix_changed=true', 'continue', '--previous-path', 'feedcheck --base-ref',
                                 'site/content/briefs/*.md', ':(exclude)site/content/briefs/_index.md',
                                 'site/static/stix.json', 'site/static/stix/**',
                                 'changed+=("site/static/stix/index.json")']:
                    self.assertIn(required, validation['run'])
                self.assertNotIn('--legacy', validation['run'])
                build_index = named['Build site'][0]
                shard_index, shard = named['Shard generated sitemap']
                sitemap_index, sitemap = named['Validate generated sitemap']
                self.assertLess(validation_index, build_index)
                self.assertLess(build_index, shard_index)
                self.assertLess(shard_index, sitemap_index)
                self.assertIn('python3 scripts/shard_sitemap.py public', shard['run'])
                self.assertIn('feedcheck --generated-site site/public', sitemap['run'])
                self.assertEqual(sitemap['working-directory'], '.')

    def test_tooling_is_public_digest_pinned_without_private_auth_or_source(self):
        manifest = json.loads((ROOT / '.github/tooling/feedcheck.json').read_text())
        self.assertRegex(manifest['source_sha'], r'^[0-9a-f]{40}$')
        self.assertRegex(manifest['sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual(manifest['platform'], 'linux/amd64')
        self.assertEqual(manifest['url'], 'https://github.com/CraftedSignal/threat-feed/releases/download/feedcheck-'
                         + manifest['source_sha'] + '/feedcheck-linux-amd64')
        self.assertFalse(manifest['build']['cgo_enabled'])
        self.assertFalse(manifest['build']['buildvcs'])
        self.assertTrue(manifest['build']['trimpath'])
        for name in ['validate', 'build']:
            with self.subTest(job=name):
                job = self.jobs[name]
                install = next(s for s in steps(job) if s.get('name') == 'Install pinned public feed validator')
                self.assertEqual(install['working-directory'], '.')
                self.assertIn('python3 .github/scripts/install-feedcheck.py', install['run'])
                self.assertIn('"$RUNNER_TEMP/feedcheck"', install['run'])
                self.assertIn('"$RUNNER_TEMP" >> "$GITHUB_PATH"', install['run'])
                self.assertNotIn('secrets.', json.dumps(install))
                for step in steps(job):
                    self.assertNotEqual(step.get('with', {}).get('repository'), 'CraftedSignal/ti-bot')
                    self.assertNotIn('actions/setup-go', step.get('uses', ''))
                    self.assertNotIn('go run ./cmd/feedcheck', step.get('run', ''))

    def test_changed_artifact_script_preserves_rename_and_feed_cwd(self):
        # Run the actual workflow shell against real Git history in a standalone
        # feed checkout. The instrumented binary records exactly what CI invokes.
        script = next(s['run'] for s in steps(self.jobs['validate'])
                      if s.get('name') == 'Validate changed public artifacts')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, text=True).strip()
            git('init', '-q')
            git('config', 'user.email', 'test@example.test')
            git('config', 'user.name', 'Workflow Test')
            old = root / 'site/content/briefs/old.md'
            old.parent.mkdir(parents=True)
            old.write_text('unchanged brief for exact rename detection\n')
            git('add', '.')
            git('commit', '-qm', 'old path')
            base = git('rev-parse', 'HEAD')
            new = old.with_name('new.md')
            old.rename(new)
            git('add', '-A')
            git('commit', '-qm', 'rename brief')
            current = git('rev-parse', 'HEAD')
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            binary = bin_dir / 'feedcheck'
            binary.write_text('#!/usr/bin/env python3\nimport os,sys,json\n'
                              'open(os.environ["CAPTURE"],"w").write(json.dumps({"cwd":os.getcwd(),"args":sys.argv[1:]}))\n')
            binary.chmod(0o755)
            capture = root / 'capture.json'
            env = dict(os.environ, BASE_SHA=base, CURRENT_SHA=current, CAPTURE=str(capture),
                       PATH=str(bin_dir) + os.pathsep + os.environ['PATH'])
            subprocess.run(['bash', '-euo', 'pipefail', '-c', script], cwd=root, env=env, check=True)
            called = json.loads(capture.read_text())
            self.assertEqual(Path(called['cwd']).resolve(), root.resolve())
            self.assertEqual(called['args'], ['--base-ref', base, '--previous-path',
                                             'site/content/briefs/new.md=site/content/briefs/old.md',
                                             'site/content/briefs/new.md'])

    def test_website_does_not_own_go_source_or_dependencies(self):
        self.assertFalse((ROOT / 'go.mod').exists())
        self.assertFalse((ROOT / 'go.sum').exists())
        for directory in ['cmd', 'internal', 'pkg']:
            self.assertEqual(list((ROOT / directory).rglob('*.go')), [])


class GeneralWorkflowContracts(unittest.TestCase):
    def test_secret_scanning_uses_bounded_pull_request_history(self):
        scan = workflow('security.yml')['jobs']['secrets-scan']
        checkout = action(scan, 'actions/checkout')['with']
        self.assertIsNotNone(checkout.get('fetch-depth'))
        self.assertNotEqual(checkout['fetch-depth'], 0)
        self.assertTrue(any('git fetch --no-tags --depth=1' in s.get('run', '') and 'BASE_SHA' in s.get('run', '') for s in steps(scan)))

    def test_general_ci_gates_prs_without_repeating_on_merge(self):
        # Go lint moved with Go source; website contract/security checks remain.
        self.assertFalse((ROOT / '.github/workflows/lint.yml').exists())
        for name in ['test.yml', 'codeql.yml', 'security.yml']:
            event = triggers(workflow(name))
            self.assertNotIn('push', event)
            self.assertIn('pull_request', event)
            self.assertIn('workflow_dispatch', event)

    def test_required_checks_emit_on_documentation_only_pull_requests(self):
        for name in ['test.yml', 'codeql.yml', 'security.yml', 'site.yml']:
            event = triggers(workflow(name))['pull_request']
            self.assertNotIn('paths', event, name)
            self.assertNotIn('paths-ignore', event, name)

    def test_security_analysis_retains_scheduled_static_code_drift_checks(self):
        for name in ['codeql.yml', 'security.yml']:
            self.assertTrue(triggers(workflow(name))['schedule'])
        analysis = workflow('codeql.yml')['jobs']['analyze']
        languages = action(analysis, 'github/codeql-action/init')['with']['languages']
        self.assertIn('javascript-typescript', languages)
        self.assertNotEqual(languages, 'go')
        self.assertNotIn('govulncheck', workflow('security.yml')['jobs'])


if __name__ == '__main__':
    unittest.main()
