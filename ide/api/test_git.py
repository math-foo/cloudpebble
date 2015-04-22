"""
Tests in this file can be run with python manage.py ide/api/
"""

import json
from django.http import HttpResponse
from django.test import TestCase
from mock import call, patch, MagicMock, Mock

# These two decorators must be patched before the git module is loaded as
# decorators are applied upon module loading.

patch('django.contrib.auth.decorators.login_required', lambda x: x).start()
patch('django.views.decorators.http.require_POST', lambda x: x).start()

import git


@patch('ide.api.git.get_object_or_404')
class GithubPushPullTest(TestCase):
    def setUp(self):
        self.project_id = 12345

        self.test_commit_message = 'A test commit message, for testing'
        self.request = Mock()
        self.request.user = "test_user"
        self.request.POST = {'commit_message': self.test_commit_message}

        self.task = Mock()
        self.task.task_id = 98765

        self.project = Mock()
        self.project.id = 222222

    @patch('ide.api.git.do_github_push')
    def test_github_push(self, github_push_mock, get_object_mock):
        github_push_mock.delay.return_value = self.task
        get_object_mock.return_value = self.project

        http_response = git.github_push(self.request, self.project_id)

        self.assertEqual(98765, json.loads(http_response.content)['task_id'])
        github_push_mock.delay.assert_called_once_with(222222, self.test_commit_message)
        get_object_mock.assert_called_once_with(git.Project, owner='test_user', pk=12345)

    @patch('ide.api.git.do_github_pull')
    def test_github_pull(self, github_pull_mock, get_object_mock):
        github_pull_mock.delay.return_value = self.task
        get_object_mock.return_value = self.project

        http_response = git.github_pull(self.request, self.project_id)

        self.assertEqual(98765, json.loads(http_response.content)['task_id'])
        github_pull_mock.delay.assert_called_once_with(222222)
        get_object_mock.assert_called_once_with(git.Project, owner='test_user', pk=12345)

@patch('ide.git.get_github')
@patch('ide.api.git.get_object_or_404')
class SetProjectRepoTest(TestCase):
    def set_up_expected_content(self, access, updated, branch_exists, exists):
        content_string = ('{{"access": {}, "success": true, "updated": {},'
                          ' "branch_exists": {}, "exists": {}}}').format(
                              *map(lambda x: str(x).lower(),
                              [access, updated, branch_exists, exists]))
        return content_string

    def setUp(self):
        self.project_id = 12345
        self.project = Mock()
        self.project.github_repo = 'pebble/cloudpebble'
        self.project.github_branch = 'test-branch'
        self.project.github_hook_uuid = 55555
        self.project.id = 777777

        self.request = Mock()
        self.request.user = 'test-user'
        self.request.POST = {'repo' : 'https://github.com/pebble/cloudpebble',
                             'branch': 'test-branch',
                             'auto_pull': '0',
                             'auto_build': '0'}

        self.get_repo_mock = Mock()

        self.github_mock = Mock()
        self.github_mock.get_repo.return_value = self.get_repo_mock

    def test_set_project_repo(self, get_object_mock, get_github_mock):
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = self.set_up_expected_content(True, True, True, True)
        self.assertEquals(expected_content, http_response.content)

        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_called_once_with('pebble/cloudpebble')
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)
        self.project.save.assert_called_once_with()

    def test_invalid_repo_url(self, get_object_mock, get_github_mock):
        get_object_mock.return_value = self.project

        self.request.POST['repo'] = 'https://bad/repo/url.com'

        http_response = git.set_project_repo(self.request, self.project_id)


        expected_content = '{"success": false, "error": "Invalid repo URL."}'

        self.assertEquals(expected_content, http_response.content)
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)

    def test_get_repo_exception(self, get_object_mock, get_github_mock):
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock
        self.github_mock.get_repo.side_effect = git.UnknownObjectException('test exception','test get_repo')

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = self.set_up_expected_content(False, False, False, False)
        self.assertEquals(expected_content, http_response.content)

        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_called_once_with('pebble/cloudpebble')
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)


    @patch('ide.git.git_verify_tokens')
    @patch('ide.api.git.remove_hooks')
    def test_remove_hooks_called(self, remove_hooks_mock, verify_tokens_mock, get_object_mock, get_github_mock):
        self.project.github_repo = 'NOTpebble/NOTcloudpebble'
        self.project.github_hook_uuid = 98765
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock
        verify_tokens_mock.return_value = False

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = '{"success": false, "error": "No GitHub tokens on file."}'
        self.assertEquals(expected_content, http_response.content)

        remove_hooks_mock.assert_called_once_with(self.get_repo_mock, 98765)
        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_has_calls([call('pebble/cloudpebble'), call('NOTpebble/NOTcloudpebble')])
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)
        verify_tokens_mock.assert_called_once_with('test-user')
        self.assertEqual(0, self.project.save.call_count)

    @patch('ide.git.git_verify_tokens')
    @patch('ide.api.git.remove_hooks')
    def test_git_token_verification_fails(self, remove_hooks_mock, verify_tokens_mock, get_object_mock, get_github_mock):
        self.project.github_repo = 'NOTpebble/NOTcloudpebble'
        self.project.github_hook_uuid = None
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock
        verify_tokens_mock.return_value = False

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = '{"success": false, "error": "No GitHub tokens on file."}'
        self.assertEquals(expected_content, http_response.content)

        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_called_once_with('pebble/cloudpebble')
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)
        self.assertEqual(0, remove_hooks_mock.call_count)
        verify_tokens_mock.assert_called_once_with('test-user')
        self.assertEqual(0, self.project.save.call_count)

    @patch('ide.git.git_verify_tokens')
    @patch('ide.git.check_repo_access')
    def test_check_repo_access_exception(self, check_repo_mock, verify_tokens_mock, get_object_mock, get_github_mock):
        self.project.github_repo = 'NOTpebble/NOTcloudpebble'
        self.project.github_hook_uuid = None
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock
        verify_tokens_mock.return_value = True
        check_repo_mock.side_effect = git.UnknownObjectException('test exception','test check_repo_access')

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = self.set_up_expected_content(False, False, False, False)
        self.assertEquals(expected_content, http_response.content)

        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_called_once_with('pebble/cloudpebble')
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)
        verify_tokens_mock.assert_called_once_with('test-user')
        check_repo_mock.assert_called_once_with('test-user','pebble/cloudpebble')
        self.assertEqual(0, self.project.save.call_count)

    @patch('ide.git.git_verify_tokens')
    @patch('ide.git.check_repo_access')
    def test_no_repo_access(self, check_repo_mock, verify_tokens_mock, get_object_mock, get_github_mock):
        self.project.github_repo = 'NOTpebble/NOTcloudpebble'
        self.project.github_hook_uuid = None
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock
        verify_tokens_mock.return_value = True
        check_repo_mock.return_value = False

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = self.set_up_expected_content(True, True, True, True)
        self.assertEquals(expected_content, http_response.content)

        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_called_once_with('pebble/cloudpebble')
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)
        verify_tokens_mock.assert_called_once_with('test-user')
        check_repo_mock.assert_called_once_with('test-user','pebble/cloudpebble')
        self.assertEqual(0, self.project.save.call_count)

    @patch('ide.git.git_verify_tokens')
    @patch('ide.git.check_repo_access')
    def test_repo_mismatch_repo_access(self, check_repo_mock, verify_tokens_mock, get_object_mock, get_github_mock):
        self.project.github_repo = 'NOTpebble/NOTcloudpebble'
        self.project.github_branch = 'NOT-test-branch'
        self.project.github_last_sync = 'foo'
        self.project.github_last_commit = 'bar'
        self.project.github_hook_uuid = ''
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock
        verify_tokens_mock.return_value = True
        check_repo_mock.return_value = True

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = self.set_up_expected_content(True, True, True, True)
        self.assertEquals(expected_content, http_response.content)

        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_called_once_with('pebble/cloudpebble')
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)
        verify_tokens_mock.assert_called_once_with('test-user')
        check_repo_mock.assert_called_once_with('test-user','pebble/cloudpebble')
        self.assertEqual('pebble/cloudpebble', self.project.github_repo)
        self.assertEqual('test-branch', self.project.github_branch)
        self.assertIsNone(self.project.github_last_sync)
        self.assertIsNone(self.project.github_last_commit)
        self.assertIsNone(self.project.github_hook_uuid)
        self.project.save.assert_called_once_with()

    def test_repo_branch_does_not_match(self, get_object_mock, get_github_mock):
        self.project.github_branch = 'NOT-test-branch'
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = self.set_up_expected_content(True, True, True, True)
        self.assertEquals(expected_content, http_response.content)

        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_called_once_with('pebble/cloudpebble')
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)
        self.assertEqual('test-branch', self.project.github_branch)
        self.project.save.assert_called_once_with()

    def test_create_new_hook_uuid_exception(self, get_object_mock, get_github_mock):
        self.project.github_hook_uuid = None
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock
        self.request.POST['auto_pull'] = '1'
        self.get_repo_mock.create_hook.side_effect = Exception('test exception raised by create_hook')

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = '{"success": false, "error": "test exception raised by create_hook"}'
        self.assertEquals(expected_content, http_response.content)

        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_called_once_with('pebble/cloudpebble')
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)

        self.assertIsNotNone(self.project.github_hook_uuid)
        create_hook_url = 'http://example.com/ide/project/{}/github/push_hook?key={}'.format(self.project.id,
                                                                                             self.project.github_hook_uuid)
        self.get_repo_mock.create_hook.assert_called_once_with('web',
                                                               {'url': create_hook_url, 'content_type': 'form'},
                                                               ['push'],
                                                               True)
        self.assertEqual(0, self.project.save.call_count)

    def test_create_new_uuid_hook_success(self, get_object_mock, get_github_mock):
        self.project.github_hook_uuid = None
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock
        self.request.POST['auto_pull'] = '1'

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = self.set_up_expected_content(True, True, True, True)
        self.assertEquals(expected_content, http_response.content)

        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_called_once_with('pebble/cloudpebble')
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)

        self.assertIsNotNone(self.project.github_hook_uuid)
        create_hook_url = 'http://example.com/ide/project/{}/github/push_hook?key={}'.format(self.project.id,
                                                                                             self.project.github_hook_uuid)
        self.get_repo_mock.create_hook.assert_called_once_with('web',
                                                               {'url': create_hook_url, 'content_type': 'form'},
                                                               ['push'],
                                                               True)
        self.project.save.assert_called_once_with()

    def test_auto_pull_false_remove_uuid_hook(self, get_object_mock, get_github_mock):
        get_object_mock.return_value = self.project
        get_github_mock.return_value = self.github_mock
        self.project.github_hook_uuid = 98765

        http_response = git.set_project_repo(self.request, self.project_id)

        expected_content = self.set_up_expected_content(True, True, True, True)
        self.assertEquals(expected_content, http_response.content)

        get_github_mock.assert_called_once_with('test-user')
        self.github_mock.get_repo.assert_called_once_with('pebble/cloudpebble')
        get_object_mock.assert_called_once_with(git.Project, owner='test-user', pk=12345)

        self.assertIsNone(self.project.github_hook_uuid)
        self.project.save.assert_called_once_with()

@patch('ide.git.create_repo')
@patch('ide.api.git.get_object_or_404')
class CreateProjectRepoTest(TestCase):
    def setUp(self):
        self.project_id = 12345

        self.test_exception = Exception('test create_repo exception')

        self.repo = Mock()
        self.repo.full_name = 'test_full_repo_name'
        self.repo.html_url = 'www.test.com/test.html'

        self.request = Mock()
        self.request.user = "test_user"
        self.request.POST = {'repo': 'test_repo',
                             'description': 'a test description'}

        self.project = Mock()
        self.project.id = 222222

    def test_create_repo_error(self, get_object_mock, create_repo_mock):
        get_object_mock.return_value = self.project
        create_repo_mock.side_effect = self.test_exception

        http_response = git.create_project_repo(self.request, self.project_id)

        expected_content = '{"success": false, "error": "test create_repo exception"}'

        self.assertEquals(expected_content, http_response.content)
        create_repo_mock.assert_called_once_with('test_user', 'test_repo', 'a test description')
        get_object_mock.assert_called_once_with(git.Project, owner='test_user', pk=12345)

    def test_create_project_repo(self, get_object_mock, create_repo_mock):
        get_object_mock.return_value = self.project
        create_repo_mock.return_value = self.repo

        http_response = git.create_project_repo(self.request, self.project_id)

        expected_content = '{"repo": "www.test.com/test.html", "success": true}'

        self.assertEquals(expected_content, http_response.content)
        self.assertEquals(self.repo.full_name, self.project.github_repo)
        self.assertEquals('master', self.project.github_branch)
        self.assertIsNone(self.project.github_last_sync)
        self.assertIsNone(self.project.github_last_commit)

        self.project.save.called_once_with()
        create_repo_mock.assert_called_once_with('test_user', 'test_repo', 'a test description')
        get_object_mock.assert_called_once_with(git.Project, owner='test_user', pk=12345)


class RemoveHooksTest(TestCase):
    def setUp(self):
        self.mock_repo = MagicMock()
        self.mock_hook = MagicMock()
        self.mock_hook.name = "web"
        self.mock_hook.config = {"url": ["test_string"]}
        self.mock_repo.get_hooks.return_value = [self.mock_hook]

    def test_remove_hooks(self):
        git.remove_hooks(self.mock_repo, "test_string")

        self.mock_repo.get_hooks.assert_called_once_with()
        self.mock_hook.delete.assert_called_once_with()

    def test_remove_hook_not_web_not_deleted(self):
        self.mock_hook.name = "foo"

        git.remove_hooks(self.mock_repo, "test_string")

        self.mock_repo.get_hooks.assert_called_once_with()
        self.assertEqual(0, self.mock_hook.delete.call_count)
 
    def test_s_not_in_hook_not_deleted(self):
        git.remove_hooks(self.mock_repo, "foo")

        self.mock_repo.get_hooks.assert_called_once_with()
        self.assertEqual(0, self.mock_hook.delete.call_count)
