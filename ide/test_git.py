"""
Tests in this file can be run with python manage.py test ide/
"""

from django.conf import settings
from django.test import TestCase
from mock import MagicMock, Mock, patch, PropertyMock
import git


@patch('ide.git.git_verify_tokens')
class GitAuthCheckTest(TestCase):
    def setUp(self):
        self.f = Mock()
        self.f.return_value = "test result"

        self.mock_user = MagicMock()

    def test_invalid_tokens(self, mock_verify_tokens):
        mock_verify_tokens.return_value = False
        g = git.git_auth_check(self.f)

        self.assertRaises(Exception, g, self.mock_user)

    def test_bad_credentials_expection(self, mock_verify_tokens):
        mock_verify_tokens.return_value = True
        self.f.side_effect = git.BadCredentialsException(None, None)
        g = git.git_auth_check(self.f)

        self.assertRaises(git.BadCredentialsException, g, self.mock_user)
        self.mock_user.github.delete.assert_called_once_with()

    def test_other_excpetion(self, mock_verify_tokens):
        mock_verify_tokens.return_value = True
        self.f.side_effect = Exception("Test exception")
        g = git.git_auth_check(self.f)

        self.assertRaises(Exception, g, self.mock_user)
        self.assertEqual(0, self.mock_user.github.delete.call_count)

    def test_successful_auth_check(self, mock_verify_tokens):
        mock_verify_tokens.return_value = True
        g = git.git_auth_check(self.f)

        self.assertEquals("test result", g(self.mock_user))
        self.assertEqual(0, self.mock_user.github.delete.call_count)


@patch('ide.git.urllib2.urlopen')
@patch('ide.git.json.loads')
@patch('ide.git.urllib2.Request')
class GitVerifyTokensTest(TestCase):
    def setUp(self):
        self.mock_user = MagicMock()
        self.mock_user.github = Mock()
        self.mock_user.github.token = "123456"

        self.mock_request = MagicMock()

        self.urlopen_read_result_mock = Mock()
        self.urlopen_result_mock = Mock()
        self.urlopen_result_mock.read.return_value = self.urlopen_read_result_mock

    def test_user_does_not_exist(self, request_mock, loads_mock, urlopen_mock):
        error_raising_property = PropertyMock(side_effect=git.UserGithub.DoesNotExist(None));
        type(self.mock_user).github = error_raising_property

        self.assertFalse(git.git_verify_tokens(self.mock_user))

        self.assertEqual(0, request_mock.call_count)
        self.assertEqual(0, loads_mock.call_count)
        self.assertEqual(0, urlopen_mock.call_count)

    def test_github_token_none(self, request_mock, loads_mock, urlopen_mock):
        self.mock_user.github.token = None

        self.assertFalse(git.git_verify_tokens(self.mock_user))

        self.assertEqual(0, request_mock.call_count)
        self.assertEqual(0, loads_mock.call_count)
        self.assertEqual(0, urlopen_mock.call_count)


    def test_github_token_no_such_token(self, request_mock, loads_mock, urlopen_mock):
        request_mock.return_value = self.mock_request
        loads_mock.side_effect = git.urllib2.HTTPError("Squirrels not found", 404, None, None, None)
        urlopen_mock.return_value = self.urlopen_result_mock
        self.mock_user.github.delete = Mock()

        self.assertFalse(git.git_verify_tokens(self.mock_user))

        request_mock.assert_called_once_with("https://api.github.com/applications/%s/tokens/%s" %
                                             (settings.GITHUB_CLIENT_ID, self.mock_user.github.token))
        loads_mock.assert_called_once_with(self.urlopen_read_result_mock)
        urlopen_mock.assert_called_once_with(self.mock_request)
        self.urlopen_result_mock.read.assert_called_once_with()
        self.mock_user.github.delete.assert_called_once_with()

    def test_other_http_error(self, request_mock, loads_mock, urlopen_mock):
        request_mock.return_value = self.mock_request
        loads_mock.side_effect = git.urllib2.HTTPError("Squirrels are black, not red", 406, None, None, None)
        urlopen_mock.return_value = self.urlopen_result_mock
        self.mock_user.github.delete = Mock()

        self.assertFalse(git.git_verify_tokens(self.mock_user))

        request_mock.assert_called_once_with("https://api.github.com/applications/%s/tokens/%s" %
                                             (settings.GITHUB_CLIENT_ID, self.mock_user.github.token))
        loads_mock.assert_called_once_with(self.urlopen_read_result_mock)
        urlopen_mock.assert_called_once_with(self.mock_request)
        self.urlopen_result_mock.read.assert_called_once_with()
        self.assertEqual(0, self.mock_user.github.delete.call_count)

    def test_github_token_verified(self, request_mock, loads_mock, urlopen_mock):
        request_mock.return_value = self.mock_request
        urlopen_mock.return_value = self.urlopen_result_mock

        self.assertTrue(git.git_verify_tokens(self.mock_user))

        request_mock.assert_called_once_with("https://api.github.com/applications/%s/tokens/%s" %
                                             (settings.GITHUB_CLIENT_ID, self.mock_user.github.token))
        loads_mock.assert_called_once_with(self.urlopen_read_result_mock)
        urlopen_mock.assert_called_once_with(self.mock_request)
        self.urlopen_result_mock.read.assert_called_once_with()


class GetGithubTest(TestCase):
    def setUp(self):
	self.mock_user = Mock()
	self.mock_user.github = Mock()
        self.mock_user.github.token = "12345"

    @patch('ide.git.Github')
    def test_get_github_basic(self, mock_github):
        test_result = git.get_github(self.mock_user)
        mock_github.assert_called_once_with(
            "12345",
            client_id=settings.GITHUB_CLIENT_ID,
            client_secret=settings.GITHUB_CLIENT_SECRET)


class GetGithubTest(TestCase):
    def setUp(self):
	self.mock_user = Mock()
	self.mock_user.github = Mock()
        self.mock_user.github.token = "12345"

    @patch('ide.git.Github')
    def test_get_github_basic(self, mock_github):
        test_result = git.get_github(self.mock_user)
        mock_github.assert_called_once_with(
            "12345",
            client_id=settings.GITHUB_CLIENT_ID,
            client_secret=settings.GITHUB_CLIENT_SECRET)


@patch('ide.git.get_github')
class CheckRepoAccessTest(TestCase):
    def setUp(self):
        self.mock_repo = MagicMock()

        self.mock_github = MagicMock(spec=git.Github)
        self.mock_github.get_repo.return_value = self.mock_repo

	self.mock_user = Mock()
	self.mock_user.github = Mock()
        self.mock_user.github.username = "FuzzyWuzzy"

        self.repo_name = "bear/bear_code"

    def test_repo_access(self, mock_get_github):
        mock_get_github.return_value = self.mock_github
        self.mock_repo.has_in_collaborators.return_value = True

        self.assertTrue(git.check_repo_access(self.mock_user, self.repo_name))

        mock_get_github.assert_called_once_with(self.mock_user)
        self.mock_github.get_repo.assert_called_once_with(self.repo_name)

        named_user = self.mock_repo.has_in_collaborators.call_args[0][0]
        self.assertEquals(self.mock_user.github.username, named_user._login)
        self.assertIsNone(named_user._requester)
        self.assertFalse(named_user._CompletableGithubObject__completed)

    def test_no_repo_access(self, mock_get_github):
        mock_get_github.return_value = self.mock_github
        self.mock_repo.has_in_collaborators.return_value = False

        self.assertFalse(git.check_repo_access(self.mock_user, self.repo_name))

        mock_get_github.assert_called_once_with(self.mock_user)
        self.mock_github.get_repo.assert_called_once_with(self.repo_name)

        named_user = self.mock_repo.has_in_collaborators.call_args[0][0]
        self.assertEquals(self.mock_user.github.username, named_user._login)
        self.assertIsNone(named_user._requester)
        self.assertFalse(named_user._CompletableGithubObject__completed)

    def test_get_repo_error(self, mock_get_github):
        mock_get_github.return_value = self.mock_github
        self.mock_github.get_repo.side_effect = git.UnknownObjectException(404, "Not Found")

        self.assertRaises(git.UnknownObjectException,
                          git.check_repo_access,
                          self.mock_user,
                          self.repo_name)

        mock_get_github.assert_called_once_with(self.mock_user)
        self.mock_github.get_repo.assert_called_once_with(self.repo_name)
        self.assertEqual(0, self.mock_repo.call_count)


class UrlToReposTest(TestCase):
    def test_basic_url_to_repo(self):
        """
        Tests that a simple repo url is correctly recognized.
        """
        username, reponame  = git.url_to_repo("https://github.com/pebble/cloudpebble")
        self.assertEqual("pebble", username)
        self.assertEqual("cloudpebble", reponame)

    def test_strange_url_to_repo(self):
        """
        Tests that a non-standard repo url is correctly recognized.
        """
        username, reponame  = git.url_to_repo("git://github.com:foo/bar.git")
        self.assertEqual("foo", username)
        self.assertEqual("bar", reponame)


    def test_bad_url_to_repo(self):
        """
        Tests that a entirely different url returns None.
        """
        self.assertEqual(None, git.url_to_repo("http://www.cuteoverload.com"))


@patch('ide.git.get_github')
@patch('ide.git.git_verify_tokens')
class CreateRepoTest(TestCase):
    def test_expected_call(self, mock_verify_tokens, mock_get_github):
        mock_user = MagicMock()
        mock_github = Mock()
        mock_github.get_user = Mock(return_value=mock_user)
        mock_get_github.return_value = mock_github

        self.assertTrue(git.create_repo("user", "repo", "description"))

        mock_verify_tokens.assert_called_once_with("user")
        mock_get_github.assert_called_once_with("user")
        mock_user.create_repo.assert_called_once_with("repo", description="description", auto_init=True)
