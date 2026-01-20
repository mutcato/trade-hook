from django.contrib.auth import get_user_model
from django.urls import reverse
from model_bakery import baker
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class RegisterViewTests(APITestCase):
    """Tests for user registration endpoint."""

    @classmethod
    def setUpTestData(cls):
        cls.url = reverse('authentication:register')
        cls.existing_user = baker.make(User, email='existing@example.com')

    def setUp(self):
        self.valid_data = {
            'email': 'newuser@example.com',
            'password': 'SecurePass123!',
            'password_confirm': 'SecurePass123!',
            'first_name': 'John',
            'last_name': 'Doe',
        }

    def test_register_success(self):
        """Test successful user registration."""
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], self.valid_data['email'])
        self.assertTrue(User.objects.filter(email=self.valid_data['email']).exists())

    def test_register_passwords_do_not_match(self):
        """Test registration fails when passwords don't match."""
        self.valid_data['password_confirm'] = 'DifferentPass123!'
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password_confirm', response.data)

    def test_register_weak_password(self):
        """Test registration fails with weak password."""
        self.valid_data['password'] = '123'
        self.valid_data['password_confirm'] = '123'
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_register_duplicate_email(self):
        """Test registration fails with existing email."""
        self.valid_data['email'] = 'existing@example.com'
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_register_invalid_email(self):
        """Test registration fails with invalid email format."""
        self.valid_data['email'] = 'invalid-email'
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_register_missing_required_fields(self):
        """Test registration fails when required fields are missing."""
        response = self.client.post(self.url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        self.assertIn('password', response.data)


class LoginViewTests(APITestCase):
    """Tests for user login endpoint."""

    @classmethod
    def setUpTestData(cls):
        cls.url = reverse('authentication:login')
        cls.password = 'TestPass123!'
        cls.user = User.objects.create_user(
            email='testuser@example.com',
            password=cls.password,
            first_name='Test',
            last_name='User',
        )
        cls.inactive_user = User.objects.create_user(
            email='inactive@example.com',
            password=cls.password,
            is_active=False,
        )

    def setUp(self):
        self.valid_credentials = {
            'email': 'testuser@example.com',
            'password': self.password,
        }

    def test_login_success(self):
        """Test successful login returns tokens and user data."""
        response = self.client.post(self.url, self.valid_credentials)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], self.valid_credentials['email'])

    def test_login_wrong_password(self):
        """Test login fails with wrong password."""
        self.valid_credentials['password'] = 'WrongPassword123!'
        response = self.client.post(self.url, self.valid_credentials)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_nonexistent_user(self):
        """Test login fails with non-existent email."""
        self.valid_credentials['email'] = 'nonexistent@example.com'
        response = self.client.post(self.url, self.valid_credentials)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_inactive_user(self):
        """Test login fails for inactive user."""
        response = self.client.post(self.url, {
            'email': 'inactive@example.com',
            'password': self.password,
        })

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_missing_credentials(self):
        """Test login fails with missing credentials."""
        response = self.client.post(self.url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class LogoutViewTests(APITestCase):
    """Tests for user logout endpoint."""

    @classmethod
    def setUpTestData(cls):
        cls.url = reverse('authentication:logout')
        cls.user = baker.make(User)

    def setUp(self):
        self.refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')

    def test_logout_success(self):
        """Test successful logout blacklists refresh token."""
        response = self.client.post(self.url, {'refresh': str(self.refresh)})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], 'Successfully logged out.')

    def test_logout_invalid_token(self):
        """Test logout with invalid token returns error."""
        response = self.client.post(self.url, {'refresh': 'invalid-token'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_unauthenticated(self):
        """Test logout requires authentication."""
        self.client.credentials()
        response = self.client.post(self.url, {'refresh': str(self.refresh)})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TokenRefreshViewTests(APITestCase):
    """Tests for token refresh endpoint."""

    @classmethod
    def setUpTestData(cls):
        cls.url = reverse('authentication:token_refresh')
        cls.user = baker.make(User)

    def setUp(self):
        self.refresh = RefreshToken.for_user(self.user)

    def test_refresh_token_success(self):
        """Test successful token refresh returns new access token."""
        response = self.client.post(self.url, {'refresh': str(self.refresh)})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_refresh_token_invalid(self):
        """Test refresh fails with invalid token."""
        response = self.client.post(self.url, {'refresh': 'invalid-token'})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_token_missing(self):
        """Test refresh fails when token is missing."""
        response = self.client.post(self.url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ProfileViewTests(APITestCase):
    """Tests for user profile endpoint."""

    @classmethod
    def setUpTestData(cls):
        cls.url = reverse('authentication:profile')
        cls.user = baker.make(
            User,
            email='profile@example.com',
            first_name='Original',
            last_name='Name',
        )

    def setUp(self):
        self.refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')

    def test_get_profile_success(self):
        """Test retrieving user profile."""
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)
        self.assertEqual(response.data['first_name'], self.user.first_name)
        self.assertEqual(response.data['last_name'], self.user.last_name)

    def test_get_profile_unauthenticated(self):
        """Test profile access requires authentication."""
        self.client.credentials()
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_profile_put(self):
        """Test full profile update with PUT."""
        data = {'first_name': 'Updated', 'last_name': 'User'}
        response = self.client.put(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Updated')
        self.assertEqual(response.data['last_name'], 'User')

    def test_update_profile_patch(self):
        """Test partial profile update with PATCH."""
        data = {'first_name': 'Patched'}
        response = self.client.patch(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Patched')
        self.assertEqual(response.data['last_name'], self.user.last_name)

    def test_profile_email_is_readonly(self):
        """Test that email cannot be updated via profile."""
        original_email = self.user.email
        data = {'email': 'newemail@example.com', 'first_name': 'Test'}
        response = self.client.patch(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], original_email)


class ChangePasswordViewTests(APITestCase):
    """Tests for password change endpoint."""

    @classmethod
    def setUpTestData(cls):
        cls.url = reverse('authentication:change_password')
        cls.old_password = 'OldPass123!'
        cls.new_password = 'NewPass456!'
        cls.user = User.objects.create_user(
            email='changepass@example.com',
            password=cls.old_password,
        )

    def setUp(self):
        self.refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.refresh.access_token}')
        self.valid_data = {
            'old_password': self.old_password,
            'new_password': self.new_password,
            'new_password_confirm': self.new_password,
        }

    def test_change_password_success(self):
        """Test successful password change."""
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))

    def test_change_password_wrong_old_password(self):
        """Test password change fails with wrong old password."""
        self.valid_data['old_password'] = 'WrongOldPass123!'
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('old_password', response.data)

    def test_change_password_mismatch(self):
        """Test password change fails when new passwords don't match."""
        self.valid_data['new_password_confirm'] = 'DifferentPass789!'
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('new_password_confirm', response.data)

    def test_change_password_weak(self):
        """Test password change fails with weak new password."""
        self.valid_data['new_password'] = '123'
        self.valid_data['new_password_confirm'] = '123'
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('new_password', response.data)

    def test_change_password_unauthenticated(self):
        """Test password change requires authentication."""
        self.client.credentials()
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
