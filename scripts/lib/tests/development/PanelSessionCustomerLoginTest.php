<?php
namespace PMSS\Tests;

require_once dirname(__DIR__, 4).'/etc/skel/www/panelSession.php';

class PanelSessionCustomerLoginTest extends TestCase
{
    private function fixturePaths(string $username = 'alice'): array
    {
        $home = $this->pmssEnsureDir($this->pmssMakeTempDir('pmss-panel-session-home-').'/'.$username);
        $this->pmssEnsureDir($home.'/.lighttpd');
        return \pmssPanelSessionPaths($home);
    }

    private function writeHtpasswd(array $paths, string $username = 'alice', string $password = 'secret'): string
    {
        $hash = crypt($password, '$6$rounds=5000$pmsspaneltest$');
        $this->assertTrue(is_string($hash) && $hash !== '');
        $this->pmssWriteFile($paths['htpasswd'], $username.':'.$hash."\n");
        return $hash;
    }

    public function testHtpasswdCryptCompareAcceptsExpectedPasswordOnly(): void
    {
        $paths = $this->fixturePaths();
        $hash = $this->writeHtpasswd($paths);

        $this->assertTrue(\pmssPanelSessionPasswordMatchesHash('secret', $hash));
        $this->assertFalse(\pmssPanelSessionPasswordMatchesHash('wrong', $hash));
        $this->assertTrue(\pmssPanelSessionPasswordValid($paths, 'alice', 'secret'));
        $this->assertFalse(\pmssPanelSessionPasswordValid($paths, 'bob', 'secret'));
    }

    public function testLoginRequiresCsrfTokenOnPost(): void
    {
        $paths = $this->fixturePaths();
        $this->writeHtpasswd($paths);

        $result = \pmssPanelSessionLoginAttempt(['password' => 'secret'], $paths, 'alice', 1700000000);

        $this->assertFalse((bool) $result['ok']);
        $this->assertSame(403, $result['status']);
        $this->assertSame([], $result['headers']);
        $this->assertSame(1, \pmssPanelSessionRead($paths)['failed']);
    }

    public function testLoginRejectsWrongPasswordAndIncrementsFailedCounter(): void
    {
        $paths = $this->fixturePaths();
        $this->writeHtpasswd($paths);
        $csrf = \pmssPanelSessionCsrfEnsure($paths, 1700000000);

        $result = \pmssPanelSessionLoginAttempt([
            'csrf' => $csrf,
            'password' => 'wrong',
        ], $paths, 'alice', 1700000001);

        $this->assertFalse((bool) $result['ok']);
        $this->assertSame(401, $result['status']);
        $this->assertSame([], $result['headers']);
        $this->assertSame(1, \pmssPanelSessionRead($paths)['failed']);
    }

    public function testSuccessfulLoginRegeneratesSessionIdAndWritesMode600SessionFile(): void
    {
        $paths = $this->fixturePaths();
        $this->writeHtpasswd($paths);
        $oldSessionId = str_repeat('a', 64);
        $csrf = str_repeat('b', 64);
        $this->assertTrue(\pmssPanelSessionWrite($paths, [
            'id' => $oldSessionId,
            'csrf' => $csrf,
            'created' => 1699999000,
            'seen' => 1699999000,
            'failed' => 3,
        ]));

        $result = \pmssPanelSessionLoginAttempt([
            'csrf' => $csrf,
            'password' => 'secret',
            'return' => '/user-alice/stats.php',
        ], $paths, 'alice', 1700000000);
        $session = \pmssPanelSessionRead($paths);

        $this->assertTrue((bool) $result['ok']);
        $this->assertSame(302, $result['status']);
        $this->assertSame($oldSessionId, $result['oldSessionId']);
        $this->assertMatches('/^[0-9a-f]{64}$/D', $result['sessionId']);
        $this->assertTrue($result['sessionId'] !== $oldSessionId, 'login must regenerate the session id');
        $this->assertSame($result['sessionId'], $session['id']);
        $this->assertSame(0, $session['failed']);
        $this->assertSame('/user-alice/stats.php', $result['headers']['Location']);
        $this->assertSame(0600, fileperms($paths['session']) & 0777);
    }

    public function testSessionCookieHeadersCarryRequiredBrowserFlagsWithoutDomain(): void
    {
        $header = \pmssPanelSessionCookieHeader('alice', str_repeat('c', 64), 1700000000);
        $delete = \pmssPanelSessionCookieDeleteHeader('alice');

        foreach ([$header, $delete] as $cookieHeader) {
            $this->assertStringContainsAllStrings([
                'pmss_panel_session=',
                'Path=/user-alice/',
                'Secure',
                'HttpOnly',
                'SameSite=Lax',
            ], $cookieHeader);
            $this->assertStringNotContainsString('Domain=', $cookieHeader);
        }
        $this->assertStringContainsString('Max-Age=28800', $header);
        $this->assertStringContainsString('Max-Age=0', $delete);
    }

    public function testReturnUrlIsScopedToTheSameUserPanel(): void
    {
        $this->assertSame('/user-alice/stats.php', \pmssPanelSessionReturnUrl('alice', '/user-alice/stats.php'));
        $this->assertSame('/user-alice/', \pmssPanelSessionReturnUrl('alice', '/user-bob/stats.php'));
        $this->assertSame('/user-alice/', \pmssPanelSessionReturnUrl('alice', 'https://example.test/user-alice/'));
        $this->assertSame('/user-alice/', \pmssPanelSessionReturnUrl('alice', "//example.test/user-alice/"));
    }

    /** A logged-in session as the login page leaves it. */
    private function writeLiveSession(array $paths, int $now): array
    {
        $session = ['id' => str_repeat('d', 64), 'csrf' => str_repeat('e', 64), 'created' => $now - 60, 'seen' => $now - 30, 'failed' => 0];
        $this->assertTrue(\pmssPanelSessionWrite($paths, $session));
        return $session;
    }

    public function testLogoutWithoutTheSessionCookieChangesNothing(): void
    {
        $paths = $this->fixturePaths();
        $now = 1700000000;
        $session = $this->writeLiveSession($paths, $now);
        $before = file_get_contents($paths['session']);

        // The public CSRF token alone (the login page hands it to anyone) is not proof of the session.
        foreach ([
            ['GET', [], []],
            ['POST', [], ['csrf' => $session['csrf']]],
            ['POST', ['pmss_panel_session' => str_repeat('f', 64)], ['csrf' => $session['csrf']]],
            ['POST', ['pmss_panel_session' => ['x']], ['csrf' => $session['csrf']]],
        ] as [$method, $cookies, $request]) {
            $result = \pmssPanelSessionLogoutAttempt($method, $cookies, $request, $paths, 'alice', $now);
            $this->assertFalse((bool) $result['ok'], $method);
            $this->assertSame(302, $result['status'], $method);
            $this->assertSame(['Location' => '/user-alice/panelSessionLogin.php'], $result['headers'], $method);
            $this->assertFalse((bool) $result['form'], $method);
            $this->assertSame($before, file_get_contents($paths['session']), $method);
        }
    }

    public function testLogoutGetWithTheSessionCookieOnlyOffersTheForm(): void
    {
        $paths = $this->fixturePaths();
        $now = 1700000000;
        $session = $this->writeLiveSession($paths, $now);
        $before = file_get_contents($paths['session']);

        // A cross-site top-level GET carries a SameSite=Lax cookie, so GET must never log out.
        $result = \pmssPanelSessionLogoutAttempt('GET', ['pmss_panel_session' => $session['id']], ['csrf' => $session['csrf']], $paths, 'alice', $now);

        $this->assertFalse((bool) $result['ok']);
        $this->assertSame(200, $result['status']);
        $this->assertSame([], $result['headers']);
        $this->assertTrue((bool) $result['form']);
        $this->assertSame($before, file_get_contents($paths['session']));

        $form = \pmssPanelSessionRenderLogoutForm('alice', $session['csrf']);
        $this->assertStringContainsAllStrings([
            '<form method="post" action="/user-alice/panelSessionLogout.php">',
            '<input type="hidden" name="csrf" value="'.$session['csrf'].'">',
            '<button type="submit">Sign out</button>',
        ], $form);
    }

    public function testLogoutPostNeedsTheSessionCsrfToken(): void
    {
        $paths = $this->fixturePaths();
        $now = 1700000000;
        $session = $this->writeLiveSession($paths, $now);
        $before = file_get_contents($paths['session']);

        $result = \pmssPanelSessionLogoutAttempt('POST', ['pmss_panel_session' => $session['id']], ['csrf' => str_repeat('0', 64)], $paths, 'alice', $now);

        $this->assertFalse((bool) $result['ok']);
        $this->assertSame(403, $result['status']);
        $this->assertSame([], $result['headers']);
        $this->assertSame($before, file_get_contents($paths['session']));
    }

    public function testLogoutRefusesAnExpiredSession(): void
    {
        $paths = $this->fixturePaths();
        $now = 1700000000;
        $session = $this->writeLiveSession($paths, $now);
        $request = ['csrf' => $session['csrf']];
        $cookies = ['pmss_panel_session' => $session['id']];

        $idle = \pmssPanelSessionLogoutAttempt('POST', $cookies, $request, $paths, 'alice', $session['seen'] + PMSS_PANEL_SESSION_IDLE_TIMEOUT + 1);
        $this->assertFalse((bool) $idle['ok']);
        $this->assertSame(302, $idle['status']);
        $this->assertTrue(is_file($paths['session']));

        $this->assertTrue(\pmssPanelSessionCookieValid($session, $session['id'], $now));
        $this->assertFalse(\pmssPanelSessionCookieValid($session, $session['id'], $session['created'] + PMSS_PANEL_SESSION_ABSOLUTE_LIFETIME + 1));
        $this->assertFalse(\pmssPanelSessionCookieValid($session, str_repeat('f', 64), $now));
        $this->assertFalse(\pmssPanelSessionCookieValid(['id' => ''] + $session, '', $now));
    }

    public function testLogoutPostWithCookieAndCsrfEndsTheSession(): void
    {
        $paths = $this->fixturePaths();
        $now = 1700000000;
        $session = $this->writeLiveSession($paths, $now);

        $result = \pmssPanelSessionLogoutAttempt('POST', ['pmss_panel_session' => $session['id']], ['csrf' => $session['csrf']], $paths, 'alice', $now);

        $this->assertTrue((bool) $result['ok']);
        $this->assertSame(302, $result['status']);
        $this->assertSame('/user-alice/panelSessionLogin.php', $result['headers']['Location']);
        $this->assertStringContainsString('Max-Age=0', $result['headers']['Set-Cookie']);
        $this->assertFalse(file_exists($paths['session']));
    }

    public function testLogoutStopsAgentUisOnlyAfterASuccessfulAttempt(): void
    {
        $source = $this->pmssReadRepoFile('etc/skel/www/panelSessionPage.php');
        $this->assertSame(1, substr_count($source, 'pmssPanelSessionLogoutStopAgents($paths);'));
        $this->assertOrderedStrings([
            '$result = pmssPanelSessionLogoutAttempt(',
            "if (!empty(\$result['ok'])) {",
            'pmssPanelSessionLogoutStopAgents($paths);',
        ], $source);
    }
}
