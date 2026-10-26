"""Observe a real console UID round trip; never initiate a user transition."""
import ctypes
import json
import time


def console_uid():
    system = ctypes.CDLL('/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration')
    core = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    system.SCDynamicStoreCopyConsoleUser.argtypes = [ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    system.SCDynamicStoreCopyConsoleUser.restype = ctypes.c_void_p
    core.CFRelease.argtypes = [ctypes.c_void_p]
    core.CFRelease.restype = None
    uid, gid = ctypes.c_uint32(0xffffffff), ctypes.c_uint32(0xffffffff)
    name = system.SCDynamicStoreCopyConsoleUser(None, ctypes.byref(uid), ctypes.byref(gid))
    if not name:
        raise ValueError('console user unavailable')
    core.CFRelease(name)
    return uid.value


def wait_user_switch(actor, check_away, read_uid=console_uid, clock=time.time,
                     pause=time.sleep, observe=None):
    started = previous = clock()
    if read_uid() != actor:
        raise ValueError('administrator must initially own the graphical console')
    away_uid = None
    away_since = None
    checked = False
    last_uid = actor
    while True:
        now = clock()
        if now < previous:
            raise ValueError('wall clock moved backwards during user switch')
        previous = now
        if now - started > 90:
            raise ValueError('user switch and return must complete within 90 seconds')
        uid = read_uid()
        if uid != last_uid:
            if observe:
                observe({'uid': uid, 'wall': now, 'started': started})
            last_uid = uid
        if uid == actor:
            if away_uid is not None:
                if not checked:
                    raise ValueError('returned before six seconds and away-state checks')
                return away_uid
        elif uid not in (0, 0xffffffff):
            if away_uid is None:
                away_uid, away_since = uid, now
            elif uid != away_uid:
                raise ValueError('unexpected third console user')
            if not checked and now - away_since >= 6:
                check_away()
                checked = True
        elif away_uid is not None and not checked:
            # Login-window time does not count as logged into another user.
            away_since = now
        pause(.2)


def operator_user_switch(actor, check_away):
    from acceptance_se import kernel_sleep_times
    before = kernel_sleep_times()
    if console_uid() != actor:
        raise ValueError('administrator must initially own the graphical console')
    print('READY FOR MANUAL USER SWITCH: switch to another graphical account, '
          'leave its desktop active for at least 10 seconds, then switch back within '
          '90 seconds. Do not log out or sleep. Detection is automatic; no Enter.', flush=True)
    other = wait_user_switch(actor, check_away,
        observe=lambda evidence: print('CONSOLE_SWITCH_EVIDENCE ' + json.dumps(evidence), flush=True))
    if kernel_sleep_times() != before:
        raise ValueError('sleep occurred during user-switch test; evidence is confounded')
    print(f'PASS observed graphical console UID {actor} -> {other} -> {actor}; '
          'away-state checks ran; no kernel sleep transition', flush=True)


def wait_logout(actor, old_session, check_away, read_session, read_uid=console_uid,
                clock=time.time, pause=time.sleep, observe=None):
    started = previous = clock()
    if read_uid() != actor:
        raise ValueError('administrator must initially own the graphical console')
    since = None
    checked = False
    last_uid = actor
    while True:
        now = clock()
        if now < previous:
            raise ValueError('wall clock moved backwards during logout')
        previous = now
        if since is None:
            # Saving work before logging out is not part of the relogin window,
            # but the approval and SE session are bounded at 900 seconds, so the
            # pre-logout wait stays well inside that budget.
            if now - started > 300:
                raise ValueError('logout did not start within 300 seconds')
        elif now - since > 90:
            raise ValueError('relogin from the login window must complete within 90 seconds')
        uid = read_uid()
        if uid != last_uid:
            if observe:
                observe({'uid': uid, 'wall': now, 'started': started})
            last_uid = uid
        if uid == 0:
            if since is None:
                since = now
            if not checked and now - since >= 6:
                check_away()
                checked = True
        elif uid == actor:
            if since is not None:
                if not checked:
                    raise ValueError('login window must remain active for at least six seconds')
                new_session = read_session()
                finished = clock()
                if finished < now or finished - since > 90:
                    raise ValueError('relogin from the login window exceeded acceptance interval')
                if new_session in (0, 0xffffffff, old_session):
                    raise ValueError('graphical audit session did not change; logout not proven')
                return new_session
        else:
            raise ValueError('unexpected console UID during logout acceptance')
        pause(.2)


def operator_logout(actor, old_session, check_away, read_session):
    from acceptance_se import kernel_sleep_times
    before = kernel_sleep_times()
    print('READY FOR MANUAL LOGOUT: save your work before starting this test; you have '
          'up to 5 minutes to log out from now. Use Apple menu Log Out; stay at the login '
          'window for 10 seconds, then log back into the SAME account within 90 seconds of '
          'the login window appearing. Do not switch users, '
          'sleep or reboot. The system test runner continues without this terminal. '
          'After logging back in, open Terminal and run: '
          'sudo sh /Library/ANPIOKeyLogoutChecks-post-relogin.sh '
          '(the runner waits up to 10 minutes for its result).', flush=True)
    new_session = wait_logout(actor, old_session, check_away, read_session,
        observe=lambda evidence: print('LOGOUT_EVIDENCE ' + json.dumps(evidence), flush=True))
    if kernel_sleep_times() != before:
        raise ValueError('sleep occurred during logout acceptance')
    print(f'PASS logout/relogin graphical audit session {old_session} -> {new_session}; '
          'login-window checks ran; no kernel sleep transition', flush=True)
