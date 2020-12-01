
from mfasweep import mfasweep
import pytest
import io
import contextlib
from argparse import Namespace


args = Namespace(user='johndoe', domain='contoso.com')
sweep = mfasweep.MFASweep(args)

def test_mfasweep():
    assert sweep.__class__ == mfasweep.MFASweep

def test_mfasweep_recon():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sweep.Recon()
        assert "does not use ADFS" in out.getvalue()

def test_mfasweep_O365web():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sweep.O365WebPortalAuth(False)
        assert "Unsuccessful login to O365 Web portal" in out.getvalue()

def test_mfasweep_O365Mobile():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sweep.O365WebPortalAuth(True)
        assert "Unsuccessful login to O365 Web portal" in out.getvalue()

def test_mfasweep_graphAPI():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sweep.GraphAPIAuth()
        assert "Unsuccessful login to GraphAPI" in out.getvalue()

def test_mfasweep_MgmtAPI():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sweep.AzureManagementAPIAuth()
        assert "Unsuccessful login to Azure Management API" in out.getvalue()

def test_mfasweep_ActiveSync():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sweep.O365ActiveSyncAuth()
        assert "Unsuccessful login to ActiveSync" in out.getvalue()

def test_mfa_log_error():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sweep.log('error', 'hello world')
        assert "[!] hello world" in out.getvalue()

def test_mfa_log_warn():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sweep.log('warn', 'hello world')
        assert "[+] hello world" in out.getvalue()

def test_mfa_log_info():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sweep.log('info', 'hello world')
        assert "[-] hello world" in out.getvalue()

def test_mfa_print_header():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sweep.PrintHeader('hello world')
        assert "~~:" in out.getvalue() and 'hello world' in out.getvalue()