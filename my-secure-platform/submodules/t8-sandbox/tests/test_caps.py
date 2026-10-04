"""Тесты capability-логики (F-E-09) и парсинга /proc/self/status."""
from __future__ import annotations

import pytest

from ztseccomp.apply import (
    SeccompError,
    CapsStatus,
    read_caps_status,
    verify_capability_drop,
)

STATUS_CLEAN = """Name:	python3.11
Umask:	0022
State:	S (sleeping)
Tgid:	4242
Pid:	4242
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000000000000000
CapAmb:	0000000000000000
NoNewPrivs:	1
Seccomp:	2
"""

STATUS_DIRTY = """Name:	python3.11
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
"""


def test_parse_clean_status():
    st = read_caps_status(STATUS_CLEAN)
    assert st.cap_eff == 0
    assert st.cap_prm == 0
    assert st.cap_inh == 0
    assert st.cap_bnd == 0
    assert st.no_new_privs == 1
    assert st.seccomp == 2
    assert st.all_cleared


def test_parse_dirty_status():
    st = read_caps_status(STATUS_DIRTY)
    assert st.cap_eff == 0xA80425FB
    assert st.no_new_privs == 0
    assert not st.all_cleared


def test_verify_raises_on_dirty(monkeypatch):
    monkeypatch.setattr("ztseccomp.apply.STATUS_PATH",
                        _FakePath(STATUS_DIRTY))
    with pytest.raises(SeccompError, match="capability drop verification failed"):
        verify_capability_drop()


def test_verify_passes_on_clean(monkeypatch):
    monkeypatch.setattr("ztseccomp.apply.STATUS_PATH",
                        _FakePath(STATUS_CLEAN))
    st = verify_capability_drop()
    assert st.all_cleared


def test_no_new_privs_alone_not_enough():
    st = CapsStatus(cap_inh=0, cap_prm=0, cap_eff=0x1, cap_bnd=0, cap_amb=0,
                    no_new_privs=1, seccomp=0)
    assert not st.all_cleared


def test_all_cleared_requires_nnp():
    st = CapsStatus(cap_inh=0, cap_prm=0, cap_eff=0, cap_bnd=0x1ff, cap_amb=0,
                    no_new_privs=0, seccomp=0)
    assert not st.all_cleared


class _FakePath:
    """Замена STATUS_PATH для тестов без /proc."""

    def __init__(self, text: str):
        self._text = text

    def read_text(self, *args, **kwargs) -> str:
        return self._text
