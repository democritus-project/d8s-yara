#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for `democritus_yara` module."""

import pytest


from democritus_yara import democritus_yara


@pytest.fixture
def response():
    return "foo bar"


def test_democritus_yara_initialization():
    assert 1 == 1
