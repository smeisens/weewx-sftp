"""Tests for the JSON upload cache and legacy pickle handling."""

import json
import pickle

import pytest
from test_sftp import make_uploader

# --------------------------------------------------------------------------
# JSON upload cache
# --------------------------------------------------------------------------

def test_cache_is_json_with_destination(tmp_path):
    up = make_uploader(local_root=str(tmp_path))
    up.save_last_upload(12.5, {'b', 'a'})
    data = json.loads((tmp_path / '#SFTP.last').read_text(encoding='utf-8'))
    assert data == {
        'format': 1,
        'timestamp': 12.5,
        'files': ['a', 'b'],
        'target': ['host.example', 22, 'bob', '/remote/pub'],
    }


def test_cache_roundtrips_non_ascii_and_undecodable_names(tmp_path):
    up = make_uploader(local_root=str(tmp_path))
    files = {str(tmp_path / 'Wetter-Übersicht.html'), str(tmp_path / 'bad\udcff.html')}
    up.save_last_upload(1.0, files)
    assert up.get_last_upload() == (1.0, files)


def test_legacy_pickle_cache_is_never_unpickled(tmp_path, monkeypatch):
    cache = tmp_path / '#SFTP.last'
    with cache.open('wb') as stream:
        pickle.dump(123, stream)
        pickle.dump({'index.html'}, stream)

    def refuse(*args, **kwargs):
        raise AssertionError('legacy cache must not be unpickled')

    monkeypatch.setattr(pickle, 'load', refuse)
    monkeypatch.setattr(pickle, 'loads', refuse)
    monkeypatch.setattr(pickle, 'Unpickler', refuse)
    assert make_uploader(local_root=str(tmp_path)).get_last_upload() == (0, set())
    assert cache.exists()  # replaced only by the next successful upload


@pytest.mark.parametrize('content', [
    '[]',
    '{"format": 1}',
    '{"format": 2, "timestamp": 1, "files": [], "target": []}',
    '{"format": 1, "timestamp": "1", "files": [], "target": []}',
    '{"format": 1, "timestamp": true, "files": [], "target": []}',
    '{"format": 1, "timestamp": 1, "files": "abc", "target": []}',
    '{"format": 1, "timestamp": 1, "files": [1], "target": []}',
    '{"format": 1, "timestamp": 1, "files": [], "target": "x"}',
])
def test_malformed_json_cache_is_discarded(tmp_path, content):
    cache = tmp_path / '#SFTP.last'
    cache.write_text(content)
    assert make_uploader(local_root=str(tmp_path)).get_last_upload() == (0, set())
    assert not cache.exists()


def test_json_cache_for_other_destination_is_ignored(tmp_path):
    make_uploader(local_root=str(tmp_path), port=2222).save_last_upload(5, {'a'})
    assert make_uploader(local_root=str(tmp_path)).get_last_upload() == (0, set())
    assert make_uploader(local_root=str(tmp_path), port='2222').get_last_upload() == (5, {'a'})
