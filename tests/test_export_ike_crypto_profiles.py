"""Field-asserting tests for export_ike_crypto_profiles() — issue #92 backfill."""
from __future__ import annotations

from export.objects import export_ike_crypto_profiles
from export_fixtures import network_root


def _profiles(inner: str) -> str:
    return f"<ike><crypto-profiles><ike-crypto-profiles>{inner}</ike-crypto-profiles></crypto-profiles></ike>"


class TestExportIkeCryptoProfiles:
    def test_none_root(self):
        assert export_ike_crypto_profiles(None) == []

    def test_missing_container(self):
        assert export_ike_crypto_profiles(network_root("<ike><gateway/></ike>")) == []

    def test_empty_container(self):
        assert export_ike_crypto_profiles(network_root(_profiles(""))) == []

    def test_full_profile_with_lifetime(self):
        root = network_root(_profiles("""
        <entry name="ike-strong">
          <hash><member>sha256</member><member>sha1</member></hash>
          <encryption><member>aes-256-cbc</member><member>aes-128-cbc</member></encryption>
          <dh-group><member>group14</member><member>group2</member></dh-group>
          <lifetime><hours>8</hours></lifetime>
        </entry>
        """))
        assert export_ike_crypto_profiles(root) == [{
            "name": "ike-strong",
            "hash": ["sha256", "sha1"],
            "encryption": ["aes-256-cbc", "aes-128-cbc"],
            "dh_group": ["group14", "group2"],
            "lifetime": {"hours": 8},
        }]

    def test_lifetime_variants_omitted_when_unusable(self):
        root = network_root(_profiles("""
        <entry name="no-lifetime">
          <hash><member>sha1</member></hash>
          <encryption><member>aes-128-cbc</member></encryption>
          <dh-group><member>group2</member></dh-group>
        </entry>
        <entry name="empty-lifetime"><lifetime/></entry>
        <entry name="textless-lifetime"><lifetime><hours/></lifetime></entry>
        """))
        out = export_ike_crypto_profiles(root)
        assert out[0] == {
            "name": "no-lifetime",
            "hash": ["sha1"],
            "encryption": ["aes-128-cbc"],
            "dh_group": ["group2"],
        }
        assert out[1] == {"name": "empty-lifetime", "hash": [], "encryption": [], "dh_group": []}
        assert out[2] == {"name": "textless-lifetime", "hash": [], "encryption": [], "dh_group": []}

    def test_document_order_preserved(self):
        root = network_root(_profiles('<entry name="z-ike"/><entry name="a-ike"/>'))
        assert [p["name"] for p in export_ike_crypto_profiles(root)] == ["z-ike", "a-ike"]
