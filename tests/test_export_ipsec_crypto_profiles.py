"""Field-asserting tests for export_ipsec_crypto_profiles() — issue #92 backfill."""
from __future__ import annotations

from export.objects import export_ipsec_crypto_profiles
from export_fixtures import network_root


def _profiles(inner: str) -> str:
    return f"<ike><crypto-profiles><ipsec-crypto-profiles>{inner}</ipsec-crypto-profiles></crypto-profiles></ike>"


class TestExportIpsecCryptoProfiles:
    def test_none_root(self):
        assert export_ipsec_crypto_profiles(None) == []

    def test_missing_container(self):
        assert export_ipsec_crypto_profiles(network_root("<ike><crypto-profiles/></ike>")) == []

    def test_empty_container(self):
        assert export_ipsec_crypto_profiles(network_root(_profiles(""))) == []

    def test_full_profile(self):
        root = network_root(_profiles("""
        <entry name="ipsec-strong">
          <esp>
            <encryption><member>aes-256-gcm</member><member>aes-128-cbc</member></encryption>
            <authentication><member>sha256</member></authentication>
          </esp>
          <dh-group>group14</dh-group>
          <lifetime><seconds>3600</seconds></lifetime>
        </entry>
        """))
        assert export_ipsec_crypto_profiles(root) == [{
            "name": "ipsec-strong",
            "esp": {
                "encryption": ["aes-256-gcm", "aes-128-cbc"],
                "authentication": ["sha256"],
            },
            "dh_group": "group14",
            "lifetime": {"seconds": 3600},
        }]

    def test_optional_fields_omitted(self):
        root = network_root(_profiles("""
        <entry name="minimal"/>
        <entry name="empty-lifetime"><lifetime/></entry>
        <entry name="textless-lifetime"><lifetime><hours/></lifetime></entry>
        <entry name="esp-only"><esp><encryption><member>aes-128-cbc</member></encryption></esp></entry>
        """))
        out = export_ipsec_crypto_profiles(root)
        assert out[0] == {"name": "minimal"}
        assert out[1] == {"name": "empty-lifetime"}
        assert out[2] == {"name": "textless-lifetime"}
        assert out[3] == {
            "name": "esp-only",
            "esp": {"encryption": ["aes-128-cbc"], "authentication": []},
        }

    def test_document_order_preserved(self):
        root = network_root(_profiles('<entry name="z-ipsec"/><entry name="a-ipsec"/>'))
        assert [p["name"] for p in export_ipsec_crypto_profiles(root)] == ["z-ipsec", "a-ipsec"]
