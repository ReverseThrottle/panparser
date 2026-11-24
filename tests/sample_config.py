"""Shared populated sample PAN-OS config for the viewer test harness (#80).

One realistic config exercising every TUI section (36) plus the renderer-only
CLI sections (dhcp, monitor profiles, QoS interface profiles, virtual wires).
Stored as a Python string, not a .xml file: the repo gitignores *.xml so
customer configs can never be committed by accident (same convention as the
inline XML in the existing test suite).

Root placement mirrors real PAN-OS exports:
- objects (address/service/application/tag/profile/...) under vsys1 + shared
- network (interfaces, VRs, IKE/IPsec, QoS, VLANs) under devices/entry/network
- zones under vsys1 (per closed issue #9 — NOT under network)
- auth/server profiles (#122): authentication-profile + server-profile/{ldap,
  radius} in both scopes; syslog/snmptrap/email/http under log-settings/
  (canonical per pan-os-python — NOT server-profile/). Fake encrypted
  secrets (FAKE-TEST-*) are planted for export leak assertions.

Names are unique and grep-friendly; tests assert them as exact substrings.
Do not rename entries without updating tests/test_data_getters.py,
tests/test_renderers.py and tests/test_tui_smoke.py.
"""

SAMPLE_CONFIG_XML = r"""<?xml version="1.0"?>
<!--
Shared sample PAN-OS config for viewer/TUI tests (issue #80).

Populated for every TUI section (tui.SECTIONS, 36 tabs) plus the four
renderer-only CLI sections (dhcp, monitor profiles, QoS interface profiles,
virtual wires). Realistic root placement: objects under vsys/shared, network
constructs under devices/entry/network, zones under vsys (see issue #9).

Names are chosen to be unique and grep-friendly so render assertions can
assert on exact substrings. Do not rename entries without updating
tests/viewer_harness.py expectations.
-->
<config>
  <shared>
    <address>
      <entry name="shared-dns">
        <ip-netmask>8.8.8.8/32</ip-netmask>
        <description>shared resolver</description>
      </entry>
    </address>
    <address-group>
      <entry name="grp-shared">
        <static><member>shared-dns</member></static>
      </entry>
    </address-group>
    <service>
      <entry name="svc-shared-ntp">
        <protocol><udp><port>123</port></udp></protocol>
      </entry>
    </service>
    <service-group>
      <entry name="svc-grp-shared">
        <members><member>svc-shared-ntp</member></members>
      </entry>
    </service-group>
    <tag>
      <entry name="tag-global">
        <color>color5</color>
        <comments>shared scope tag</comments>
      </entry>
    </tag>
    <application>
      <entry name="app-shared">
        <category>networking</category>
        <subcategory>routing</subcategory>
        <technology>network-protocol</technology>
        <risk>2</risk>
      </entry>
    </application>
    <application-group>
      <entry name="app-grp-shared">
        <members><member>app-shared</member></members>
      </entry>
    </application-group>
    <application-filter>
      <entry name="app-filter-shared">
        <category><member>networking</member></category>
      </entry>
    </application-filter>
    <profiles>
      <virus>
        <entry name="av-shared">
          <description>shared antivirus</description>
        </entry>
      </virus>
      <decryption>
        <entry name="decrypt-shared">
          <ssl-inbound-proxy>
            <block-unsupported-version>yes</block-unsupported-version>
          </ssl-inbound-proxy>
          <description>shared decryption</description>
        </entry>
      </decryption>
      <dns-security>
        <entry name="dns-shared">
          <botnet-domains>
            <lists>
              <entry name="shared-blocklist">
                <action><block/></action>
              </entry>
            </lists>
          </botnet-domains>
        </entry>
      </dns-security>
    </profiles>
    <certificate>
      <entry name="vpn-cert">
        <common-name>vpn.example.com</common-name>
        <issuer>Example CA</issuer>
        <not-valid-before>Jan  1 00:00:00 2026 GMT</not-valid-before>
        <not-valid-after>Jan  1 00:00:00 2028 GMT</not-valid-after>
        <ca>no</ca>
        <algorithm>RSA</algorithm>
      </entry>
      <entry name="ca-cert">
        <common-name>Example CA</common-name>
        <issuer>Example CA</issuer>
        <ca>yes</ca>
        <algorithm>ECDSA</algorithm>
      </entry>
    </certificate>
    <authentication-profile>
      <entry name="auth-local">
        <method><local-database/></method>
        <multi-factor-auth><mfa-enable>yes</mfa-enable></multi-factor-auth>
        <allow-list><member>all</member></allow-list>
        <user-domain>example.local</user-domain>
      </entry>
      <entry name="auth-nomethod"/>
    </authentication-profile>
    <ssl-tls-service-profile>
      <entry name="ssl-default">
        <certificate>vpn-cert</certificate>
        <protocol-settings>
          <min-version>tls1-0</min-version>
          <max-version>tls1-2</max-version>
        </protocol-settings>
      </entry>
    </ssl-tls-service-profile>
    <server-profile>
      <ldap>
        <entry name="ldap-main">
          <base>dc=example,dc=local</base>
          <ldap-type>active-directory</ldap-type>
          <bind-dn>cn=svc-ldap,dc=example,dc=local</bind-dn>
          <bind-password>FAKE-TEST-SECRET-DO-NOT-USE</bind-password>
          <server>
            <entry name="dc1"><address>10.0.0.10</address></entry>
            <entry name="dc2"><address>10.0.0.11</address></entry>
          </server>
        </entry>
        <entry name="ldap-nobase">
          <ldap-type>sun</ldap-type>
        </entry>
      </ldap>
      <radius>
        <entry name="radius-main">
          <protocol><CHAP/></protocol>
          <server>
            <entry name="r1"><ip-address>10.0.0.20</ip-address><secret>FAKE-TEST-SECRET-DO-NOT-USE</secret></entry>
          </server>
        </entry>
      </radius>
    </server-profile>
    <log-settings>
      <syslog>
        <entry name="syslog-main">
          <server>
            <entry name="siem"><server>10.0.0.30</server></entry>
          </server>
        </entry>
      </syslog>
      <snmptrap>
        <entry name="snmp-main">
          <version>
            <v2c>
              <server>
                <entry name="nms"><manager>10.0.0.40</manager><community>FAKE-TEST-COMMUNITY-DO-NOT-USE</community></entry>
              </server>
            </v2c>
          </version>
        </entry>
      </snmptrap>
      <email>
        <entry name="email-main">
          <server>
            <entry name="smtp">
              <gateway>10.0.0.50</gateway>
              <from>pan@example.com</from>
              <to>noc@example.com</to>
              <username>smtp-user</username>
              <password>FAKE-TEST-SECRET-DO-NOT-USE</password>
            </entry>
          </server>
        </entry>
      </email>
      <http>
        <entry name="http-main">
          <server>
            <entry name="webhook"><address>10.0.0.60</address></entry>
          </server>
        </entry>
      </http>
    </log-settings>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <address>
            <entry name="host-web">
              <ip-netmask>10.1.1.10/32</ip-netmask>
              <description>web server</description>
            </entry>
            <entry name="range-printers">
              <ip-range>10.1.2.10-10.1.2.20</ip-range>
            </entry>
            <entry name="fqdn-updates">
              <fqdn>updates.example.com</fqdn>
            </entry>
            <entry name="wildcard-mask">
              <ip-wildcard>10.0.0.0/0.255.255.255</ip-wildcard>
            </entry>
            <entry name="mystery-obj"/>
          </address>
          <address-group>
            <entry name="grp-static">
              <static>
                <member>host-web</member>
                <member>shared-dns</member>
              </static>
              <description>static group</description>
            </entry>
            <entry name="grp-dynamic">
              <dynamic><filter>'tag-prod'</filter></dynamic>
            </entry>
          </address-group>
          <service>
            <entry name="svc-https">
              <protocol><tcp><port>443</port><source-port>1024-65535</source-port></tcp></protocol>
              <description>HTTPS</description>
            </entry>
            <entry name="svc-dns">
              <protocol><udp><port>53</port></udp></protocol>
            </entry>
            <entry name="svc-sctp">
              <protocol><sctp><port>3868</port></sctp></protocol>
            </entry>
            <entry name="svc-unknown"/>
          </service>
          <service-group>
            <entry name="svc-grp-web">
              <members>
                <member>svc-https</member>
                <member>svc-dns</member>
              </members>
            </entry>
          </service-group>
          <tag>
            <entry name="tag-prod">
              <color>color1</color>
              <comments>production</comments>
            </entry>
            <entry name="tag-nocolor"/>
          </tag>
          <application>
            <entry name="app-custom">
              <category>business-systems</category>
              <subcategory>general-business</subcategory>
              <technology>client-server</technology>
              <risk>4</risk>
              <default>
                <port><member>tcp/8443</member></port>
                <ident-by-ip-protocol>
                  <ip-protocol><member>6</member></ip-protocol>
                </ident-by-ip-protocol>
              </default>
            </entry>
          </application>
          <application-group>
            <entry name="app-grp-custom">
              <members>
                <member>app-custom</member>
                <member>app-shared</member>
              </members>
            </entry>
          </application-group>
          <application-filter>
            <entry name="app-filter-risky">
              <category><member>business-systems</member></category>
              <subcategory><member>general-business</member></subcategory>
              <technology><member>client-server</member></technology>
              <risk><member>4</member><member>5</member></risk>
              <characteristic><member>evades</member></characteristic>
            </entry>
          </application-filter>
          <profiles>
            <virus>
              <entry name="av-default">
                <rules>
                  <entry name="r1"><action>reset-both</action></entry>
                </rules>
                <default-action><action>drop</action></default-action>
              </entry>
            </virus>
            <spyware>
              <entry name="as-default">
                <rules>
                  <entry name="r1"><action>block</action></entry>
                </rules>
              </entry>
            </spyware>
            <vulnerability>
              <entry name="vp-default">
                <rules>
                  <entry name="r1"><action>reset-both</action></entry>
                  <entry name="r2"><action>alert</action></entry>
                </rules>
              </entry>
            </vulnerability>
            <url-filtering>
              <entry name="url-default">
                <block><member>malware</member><member>phishing</member></block>
                <allow><member>search-engines</member></allow>
                <alert><member>news</member></alert>
              </entry>
            </url-filtering>
            <file-blocking>
              <entry name="fb-default">
                <rules>
                  <entry name="r1"><action>block</action></entry>
                </rules>
              </entry>
            </file-blocking>
            <wildfire-analysis>
              <entry name="wf-default">
                <rules>
                  <entry name="r1"><action>forward</action></entry>
                </rules>
              </entry>
            </wildfire-analysis>
            <data-filtering>
              <entry name="df-default"/>
            </data-filtering>
            <dos-protection>
              <entry name="dos-profile">
                <flood><tcp-syn/></flood>
                <resource><sessions/></resource>
              </entry>
            </dos-protection>
            <decryption>
              <entry name="decrypt-profile">
                <ssl-forward-proxy>
                  <block-expired-certificate>yes</block-expired-certificate>
                  <block-untrusted-issuer>yes</block-untrusted-issuer>
                </ssl-forward-proxy>
                <ssl-no-proxy>
                  <block-expired-certificate>yes</block-expired-certificate>
                </ssl-no-proxy>
                <ssl-protocol-settings>
                  <min-version>tls1-0</min-version>
                  <max-version>tls1-2</max-version>
                </ssl-protocol-settings>
                <description>vsys decryption profile</description>
              </entry>
            </decryption>
            <dns-security>
              <entry name="dns-default">
                <botnet-domains>
                  <dns-security-categories>
                    <entry name="pan-dns-sec-malware">
                      <action>sinkhole</action>
                      <log-level>high</log-level>
                    </entry>
                    <entry name="pan-dns-sec-benign">
                      <action>allow</action>
                    </entry>
                  </dns-security-categories>
                  <lists>
                    <entry name="bad-domains">
                      <action><block/></action>
                      <packet-capture>single-packet</packet-capture>
                    </entry>
                  </lists>
                  <sinkhole>
                    <ipv4-address>127.0.0.1</ipv4-address>
                    <ipv6-address>::1</ipv6-address>
                  </sinkhole>
                  <whitelist>
                    <entry name="good.example.com"/>
                  </whitelist>
                </botnet-domains>
              </entry>
            </dns-security>
            <custom-url-category>
              <entry name="url-custom">
                <type>URL List</type>
                <list>
                  <member>example.com</member>
                  <member>example.org</member>
                  <member>example.net</member>
                </list>
                <description>custom list</description>
              </entry>
            </custom-url-category>
          </profiles>
          <authentication-profile>
            <entry name="auth-vsys">
              <method><radius><server-profile>radius-vsys</server-profile></radius></method>
              <allow-list><member>all</member></allow-list>
            </entry>
          </authentication-profile>
          <server-profile>
            <radius>
              <entry name="radius-vsys">
                <protocol><PAP/></protocol>
                <server>
                  <entry name="r-vsys"><ip-address>10.1.0.20</ip-address><secret>FAKE-TEST-SECRET-DO-NOT-USE</secret></entry>
                </server>
              </entry>
            </radius>
          </server-profile>
          <zone>
            <entry name="trust">
              <network>
                <layer3><member>ethernet1/1</member></layer3>
              </network>
              <zone-protection-profile>zpp-strict</zone-protection-profile>
              <log-setting>default</log-setting>
            </entry>
            <entry name="untrust">
              <network>
                <layer3><member>ethernet1/2</member></layer3>
              </network>
            </entry>
          </zone>
          <rulebase>
            <security>
              <rules>
                <entry name="allow-web">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>host-web</member></source>
                  <destination><member>any</member></destination>
                  <application><member>app-custom</member></application>
                  <service><member>svc-https</member></service>
                  <action>allow</action>
                  <profile-setting>
                    <group><member>profile-grp-1</member></group>
                  </profile-setting>
                </entry>
                <entry name="deny-all">
                  <disabled>yes</disabled>
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>deny</action>
                  <profile-setting>
                    <profiles><virus><member>av-default</member></virus></profiles>
                  </profile-setting>
                </entry>
                <entry name="allow-open">
                  <from><member>trust</member></from>
                  <to><member>trust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="nat-dipp-iface">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>host-web</member></source>
                  <destination><member>any</member></destination>
                  <to-interface>ethernet1/2</to-interface>
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address><interface>ethernet1/2</interface></interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                </entry>
                <entry name="nat-dipp-pool">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-translation>
                    <dynamic-ip-and-port>
                      <translated-address>
                        <member>10.1.1.100</member>
                        <member>10.1.1.101</member>
                      </translated-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                </entry>
                <entry name="nat-dynamic-ip">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-translation>
                    <dynamic-ip>
                      <translated-address><member>10.1.1.200</member></translated-address>
                    </dynamic-ip>
                  </source-translation>
                </entry>
                <entry name="nat-static">
                  <from><member>untrust</member></from>
                  <to><member>trust</member></to>
                  <source><member>any</member></source>
                  <destination><member>host-web</member></destination>
                  <source-translation>
                    <static-ip><translated-address>10.1.1.10</translated-address></static-ip>
                  </source-translation>
                </entry>
                <entry name="nat-dst">
                  <from><member>untrust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <destination-translation>
                    <translated-address>10.1.1.10</translated-address>
                    <translated-port>8443</translated-port>
                  </destination-translation>
                </entry>
                <entry name="nat-both">
                  <disabled>yes</disabled>
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address><interface>ethernet1/2</interface></interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                  <destination-translation>
                    <translated-address>10.1.1.50</translated-address>
                  </destination-translation>
                </entry>
                <entry name="nat-none">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                </entry>
              </rules>
            </nat>
            <dos>
              <rules>
                <entry name="dos-protect">
                  <from><zone><member>untrust</member></zone></from>
                  <to><zone><member>trust</member></zone></to>
                  <source><member>any</member></source>
                  <destination><member>host-web</member></destination>
                  <service><member>any</member></service>
                  <protection><aggregate/></protection>
                  <action><protect/></action>
                  <log-setting>dos-log</log-setting>
                  <description>aggregate protection</description>
                </entry>
                <entry name="dos-classified">
                  <disabled>yes</disabled>
                  <from><zone><member>untrust</member></zone></from>
                  <to><zone><member>trust</member></zone></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>any</member></service>
                  <protection><classified/></protection>
                  <action><deny/></action>
                </entry>
                <entry name="dos-bare">
                  <from><zone><member>any</member></zone></from>
                  <to><zone><member>any</member></zone></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>any</member></service>
                </entry>
              </rules>
            </dos>
            <decryption>
              <rules>
                <entry name="decrypt-web">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <type>ssl-forward-proxy</type>
                  <profile>decrypt-profile</profile>
                  <action>decrypt</action>
                </entry>
                <entry name="decrypt-off">
                  <disabled>yes</disabled>
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <type>no-decrypt</type>
                  <action>no-decrypt</action>
                </entry>
              </rules>
            </decryption>
            <pbf>
              <rules>
                <entry name="pbf-forward">
                  <from><zone><member>trust</member></zone></from>
                  <source><member>host-web</member></source>
                  <destination><member>any</member></destination>
                  <application><member>app-custom</member></application>
                  <service><member>svc-https</member></service>
                  <action>
                    <forward>
                      <egress-interface>ethernet1/2</egress-interface>
                      <nexthop><ip-address>10.1.1.254</ip-address></nexthop>
                    </forward>
                  </action>
                </entry>
                <entry name="pbf-discard">
                  <disabled>yes</disabled>
                  <from><zone><member>trust</member></zone></from>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action><discard/></action>
                </entry>
                <entry name="pbf-noaction">
                  <from><zone><member>trust</member></zone></from>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                </entry>
              </rules>
            </pbf>
            <application-override>
              <rules>
                <entry name="app-ov-1">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>host-web</member></destination>
                  <protocol>tcp</protocol>
                  <port>8080</port>
                  <application>app-custom</application>
                </entry>
                <entry name="app-ov-off">
                  <disabled>yes</disabled>
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <protocol>udp</protocol>
                  <port>9999</port>
                  <application>app-shared</application>
                </entry>
              </rules>
            </application-override>
            <authentication>
              <rules>
                <entry name="auth-rule-1">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-user><member>example\users</member></source-user>
                  <service><member>svc-https</member></service>
                  <authentication-enforcement>auth-local</authentication-enforcement>
                  <log-setting>auth-log</log-setting>
                </entry>
                <entry name="auth-rule-off">
                  <disabled>yes</disabled>
                  <from><member>trust</member></from>
                  <to><member>trust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-user><member>any</member></source-user>
                  <service><member>any</member></service>
                </entry>
              </rules>
            </authentication>
            <qos>
              <rules>
                <entry name="qos-rule-1">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>app-custom</member></application>
                  <service><member>svc-https</member></service>
                  <action><class>1</class></action>
                  <schedule>business-hours</schedule>
                </entry>
                <entry name="qos-rule-emptyclass">
                  <from><member>trust</member></from>
                  <to><member>trust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action><class/></action>
                </entry>
                <entry name="qos-rule-noaction">
                  <from><member>trust</member></from>
                  <to><member>trust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                </entry>
              </rules>
            </qos>
          </rulebase>
          <global-protect>
            <global-protect-gateway>
              <entry name="gp-gw-1">
                <ssl-tls-service-profile>ssl-default</ssl-tls-service-profile>
                <tunnel-mode>yes</tunnel-mode>
                <remote-user-tunnel>tunnel.1</remote-user-tunnel>
                <client-auth>
                  <entry name="auth-local"><user-credential-or-client-cert-required>no</user-credential-or-client-cert-required></entry>
                  <entry name="auth-cert"/>
                </client-auth>
              </entry>
            </global-protect-gateway>
            <global-protect-portal>
              <entry name="gp-portal-1">
                <portal-config>
                  <local-address><ip><ipv4>10.1.1.100</ipv4></ip></local-address>
                  <ssl-tls-service-profile>ssl-default</ssl-tls-service-profile>
                  <client-auth>
                    <entry name="auth-local"/>
                  </client-auth>
                </portal-config>
              </entry>
            </global-protect-portal>
          </global-protect>
        </entry>
      </vsys>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <ip><entry name="10.1.1.1/24"/></ip>
                <units>
                  <entry name="ethernet1/1.10">
                    <ip><entry name="10.1.10.1/24"/></ip>
                    <tag>10</tag>
                  </entry>
                </units>
              </layer3>
              <comment>uplink</comment>
            </entry>
            <entry name="ethernet1/2">
              <layer3><dhcp-client/></layer3>
            </entry>
            <entry name="ethernet1/3">
              <layer2/>
            </entry>
            <entry name="ethernet1/4">
              <virtual-wire/>
            </entry>
            <entry name="ethernet1/6">
              <virtual-wire/>
            </entry>
          </ethernet>
          <aggregate-ethernet>
            <entry name="ae1">
              <layer3><ip><entry name="10.2.2.1/24"/></ip></layer3>
              <comment>aggregate uplink</comment>
            </entry>
          </aggregate-ethernet>
          <loopback>
            <interface-management-profile>mgmt-ping</interface-management-profile>
            <units>
              <entry name="loopback.5">
                <ip><entry name="10.255.255.5/32"/></ip>
                <comment>router id</comment>
              </entry>
            </units>
          </loopback>
          <tunnel>
            <ip><entry name="10.3.3.1/30"/></ip>
          </tunnel>
          <vlan>
            <units>
              <entry name="vlan.100">
                <ip><entry name="10.30.30.1/24"/></ip>
              </entry>
            </units>
          </vlan>
        </interface>
        <vlan>
          <entry name="vlan-blue">
            <virtual-interface><interface>vlan.100</interface></virtual-interface>
            <interface><member>ethernet1/3</member></interface>
          </entry>
        </vlan>
        <virtual-wire>
          <entry name="vw-1">
            <interface1>ethernet1/4</interface1>
            <interface2>ethernet1/6</interface2>
            <tag-allowed>100</tag-allowed>
          </entry>
        </virtual-wire>
        <virtual-router>
          <entry name="vr-default">
            <interface>
              <member>ethernet1/1</member>
              <member>loopback.5</member>
            </interface>
            <routing-table>
              <ip>
                <static-route>
                  <entry name="default">
                    <destination>0.0.0.0/0</destination>
                    <nexthop><ip-address>10.1.1.254</ip-address></nexthop>
                    <metric>10</metric>
                    <admin-dist>1</admin-dist>
                  </entry>
                  <entry name="blackhole">
                    <destination>192.0.2.0/24</destination>
                    <nexthop><discard/></nexthop>
                  </entry>
                  <entry name="to-vr-branch">
                    <destination>172.16.0.0/16</destination>
                    <nexthop><next-vr>vr-branch</next-vr></nexthop>
                  </entry>
                  <entry name="via-tunnel">
                    <destination>10.9.0.0/16</destination>
                    <nexthop><tunnel>tunnel.1</tunnel></nexthop>
                  </entry>
                  <entry name="iface-only">
                    <destination>10.5.0.0/16</destination>
                    <interface>ethernet1/1</interface>
                  </entry>
                </static-route>
              </ip>
            </routing-table>
            <protocol>
              <bgp>
                <enable>yes</enable>
                <router-id>10.255.255.5</router-id>
                <local-as>65001</local-as>
                <install-route>yes</install-route>
                <peer-group>
                  <entry name="pg-external">
                    <type><ebgp/></type>
                    <peer>
                      <entry name="peer-1">
                        <enable>yes</enable>
                        <peer-as>65002</peer-as>
                        <local-address>
                          <ip>10.1.1.1</ip>
                          <interface>ethernet1/1</interface>
                        </local-address>
                        <peer-address><ip>10.1.1.254</ip></peer-address>
                      </entry>
                    </peer>
                  </entry>
                  <entry name="pg-internal">
                    <type><ibgp/></type>
                    <enable>no</enable>
                    <peer>
                      <entry name="peer-2">
                        <peer-as>65001</peer-as>
                        <local-address><interface>loopback.5</interface></local-address>
                        <peer-address><ip>10.255.255.2</ip></peer-address>
                      </entry>
                    </peer>
                  </entry>
                </peer-group>
                <redist-rules>
                  <entry name="rr-static">
                    <address-family-identifier>ipv4</address-family-identifier>
                    <route-table>unicast</route-table>
                    <set-origin>igp</set-origin>
                    <metric>5</metric>
                  </entry>
                </redist-rules>
              </bgp>
              <ospf>
                <enable>yes</enable>
                <router-id>10.255.255.5</router-id>
                <area>
                  <entry name="0.0.0.0">
                    <type><normal/></type>
                    <interface>
                      <entry name="ethernet1/1">
                        <enable>yes</enable>
                        <passive>no</passive>
                        <metric>10</metric>
                        <link-type>broadcast</link-type>
                      </entry>
                      <entry name="loopback.5">
                        <passive>yes</passive>
                        <authentication>ospf-auth</authentication>
                        <link-type><p2p/></link-type>
                      </entry>
                    </interface>
                  </entry>
                  <entry name="0.0.0.1">
                    <type><stub/></type>
                  </entry>
                </area>
                <export-rules>
                  <entry name="er-1">
                    <new-path-type>ext-2</new-path-type>
                    <metric>20</metric>
                  </entry>
                </export-rules>
              </ospf>
              <redist-profile>
                <entry name="rp-static">
                  <action><redist/></action>
                  <priority>1</priority>
                  <filter>
                    <type><member>static</member></type>
                    <destination><member>0.0.0.0/0</member></destination>
                  </filter>
                </entry>
                <entry name="rp-connected">
                  <action>no-redist</action>
                  <priority>2</priority>
                </entry>
              </redist-profile>
            </protocol>
            <ecmp>
              <enable>yes</enable>
              <max-path>4</max-path>
              <algorithm><ip-modulo/></algorithm>
            </ecmp>
          </entry>
          <entry name="vr-empty"/>
        </virtual-router>
        <ike>
          <gateway>
            <entry name="ike-gw-1">
              <peer-address><ip>203.0.113.1</ip></peer-address>
              <local-address>
                <ip>10.1.1.1</ip>
                <interface>ethernet1/1</interface>
              </local-address>
              <authentication>
                <pre-shared-key><key>-AQ==placeholder</key></pre-shared-key>
              </authentication>
              <protocol><version>ikev2</version></protocol>
            </entry>
            <entry name="ike-gw-cert">
              <peer-address><ip>203.0.113.2</ip></peer-address>
              <local-address><ip>10.1.1.1</ip></local-address>
              <authentication>
                <certificate><local-certificate>vpn-cert</local-certificate></certificate>
              </authentication>
              <protocol><version>ikev1</version></protocol>
              <disabled>yes</disabled>
            </entry>
          </gateway>
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="ike-crypto-1">
                <encryption>
                  <member>aes-256-cbc</member>
                  <member>aes-128-cbc</member>
                </encryption>
                <hash><member>sha256</member></hash>
                <dh-group><member>group14</member></dh-group>
                <lifetime><hours>8</hours></lifetime>
              </entry>
              <entry name="ike-crypto-nolife">
                <encryption><member>aes-128-cbc</member></encryption>
                <hash><member>sha1</member></hash>
                <dh-group><member>group2</member></dh-group>
              </entry>
            </ike-crypto-profiles>
            <ipsec-crypto-profiles>
              <entry name="ipsec-crypto-1">
                <esp>
                  <encryption><member>aes-256-gcm</member></encryption>
                  <authentication><member>sha256</member></authentication>
                </esp>
                <dh-group>group14</dh-group>
                <lifetime><seconds>3600</seconds></lifetime>
              </entry>
            </ipsec-crypto-profiles>
          </crypto-profiles>
        </ike>
        <tunnel>
          <ipsec>
            <entry name="ipsec-vpn-1">
              <tunnel-interface>tunnel.1</tunnel-interface>
              <auto-key>
                <ike-gateway><entry name="ike-gw-1"/></ike-gateway>
                <ipsec-crypto-profile>ipsec-crypto-1</ipsec-crypto-profile>
              </auto-key>
              <tunnel-monitor><enable>yes</enable></tunnel-monitor>
            </entry>
            <entry name="ipsec-vpn-2">
              <tunnel-interface>tunnel.2</tunnel-interface>
              <auto-key>
                <ike-gateway><entry name="ike-gw-cert"/></ike-gateway>
              </auto-key>
            </entry>
          </ipsec>
        </tunnel>
        <profiles>
          <zone-protection-profile>
            <entry name="zpp-strict">
              <flood><tcp-syn/><udp/><icmp/></flood>
              <discard-ip-spoof>yes</discard-ip-spoof>
              <discard-ip-frag>yes</discard-ip-frag>
              <strict-ip-check>yes</strict-ip-check>
            </entry>
            <entry name="zpp-loose"/>
          </zone-protection-profile>
          <monitor-profile>
            <entry name="mon-default">
              <interval>3</interval>
              <threshold>5</threshold>
              <action>wait-recover</action>
            </entry>
          </monitor-profile>
        </profiles>
        <qos>
          <profile>
            <entry name="qos-egress">
              <class-bandwidth-type>
                <mbps>
                  <egress-guaranteed>100</egress-guaranteed>
                  <egress-max>500</egress-max>
                  <class>
                    <entry name="class1"><priority>real-time</priority></entry>
                    <entry name="class4"/>
                  </class>
                </mbps>
              </class-bandwidth-type>
            </entry>
          </profile>
        </qos>
        <dhcp>
          <interface>
            <entry name="ethernet1/3">
              <server>
                <mode>auto</mode>
                <ip-pool><member>10.30.30.10-10.30.30.100</member></ip-pool>
                <option>
                  <gateway>10.30.30.1</gateway>
                  <subnet-mask>255.255.255.0</subnet-mask>
                  <dns><primary>8.8.8.8</primary><secondary>1.1.1.1</secondary></dns>
                  <lease><timeout>1440</timeout></lease>
                </option>
                <reserved>
                  <entry name="10.30.30.50"><mac>00:11:22:33:44:55</mac></entry>
                </reserved>
              </server>
            </entry>
          </interface>
        </dhcp>
      </network>
    </entry>
  </devices>
</config>
"""
