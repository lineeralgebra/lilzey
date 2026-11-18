"""
Kerberos LDAP session with signing/sealing for ldap3 connections.

ldap3's native SASL GSSAPI always negotiates "no security layer" in the SASL
bind (see ldap3/protocol/sasl/kerberos.py), so DCs enforcing LDAP signing
reject it with strongerAuthRequired. This module performs the SASL GSS-SPNEGO
bind manually (mirroring impacket's LDAPConnection.kerberosLogin) and then
transparently seals every ldap3 message by wrapping the connection socket.

Wire framing (MS Kerberos LDAP seal, same as impacket):
    [4-byte big-endian length][GSS signature][GSS ciphertext]

Works with a ticket-only ccache (no TGT): the service ticket for
ldap/<dc_hostname> is taken straight from the ccache via KRB5CCNAME.
"""

import datetime
import struct

from ldap3 import Server, ALL, Connection, SASL


class GSSSealSocket:
    """Wraps a plain socket, sealing/unsealing every ldap3 message.

    ldap3 sends one complete BER message per sendall() call and BER-parses
    partial chunks returned by recv() itself, so wrapping at this level is
    transparent to it.
    """

    def __init__(self, sock, session_key, cipher):
        from impacket.krb5.gssapi import GSSAPI
        self._sock = sock
        self._gss = GSSAPI(cipher)
        self._session_key = session_key
        self._send_seq = 0
        self._rbuf = b''  # unwrapped payload bytes pending delivery

    def settimeout(self, t):
        return self._sock.settimeout(t)

    def gettimeout(self):
        return self._sock.gettimeout()

    def close(self):
        return self._sock.close()

    def shutdown(self, how):
        return self._sock.shutdown(how)

    def fileno(self):
        return self._sock.fileno()

    def getpeername(self):
        return self._sock.getpeername()

    def getsockname(self):
        return self._sock.getsockname()

    def sendall(self, data):
        cipher_text, signature = self._gss.GSS_Wrap_LDAP(self._session_key, data, self._send_seq)
        self._send_seq += 1
        wire = signature + cipher_text
        self._sock.sendall(struct.pack('!I', len(wire)) + wire)

    def _recv_exact(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise Exception('connection closed while reading sealed LDAP message')
            buf += chunk
        return buf

    def _fill_buffer(self):
        length = struct.unpack('!I', self._recv_exact(4))[0]
        wire = self._recv_exact(length)
        plain, _ = self._gss.GSS_Unwrap_LDAP(self._session_key, wire, 0, direction='init')
        self._rbuf = plain

    def recv(self, bufsize=-1):
        if not self._rbuf:
            self._fill_buffer()
        if bufsize is None or bufsize < 0:
            out, self._rbuf = self._rbuf, b''
            return out
        out = self._rbuf[:bufsize]
        self._rbuf = self._rbuf[bufsize:]
        return out


def _read_ldap_message(sock):
    """Read one BER LDAPMessage from a plain (unsealed) socket.

    The exact wire bytes are returned untouched - dropping the long-form
    length octets corrupts the message (AD uses them, e.g. 30 84 00 00 00 28).
    """

    def _recv(n):
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise Exception('connection closed while reading bind response')
            buf += chunk
        return buf

    head = _recv(2)  # tag + first length octet
    if head[0] != 0x30:
        raise Exception(f'unexpected LDAP bind response tag: {head[0]:#x}')
    b0 = head[1]
    if b0 & 0x80:
        n = b0 & 0x7f
        if n == 0:
            raise Exception('indefinite length BER not supported')
        length_octets = _recv(n)
        length = int.from_bytes(length_octets, 'big')
        return head + length_octets + _recv(length)
    return head + _recv(b0)


def sealed_kerberos_connect(dc_ip, dc_hostname, domain, username):
    """Open an ldap3 Connection sealed with Kerberos signing on LDAP/389.

    The service ticket for ldap/<dc_hostname> is read from the ccache in
    KRB5CCNAME (set by the caller). Returns the bound Connection; raises on
    failure.
    """
    from impacket.krb5.ccache import CCache
    from impacket.krb5.gssapi import GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_C_SEQUENCE_FLAG, GSS_C_REPLAY_FLAG
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from pyasn1.type.univ import noValue
    from impacket.krb5.kerberosv5 import CheckSumField, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
    from impacket.ldap.ldapasn1 import LDAPMessage, BindRequest
    from pyasn1.codec.ber import encoder, decoder

    realm = domain.upper()
    target_name = 'ldap/%s' % dc_hostname

    # Pull TGT/TGS straight from the ccache - no KDC contact needed when the
    # service ticket is already in there (ticket-only ccache case)
    _, user, TGT, TGS = CCache.parseFile(realm, username, target_name)
    if TGS is None and TGT is None:
        raise Exception(f'no ticket for {target_name} (or any TGT) in the ccache')

    user_name = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGS is None:
        server_name = Principal(target_name, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, _, session_key = getKerberosTGS(server_name, realm, dc_ip, TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'])
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        session_key = TGS['sessionKey']

    tgs_decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs_decoded['ticket'])

    ap_req = AP_REQ()
    ap_req['pvno'] = 5
    ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req['ap-options'] = constants.encodeFlags([])
    seq_set(ap_req, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = realm
    seq_set(authenticator, 'cname', user_name.components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)
    authenticator['cksum'] = noValue
    authenticator['cksum']['cksumtype'] = 0x8003
    chk_field = CheckSumField()
    chk_field['Lgth'] = 16
    chk_field['Flags'] = GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
    authenticator['cksum']['checksum'] = chk_field.getData()
    authenticator['seq-number'] = 0
    encoded_authenticator = encoder.encode(authenticator)
    # Key Usage 11: AP-REQ authenticator encrypted with the session key
    encrypted_authenticator = cipher.encrypt(session_key, 11, encoded_authenticator, None)
    ap_req['authenticator'] = noValue
    ap_req['authenticator']['etype'] = cipher.enctype
    ap_req['authenticator']['cipher'] = encrypted_authenticator

    blob = SPNEGO_NegTokenInit()
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]
    blob['MechToken'] = encoder.encode(ap_req)

    server = Server(dc_ip, get_info=ALL)
    conn = Connection(server, authentication=SASL, sasl_mechanism='GSS-SPNEGO', auto_bind=False,
                      auto_referrals=False)
    conn.open(read_server_info=False)

    bind_request = BindRequest()
    bind_request['version'] = 3
    bind_request['name'] = 'user'
    bind_request['authentication']['sasl']['mechanism'] = 'GSS-SPNEGO'
    bind_request['authentication']['sasl']['credentials'] = blob.getData()

    ldap_message = LDAPMessage()
    ldap_message['messageID'] = 1
    ldap_message['protocolOp'].setComponentByType(bind_request.getTagSet(), bind_request)
    conn.socket.sendall(encoder.encode(ldap_message))

    raw_response = _read_ldap_message(conn.socket)
    try:
        response = decoder.decode(raw_response, asn1Spec=LDAPMessage())[0]
    except Exception:
        print(f"[-] Unexpected bind response ({len(raw_response)} bytes):")
        for i in range(0, len(raw_response), 16):
            chunk = raw_response[i:i+16]
            print(f"    {i:04x}: {chunk.hex(' ')}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)}")
        raise
    bind_response = response['protocolOp']['bindResponse']
    if int(bind_response['resultCode']) != 0:
        raise Exception(f"SASL GSS-SPNEGO bind failed: {bind_response['resultCode'].prettyPrint()} "
                        f"{bind_response['diagnosticMessage']}")

    conn.bound = True
    conn.socket = GSSSealSocket(conn.socket, session_key, cipher)

    # Load RootDSE/schema through the sealed channel (also proves sealing works)
    try:
        conn.refresh_server_info()
    except Exception as e:
        print(f"[!] Could not fetch server info over the sealed channel: {e}")
    return conn
