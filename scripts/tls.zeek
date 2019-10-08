## This script generates a file called tls.log. The difference from ssl.log is that this
## is much more focused on logging all kinds of protocol features. This can be interesting
## for academic purposes - or if one is just interested in more information about specific
## features used in local TLS traffic.

module TLSLog;

export {
	## Log identifier for certificate log, as well as for the connection information log
	redef enum Log::ID += {
		TLS_CERTIFICATE_LOG,
		TLS_LOG,
	};

	## The hash function used for certificate hashes. By default this is sha256; you can use
	## any other hash function and the hashes in both log files will change
	option hash_function: function(cert: string): string = sha256_hash;

	## If set to true, a log-file containing all certificates will be greated.
	option log_certificates: bool = F;

	type CertificateInfo: record {
		## Timestamp when this certificate was encountered.
		ts: time &log;
		## Fingerprint of the certificate - uses chosen algorithm.
		fp: string &log;
		## Base64 endoded X.509 certificate.
		cert: string &log;
		## Server hosting the certificate.
		host: addr &log;
		## Port on the server hosting the certificate
		host_p: count &log;
		## Indicates if this certificate was a end-host certificate, or sent as part of a chain
		host_cert: bool &log &default=F;
		## Indicates if this certificate was sent from the client
		client_cert: bool &log &default=F;
	};

	type TLSInfo: record {
		## Timestamp when the conenction began.
		ts: time &log;
		## Connection uid
		uid: string &log;
		## Connection 4-tup;e
		id: conn_id &log;
		## Numeric version of the server in the server hello
		server_version: count &log &optional;
		## Numeric version of the client in the client hello
		client_version: count &log &optional;
		## Cipher that was chosen for the connection
		cipher: count &log &optional;
		## Ciphers that were offered by the client for the connection
		client_ciphers: vector of count  &log &optional;
		## SNI that was sent by the client
		sni: vector of string &log &optional;
		## SSL Client extensions
		ssl_client_exts: vector of count &log &optional;
		## SSL server extensions
		ssl_server_exts: vector of count &log &optional;
		## Suggested ticket lifetime sent in the session ticket handshake
		## by the server.
		ticket_lifetime_hint: count &log &optional;
		## Hashes of the full certificate chain sent by the server
		server_certs: vector of string &log &optional;
		## Hashes of the full certificate chain sent by the server
		client_certs: vector of string &log &optional;
		## Set to true if the ssl_established event was seen.
		ssl_established: bool &log &default=F;
		## The diffie helman parameter size, when using DH.
		dh_param_size: count &log &optional;
		## supported elliptic curve point formats
		point_formats: vector of count  &log &optional;
		## The curves supported by the client.
		client_curves: vector of count  &log &optional;
		## The curve the server chose when using ECDH.
		curve: count &log &optional;
		## Application layer protocol negotiation extension sent by the client.
		orig_alpn: vector of string &log &optional;
		## Application layer protocol negotiation extension sent by the server.
		resp_alpn: vector of string &log &optional;
		## Alert. If the connection was closed with an TLS alers before being
		## completely established, this field contains the alert level and description
		## numbers that were transfered
		alert: vector of count  &log &optional;
		## TLS 1.3 supported versions
		client_supported_versions: vector of count &log &optional;
		## TLS 1.3 supported versions
		server_supported_version: count &log &optional;
		## TLS 1.3 Pre-shared key exchange modes
		psk_key_exchange_modes: vector of count &log &optional;
		## Key share groups from client hello
		client_key_share_groups: vector of count &log &optional;
		## Selected key share group from server hello
		server_key_share_group: count &log &optional;
		## Client supported compression methods
		client_comp_methods: vector of count &log &optional;
		## Server chosen compression method
		comp_method: count;
		## Client supported signature algorithms
		sigalgs: vector of count &log &optional;
		## Client supported hash algorithms
		hashalgs: vector of count &log &optional;
	};

	## Event from a manager to workers when encountering a new, cert
	global tls_cert_add: event(sha: string);

	## Event from workers to the manager when a new intermediate cert
	## is to be added.
	global tls_new_cert: event(sha: string);
}

redef record connection += {
	tls_conns: TLSInfo &optional;
};

# We store the hashes of certs here for a short period to prevent relogging.
global cert_cache: set[string] &create_expire=1hr;

@if ( Cluster::is_enabled() )
event bro_init()
	{
	Broker::auto_publish(Cluster::worker_topic, TLSLog::tls_cert_add);
	Broker::auto_publish(Cluster::manager_topic, TLSLog::tls_new_cert);
	}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event TLSLog::tls_cert_add(sha: string)
	{
	add cert_cache[sha];
	}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event TLSLog::tls_new_cert(sha: string)
	{
	if ( sha in cert_cache )
		return;

	add cert_cache[sha];
	event TLSLog::tls_cert_add(sha);
	}
@endif

event zeek_init() &priority=5
	{
	Log::create_stream(TLSLog::TLS_CERTIFICATE_LOG, [$columns=CertificateInfo, $path="tls_certificates"]);
	Log::create_stream(TLSLog::TLS_LOG, [$columns=TLSInfo, $path="tls"]);
	}

function set_session(c: connection)
	{
	if ( ! c?$tls_conns )
		{
		local t: TLSInfo;
		t$ts=network_time();
		t$uid=c$uid;
		t$id=c$id;
		t$ssl_client_exts=vector();
		t$ssl_server_exts=vector();
		c$tls_conns = t;
		}
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
	{
	set_session(c);
	c$tls_conns$client_ciphers = ciphers;
	c$tls_conns$client_version = version;
	c$tls_conns$client_comp_methods = comp_methods;
	}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
	{
	set_session(c);
	c$tls_conns$server_version = version;
	c$tls_conns$cipher = cipher;
	c$tls_conns$comp_method = comp_method;
	}

event ssl_session_ticket_handshake(c: connection, ticket_lifetime_hint: count, ticket: string)
	{
	set_session(c);
	c$tls_conns$ticket_lifetime_hint = ticket_lifetime_hint;
	}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	set_session(c);

	if ( is_orig )
		c$tls_conns$ssl_client_exts[|c$tls_conns$ssl_client_exts|] = code;
	else
		c$tls_conns$ssl_server_exts[|c$tls_conns$ssl_server_exts|] = code;
	}

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
	{
	set_session(c);
	if ( !is_orig )
		return;

	c$tls_conns$sni = names;
	}

event ssl_extension_ec_point_formats(c: connection, is_orig: bool, point_formats: index_vec)
	{
	set_session(c);
	if ( !is_orig )
		return;

	c$tls_conns$point_formats = point_formats;
	}

event ssl_extension_elliptic_curves(c: connection, is_orig: bool, curves: index_vec)
	{
	set_session(c);
	if ( !is_orig )
		return;

	c$tls_conns$client_curves = curves;
	}

event ssl_ecdh_server_params(c: connection, curve: count, point: string)
	{
	set_session(c);

	c$tls_conns$curve = curve;
	}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_orig: bool, names: string_vec)
	{
	set_session(c);

	if ( is_orig )
		c$tls_conns$orig_alpn = names;
	else
		c$tls_conns$resp_alpn = names;
	}

event ssl_alert(c: connection, is_orig: bool, level: count, desc: count)
	{
	set_session(c);

	local out: index_vec;

	if ( is_orig )
		out[0] = 1;
	else
		out[0] = 0;

	out[1] = level;
	out[2] = desc;

	c$tls_conns$alert = out;
	}

event ssl_established(c: connection)
	{
	set_session(c);

	c$tls_conns$ssl_established = T;
	}

event ssl_dh_server_params(c: connection, p: string, q: string, Ys: string)
	{
	set_session(c);

	local key_length = |Ys| * 8; # key length in bits
	c$tls_conns$dh_param_size = key_length;
	}

event ssl_extension_supported_versions(c: connection, is_orig: bool, versions: index_vec)
	{
	set_session(c);
	if ( is_orig )
		c$tls_conns$client_supported_versions = versions;
	else
		c$tls_conns$server_supported_version = versions[0];
	}

event ssl_extension_psk_key_exchange_modes(c: connection, is_orig: bool, modes: index_vec)
	{
	if ( ! is_orig )
		return;

	set_session(c);

	c$tls_conns$psk_key_exchange_modes = modes;
	}

event ssl_extension_key_share(c: connection, is_orig: bool, curves: index_vec)
	{
	set_session(c);

	if ( is_orig )
		c$tls_conns$client_key_share_groups = curves;
	else
		c$tls_conns$server_key_share_group = curves[0];
	}

event ssl_extension_signature_algorithm(c: connection, is_orig: bool, signature_algorithms: signature_and_hashalgorithm_vec)
	{
	if ( ! is_orig )
		return;

	set_session(c);

	local sigalgs: index_vec = vector();
	local hashalgs: index_vec = vector();

	for ( i in signature_algorithms )
		{
		local rec = signature_algorithms[i];
		sigalgs[|sigalgs|] = rec$SignatureAlgorithm;
		hashalgs[|hashalgs|] = rec$HashAlgorithm;
		}

	c$tls_conns$sigalgs = sigalgs;
	c$tls_conns$hashalgs = hashalgs;
	}

function log_cert_chain(c: connection, chain: vector of Files::Info, client: bool): vector of string
	{
	local out: vector of string = vector();
	for ( certI in chain )
		{
		# Apparently we might have "holes" in some chains (aka certs that OpenSSL cannot parse).
		# That is kind of a problem, because we cannot really do much in that case.
		# This was not a problem in older Zeek versions, because we then could still get access
		# to the actual raw data. But with the new versions, that information is lost when we arrive here.
		if ( ! chain[certI]?$x509 || ! chain[certI]$x509?$handle )
			{
			next;
			}

		local cert_opaque = chain[certI]$x509$handle;
		local der_cert = x509_get_certificate_string(cert_opaque);
		local fp = hash_function(der_cert);
		out[certI] = fp;

		# Only do the cert tracking if we haven't seen this cert recently.
		if ( log_certificates && fp !in cert_cache )
			{
			local cert_val: CertificateInfo;
			cert_val$ts = network_time();
			cert_val$fp = fp;
			cert_val$cert = encode_base64(der_cert);
			cert_val$host = c$id$resp_h;
			cert_val$host_p = port_to_count(c$id$resp_p);
			cert_val$client_cert = client;

			if ( certI == 0 )
				cert_val$host_cert = T;

			add cert_cache[cert_val$fp];
@if ( Cluster::is_enabled() )
			event TLSLog::tls_new_cert(cert_val$fp);
@endif
			Log::write(TLSLog::TLS_CERTIFICATE_LOG, cert_val);
			}
		}
		return out;
	}

hook SSL::ssl_finishing(c: connection)
	{
	if ( ! c?$tls_conns )
		return;

	if ( c$ssl?$cert_chain )
		c$tls_conns$server_certs = log_cert_chain(c, c$ssl$cert_chain, F);
	if ( c$ssl?$client_cert_chain )
		c$tls_conns$client_certs = log_cert_chain(c, c$ssl$client_cert_chain, T);

	Log::write(TLSLog::TLS_LOG, c$tls_conns);
	}

